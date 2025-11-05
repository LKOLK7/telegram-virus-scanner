import os
import logging
import requests
import asyncio
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
from telegram.helpers import escape_markdown

# Load environment variables
load_dotenv()
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

if not TELEGRAM_TOKEN or not VT_API_KEY:
    raise EnvironmentError("Missing TELEGRAM_TOKEN or VT_API_KEY in environment variables.")

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/{}"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Welcome! Send me a file or image and I'll scan it using VirusTotal.", parse_mode="Markdown")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📌 How to use:\nSend a file or image in this chat and I'll scan it automatically.", parse_mode="Markdown")

async def scan_and_report(file_path, progress_msg):
    headers = {"x-apikey": VT_API_KEY}
    try:
        with open(file_path, "rb") as f:
            response = requests.post(VT_FILE_SCAN_URL, headers=headers, files={"file": f})
            response.raise_for_status()
            analysis_id = response.json().get("data", {}).get("id")
            if not analysis_id:
                await progress_msg.edit_text("❌ Failed to get analysis ID from VirusTotal.")
                return
            await progress_msg.edit_text("✅ File uploaded! Scanning in progress...")
    except Exception as e:
        await progress_msg.edit_text(f"❌ Error uploading file: {escape_markdown(str(e), version=2)}")
        return

    engines_for_progress = ["Kaspersky", "Avast", "BitDefender"]
    engine_index = 0
    timeout_counter = 0

    while timeout_counter < 24:
        await asyncio.sleep(5)
        try:
            status_response = requests.get(VT_FILE_REPORT_URL.format(analysis_id), headers=headers)
            status_response.raise_for_status()
            analysis_data = status_response.json().get("data", {}).get("attributes", {})
            if analysis_data.get("status") == "completed":
                stats = analysis_data.get("stats", {})
                results = analysis_data.get("results", {})
                malicious_engines, suspicious_engines, clean_engines = [], [], []

                for engine_name, details in results.items():
                    category = details.get("category")
                    result_text = details.get("result")
                    if category == "malicious":
                        malicious_engines.append(f"• {engine_name}: {result_text}")
                    elif category == "suspicious":
                        suspicious_engines.append(f"• {engine_name}: {result_text if result_text else 'Suspicious'}")
                    else:
                        clean_engines.append(f"• {engine_name}: clean")

                grouped_text = "──────────────\n"
                if malicious_engines:
                    grouped_text += "🔴 *Malicious:*\n" + "\n".join(malicious_engines) + "\n\n"
                if suspicious_engines:
                    grouped_text += "🟠 *Suspicious:*\n" + "\n".join(suspicious_engines) + "\n\n"
                if clean_engines:
                    grouped_text += "✅ *Clean:*\n" + "\n".join(clean_engines) + "\n"
                grouped_text += "──────────────"

                summary = (
                    f"✅ **Scan Complete!**\n\n"
                    f"🔍 **Summary:**\n"
                    f"• 🛑 *Malicious:* `{stats.get('malicious', 0)}`\n"
                    f"• ⚠️ *Suspicious:* `{stats.get('suspicious', 0)}`\n"
                    f"• ✅ *Harmless:* `{stats.get('harmless', 0)}`\n"
                    f"• ❓ *Undetected:* `{stats.get('undetected', 0)}`\n\n"
                    f"🧠 **Detected Viruses:**\n{grouped_text}\n\n"
                    f"Powered by Vy Sokhamphou"
                )

                await progress_msg.edit_text(escape_markdown(summary, version=2), parse_mode="MarkdownV2")
                try:
                    os.remove(file_path)
                except Exception as e:
                    logging.error(f"Error deleting file: {e}")
                return
            else:
                await progress_msg.edit_text(f"🔍 Scanning... please wait ({engines_for_progress[engine_index]})")
                engine_index = (engine_index + 1) % len(engines_for_progress)
        except Exception as e:
            logging.error(f"Error fetching report: {e}")
        timeout_counter += 1

    await progress_msg.edit_text("⚠️ Scan taking too long. Please check on VirusTotal manually.")
    try:
        os.remove(file_path)
    except Exception as e:
        logging.error(f"Error deleting file after timeout: {e}")

async def scan_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    file = await document.get_file()
    file_path = await file.download_to_drive()
    progress_msg = await update.message.reply_text("⏳ Uploading file to VirusTotal and starting scan...")
    await scan_and_report(file_path, progress_msg)

async def scan_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    photo = update.message.photo[-1]
    file = await photo.get_file()
    file_path = await file.download_to_drive()
    progress_msg = await update.message.reply_text("⏳ Uploading image to VirusTotal and starting scan...")
    await scan_and_report(file_path, progress_msg)

def main():
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.Document.ALL, scan_file))
    app.add_handler(MessageHandler(filters.PHOTO, scan_photo))

    port = int(os.environ.get("PORT", 8443))
    app.run_webhook(
        listen="0.0.0.0",
        port=port,
        url_path=TELEGRAM_TOKEN,
        webhook_url=f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME')}/{TELEGRAM_TOKEN}"
    )

if __name__ == "__main__":
    main()
