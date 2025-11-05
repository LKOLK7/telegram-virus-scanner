# Telegram Virus Scanner Bot (Render + Webhooks)

## Features
- Automatic scanning of files and images.
- Professional formatted results.
- Deletes file after scan.
- Works with Telegram Webhooks on Render.

---

## 🚀 Deployment on Render

### 1. Prepare Files
Ensure your repository contains:
- bot.py
- requirements.txt
- Procfile

### 2. Push to GitHub

### 3. Deploy on Render
- Go to Render.
- Create **New Web Service** → Connect GitHub repo.
- Add Environment Variables:
  - TELEGRAM_TOKEN
  - VT_API_KEY
- Set Start Command:

### 4. Set Webhook
After deployment, run: curl -F "url=https:///<TELEGRAM_TOKEN>" https://api.telegram.org/bot<TELEGRAM_TOKEN>/setWebhook4

✅ Done! Your bot is live 24/7.
