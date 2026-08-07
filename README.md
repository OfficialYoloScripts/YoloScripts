# YoloScripts

Public setup site + license / purchase API for Yolo.

- Live: https://yoloscripts.onrender.com/
- Health: https://yoloscripts.onrender.com/api/health

## Deploy (Render)

1. Upload this folder to your GitHub repo (replace old files).
2. Render Web Service:
   - Build: `npm install`
   - Start: `npm start`
3. Set Environment variables from `.env.example` (secrets only on Render — never commit `.env`).

Required for desktop login + purchases:

- `SITE_URL`
- `ADMIN_KEY` (long random string)
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_BOT_TOKEN`
- `DISCORD_GUILD_ID`
- `DISCORD_PUBLIC_KEY`
- `DISCORD_REQUIRED_ROLE_IDS`
- `OWNER_DISCORD_ID` (your Discord user id — Render only)
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

## Discord redirects

Add these OAuth2 redirects:

```
https://yoloscripts.onrender.com/
https://yoloscripts.onrender.com/api/auth/desktop/callback
```

Interactions URL:

```
https://yoloscripts.onrender.com/api/discord/interactions
```

## Local

```bash
npm install
copy .env.example .env
npm start
```

Open http://localhost:4242/
