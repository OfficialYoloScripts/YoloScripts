# YoloScripts

One Node app that serves the storefront **and** the fulfillment API.

- **Live site:** https://yoloscripts.onrender.com/
- **Health check:** https://yoloscripts.onrender.com/api/health → `{"ok":true}`
- **Owner Discord ID (Devmode):** `1199408578717560942`
- **Discord Client ID:** `1535016417940869140`

## What’s in this folder

| File | Purpose |
|---|---|
| `index.html` | Storefront (also mirrored as `YoloScripts.html`) |
| `fulfillment-server.js` | Express API + static file server |
| `package.json` | Dependencies + `npm start` |
| `YOLO.ico` | Favicon / logo |
| `.env.example` | Template for secrets |
| `render.yaml` | Render service blueprint |
| `SETUP-GUIDE.md` | Longer product/setup notes |

## Upload / deploy (Render)

1. Upload **this entire folder** to your GitHub repo (`OfficialYoloScripts/YoloScripts`), replacing old files.
2. In Render → your Web Service:
   - **Root Directory:** *(leave empty)*
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`  *(or `node fulfillment-server.js`)*
3. Render → **Environment** — set at least:

```
SITE_URL=https://yoloscripts.onrender.com/
ADMIN_KEY=<long-random-string-you-choose>
DISCORD_CLIENT_ID=1535016417940869140
```

Use any long random string for `ADMIN_KEY`. Put the **same** value in Devmode → Integrations → Admin API Key.  
Never commit real secrets (`.env`, Stripe keys, bot token, Discord Client Secret).

Optional later: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `DISCORD_BOT_TOKEN`, `DISCORD_GUILD_ID`, SMTP vars, `DISCORD_CLIENT_SECRET`.

4. Deploy. Confirm https://yoloscripts.onrender.com/api/health returns `{"ok":true}`.

## Discord OAuth redirect

In [Discord Developer Portal](https://discord.com/developers/applications) → your app → **OAuth2 → Redirects**, add **exactly**:

```
https://yoloscripts.onrender.com/
```

(Client Secret stays on the server only — never in HTML.)

## After deploy — Devmode

1. Open https://yoloscripts.onrender.com/
2. **Login with Discord** using the owner account.
3. Open the ⚙️ gear → **Integrations**.
4. Confirm:
   - Checkout / Fulfillment Server Base URL = `https://yoloscripts.onrender.com`
   - Admin API Key = same `ADMIN_KEY` as Render
5. Click **Sync Products & Settings to Server**.

Devmode is OAuth-only for your Discord ID. Manual “type an ID” login is disabled.

## Local run

```bash
npm install
copy .env.example .env   # then fill ADMIN_KEY etc.
npm start
```

Open http://localhost:4242/
