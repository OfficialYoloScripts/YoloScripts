# Yolo Scripts — Setup Guide

Your store is `YoloScripts.html` — open it directly in a browser, or upload it
(plus `YOLO.ico`) to any static host, including GitHub Pages. It works fully
standalone. The `fulfillment-server.js` companion is optional and only
needed for full automation (see Level 3 below).

## Devmode access

Devmode is hardcoded to **your** Discord account only — Discord ID
`1199408578717560942` — via a constant near the top of the `<script>` block
in `YoloScripts.html`:

```js
const OWNER_DISCORD_ID = '1199408578717560942';
```

There is no "claim" step, nothing is stored in `localStorage` to grant
access, and there is no button or link anywhere for customers to find it.
To open the dashboard: log in with Discord from that exact ID, then
navigate to `YoloScripts.html#/devmode`. If you ever need to hand off
ownership, change that one constant and redeploy — that's the only place
access is decided.

## Level 1 — Get the store live (5 minutes)

1. Open `YoloScripts.html` in your browser and navigate to `#/devmode`.
2. Log in with Discord using the account matching `1199408578717560942`.
3. A gear icon (⚙️) now appears in the header on future visits — that's
   your admin dashboard.
4. Devmode → Integrations: paste your real **Discord invite link**.
5. Devmode → Products: add your first product (name, price, description,
   image).

At this point buyers can browse your shop. To actually take payment, do
Level 2.

## Discord OAuth2 setup

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications)
   → **New Application** → name it "YoloScripts".
2. OAuth2 → General → copy the **Client ID**. Paste it into Devmode →
   Integrations → Discord Client ID.
3. OAuth2 → General → **Redirects** → add **exactly**:
   `https://yoloscripts.onrender.com/`
   (trailing slash included). The storefront hardcodes this URI so it always
   matches Discord. If you change your live domain, update both Discord and
   the `Discord.redirectUri()` value in `index.html`.
4. **Do not put the Client Secret in HTML.** The browser login uses OAuth2
   implicit grant (`response_type=token`) and only needs the Client ID.
   Keep `DISCORD_CLIENT_SECRET` in Render Environment / `.env` only.

## Level 2 — Accept real payments (no server required)

Stripe Payment Links let you take real card payments with zero backend.

1. In your [Stripe Dashboard](https://dashboard.stripe.com) → **Payment
   Links** → create one link per product, matching the price.
2. Under the link's settings, set the **after payment** redirect to your
   store URL with this pattern (Devmode → Products → edit product shows you
   this exact string, pre-filled with the product's slug):

   ```
   https://officialyoloscripts.github.io/YoloScripts/?ys_success=1&product=YOUR-PRODUCT-SLUG&session_id={CHECKOUT_SESSION_ID}
   ```

3. Paste the Payment Link URL into that product's **Stripe Payment Link**
   field in Devmode and save.
4. Add a **Digital File / Download URL** (e.g. a Google Drive, Dropbox, or
   your own CDN link) so buyers get something after paying.

This mode works immediately, but is "honor system" — the download unlocks
as soon as the buyer lands back on the success page, since there's no
backend to double check with Stripe. Good for getting started; for verified,
tamper-proof delivery + automatic Discord roles, use Level 3.

Discord login is **required to buy anything** — clicking Buy Now or
Checkout while logged out prompts a login instead of proceeding. There is
no guest checkout. This is deliberate: the buyer's Discord ID has to come
from an authenticated session, not a self-typed field, otherwise anyone
could type someone else's ID and receive their role.

## Level 3 — Full automation (Discord roles, verified payments, email, cart)

This deploys the included `fulfillment-server.js`, a small Node server that
holds your secret keys and does the parts a static webpage can't safely do.

1. **Discord bot** (separate from the OAuth2 application above — this one
   needs a bot user): same Developer Portal application → Bot → **Add Bot**
   → copy the **Bot Token**. Invite it to your server with the `bot` scope
   and **Manage Roles** permission. In **Server Settings → Roles**, drag the
   bot's role **above** any role it needs to grant or remove.
2. **Stripe secret key**: Dashboard → Developers → API keys.
3. **Stripe webhook** (recommended safety net): Dashboard → Developers →
   Webhooks → Add endpoint → `https://your-server.com/api/stripe-webhook`,
   event `checkout.session.completed`. Copy the signing secret.
4. **Email**: any SMTP provider (Gmail app password, SendGrid, Mailgun...).
5. Copy `.env.example` to `.env` and fill in what you have — anything left
   blank is simply skipped.
6. Install & run (or just push to GitHub and let Render build):
   ```bash
   npm install
   npm start
   ```
   The same process serves `index.html` and the `/api/*` routes.
7. Deploy on Render (always-on HTTPS). Free tier sleeps when idle — fine for
   testing; upgrade if you need role-expiry checks every hour without cold starts.
8. Back in Devmode → Integrations, set:
   - **Checkout / Fulfillment Server Base URL** → `https://yoloscripts.onrender.com`
   - **Admin API Key** → same value as `ADMIN_KEY` in Render Environment
9. Click **Sync Products & Settings to Server** — this pushes your catalog
   (with prices, role IDs, license durations, file URLs) to the server so it
   can safely trust its own price/product data instead of the browser's.
10. Now:
    - The **Cart** does real multi-item Stripe Checkout.
    - Returning buyers get **server-verified** fulfillment — role granted,
      confirmation email sent, download unlocked only after Stripe confirms
      payment.
    - Devmode → Orders → "Refresh from Server" pulls the full cross-device
      order ledger, including per-order role expiry.
    - If `ADMIN_NOTIFY_EMAIL` is set in `.env`, you get a "🔔 New sale"
      email on every fulfilled order.

### Role expiry (timed licenses)

Each product has a **License Duration (days)** field in Devmode (0 =
lifetime). When the fulfillment server grants a role for a product with a
duration set, it records an expiry timestamp. An hourly check inside the
server automatically calls Discord's API to remove the role once that time
passes — no separate bot process needed, it's built into
`fulfillment-server.js`. This only works while the server is running
continuously; on serverless/cold-start hosting you'd need to trigger
`checkExpiredRoles()` from an external cron instead.

## GitHub Pages deployment

Your repo is `github.com/OfficialYoloScripts/YoloScripts` — a project repo,
so it publishes under a `/YoloScripts/` subpath rather than at your
account's root domain. Rename `YoloScripts.html` to `index.html` first so
it loads at the clean `.../YoloScripts/` URL instead of
`.../YoloScripts/YoloScripts.html`:

```bash
git init
git add index.html YOLO.ico
git commit -m "Initial commit - YoloScripts Store"
git branch -M main
git remote add origin https://github.com/OfficialYoloScripts/YoloScripts.git
git push -u origin main
```

Then in the repo → **Settings → Pages** → Source: "Deploy from a branch" →
`main` (root). Your live site will be at
`https://officialyoloscripts.github.io/YoloScripts/` — that's the exact
value to register as the Discord redirect URI (or just copy it straight out
of Devmode → Integrations once the site is live, since it's computed from
`window.location` automatically and will always match).

## Alternative to EmailJS vs. the server's SMTP

- No server yet? Configure **EmailJS** (Devmode → Integrations) for
  best-effort client-side confirmation emails — free, no backend needed.
- Have the server running? Its SMTP config takes over and is more reliable
  (fires after Stripe confirms payment, not just after a redirect).

## Notes & limits worth knowing

- Without the companion server, all store data (products, orders,
  subscribers) lives in **this browser's localStorage only** — export a
  backup regularly from Devmode → Danger Zone → Export JSON Backup.
- Devmode access itself is *not* stored in localStorage at all — it's a
  hardcoded check against `OWNER_DISCORD_ID` in the file, evaluated fresh
  on every load, so it can't drift or be reset by clearing browser data.
- License key pools (Devmode → edit product) let you sell keys/codes —
  one is handed out per sale, works standalone or with the server.
