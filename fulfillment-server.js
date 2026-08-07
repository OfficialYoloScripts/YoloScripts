/**
 * YoloScripts fulfillment-server.js
 * --------------------------------------------------------------
 * Serves the storefront (index.html / YoloScripts.html) AND the API:
 *   - Discord-ready static site
 *   - Verified Stripe payments
 *   - Automatic Discord role granting
 *   - Purchase confirmation emails
 *   - Multi-item cart checkout
 *   - Cross-device order ledger for Devmode
 *
 * Run locally:
 *   npm install
 *   npm start
 *
 * Deploy: push this folder to GitHub → connect Render (see README.md).
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const Stripe = require('stripe');

const PORT = process.env.PORT || 4242;
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const SITE_URL = process.env.SITE_URL || 'https://yoloscripts.onrender.com/';
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || '';
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID || '';
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(PRODUCTS_FILE)) fs.writeFileSync(PRODUCTS_FILE, '[]');
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, '[]');

function readJSON(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return []; } }
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

function extractAdminKey(req) {
  const auth = req.headers.authorization || '';
  if (/^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  if (req.headers['x-api-key']) return String(req.headers['x-api-key']).trim();
  if (req.headers['x-admin-key']) return String(req.headers['x-admin-key']).trim();
  return '';
}

function requireAdmin(req, res, next) {
  const key = extractAdminKey(req);
  if (!ADMIN_KEY || key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized', message: 'Missing or invalid ADMIN_KEY' });
  }
  next();
}

const app = express();
app.use(cors());
// Stripe webhook needs the raw body, so it's mounted BEFORE the JSON parser.
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);
app.use(express.json({ limit: '5mb' }));

app.get('/api/health', (req, res) => res.json({ ok: true }));

/* ------------------------------------------------------------------
   DEVMODE / WEBHOOK ping endpoints
   Your built-in Devmode dashboard syncs via POST /api/admin/sync-products.
   These /api/sync and /api/webhook routes are simple authenticated receivers
   for testing or external tools that only need a 200 acknowledgement.
------------------------------------------------------------------ */
function handleDevmodeWebhook(req, res) {
  console.log('[devmode-webhook]', new Date().toISOString(), {
    path: req.path,
    headers: {
      authorization: req.headers.authorization ? '[present]' : '[missing]',
      'x-api-key': req.headers['x-api-key'] ? '[present]' : '[missing]'
    },
    body: req.body
  });

  // If a full product catalog is included, persist it (same as Sync button).
  const { products, settings } = req.body || {};
  if (Array.isArray(products)) {
    writeJSON(PRODUCTS_FILE, products);
    if (settings) writeJSON(path.join(DATA_DIR, 'settings.json'), settings);
    console.log('[devmode-webhook] saved products:', products.length);
  }

  return res.status(200).json({
    status: 'success',
    message: 'Webhook received',
    ok: true
  });
}

app.post('/api/sync', requireAdmin, handleDevmodeWebhook);
app.post('/api/webhook', requireAdmin, handleDevmodeWebhook);

/* ------------------------------------------------------------------
   ADMIN: sync products/settings pushed from the Devmode dashboard
------------------------------------------------------------------ */
app.post('/api/admin/sync-products', requireAdmin, (req, res) => {
  const { products, settings } = req.body || {};
  if (!Array.isArray(products)) return res.status(400).json({ error: 'products array required' });
  writeJSON(PRODUCTS_FILE, products);
  if (settings) writeJSON(path.join(DATA_DIR, 'settings.json'), settings);
  console.log('[sync-products] saved', products.length, 'products');
  res.json({ ok: true, count: products.length, status: 'success', message: 'Webhook received' });
});

app.get('/api/admin/orders', requireAdmin, (req, res) => {
  res.json({ orders: readJSON(ORDERS_FILE) });
});

/* ------------------------------------------------------------------
   CHECKOUT: create a real multi-item Stripe Checkout Session.
   Prices are always re-read from the server's product file — the
   client's cart is never trusted for pricing.
------------------------------------------------------------------ */
app.post('/api/create-checkout-session', async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe secret key not configured on server' });
  try {
    const { items, discordUser, successBase } = req.body || {};
    const products = readJSON(PRODUCTS_FILE);
    const line_items = (items || []).map(({ productId, qty }) => {
      const p = products.find(x => x.id === productId);
      if (!p) throw new Error('unknown product ' + productId);
      return {
        quantity: Math.max(1, qty || 1),
        price_data: {
          currency: (p.currency || 'usd').toLowerCase(),
          product_data: { name: p.name, description: p.shortDescription || undefined },
          unit_amount: Math.round(Number(p.price) * 100)
        }
      };
    });
    if (!line_items.length) return res.status(400).json({ error: 'no valid items' });

    const base = successBase || SITE_URL;
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items,
      success_url: `${base}?ys_success=1&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}?ys_cancel=1`,
      client_reference_id: discordUser && discordUser.id ? discordUser.id : undefined,
      customer_email: discordUser && discordUser.email ? discordUser.email : undefined,
      metadata: {
        productIds: (items || []).map(i => i.productId).join(','),
        discordId: discordUser && discordUser.id ? discordUser.id : ''
      }
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/* ------------------------------------------------------------------
   FULFILL: called by the storefront right after a buyer returns from
   Stripe. Verifies the payment server-side, grants Discord role(s),
   emails the buyer, and returns download links. Idempotent — safe to
   call more than once for the same session.
------------------------------------------------------------------ */
app.post('/api/fulfill', async (req, res) => {
  if (!stripe) return res.status(500).json({ ok: false, error: 'Stripe secret key not configured on server' });
  try {
    const { sessionId, productSlug, discordUser } = req.body || {};
    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });

    const session = await stripe.checkout.sessions.retrieve(sessionId, { expand: ['line_items'] });
    if (session.payment_status !== 'paid') {
      return res.status(402).json({ ok: false, error: 'payment not completed' });
    }

    const result = await fulfillSession(session, { productSlug, discordUser });
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

async function fulfillSession(session, hint) {
  const products = readJSON(PRODUCTS_FILE);
  const orders = readJSON(ORDERS_FILE);

  // Avoid double-fulfilling the same Stripe session.
  const already = orders.find(o => o.sessionId === session.id && o.status === 'fulfilled');
  if (already) return already.result;

  let matched = [];
  const metaIds = (session.metadata && session.metadata.productIds || '').split(',').filter(Boolean);
  if (metaIds.length) {
    matched = products.filter(p => metaIds.includes(p.id));
  } else if (hint && hint.productSlug) {
    const p = products.find(p => p.slug === hint.productSlug);
    if (p) matched = [p];
  }

  const discordId = session.client_reference_id || (hint && hint.discordUser && hint.discordUser.id) || null;
  const email = session.customer_details ? session.customer_details.email : (hint && hint.discordUser && hint.discordUser.email);

  let roleGranted = false;
  const roleGrants = [];
  for (const p of matched) {
    if (p.discordRoleId && discordId && DISCORD_BOT_TOKEN && DISCORD_GUILD_ID) {
      const ok = await grantDiscordRole(discordId, p.discordRoleId);
      roleGranted = roleGranted || ok;
      if (ok) {
        const expiresAt = p.licenseDurationDays > 0 ? Date.now() + p.licenseDurationDays * 86400000 : null;
        roleGrants.push({ userId: discordId, roleId: p.discordRoleId, productName: p.name, expiresAt, revoked: false });
      }
    }
  }

  let emailSent = false;
  if (email) emailSent = await sendConfirmationEmail(email, matched);
  await sendAdminNotification(matched, discordId, email, (session.amount_total || 0) / 100);

  const items = matched.map(p => ({ productName: p.name, downloadUrl: p.fileUrl || '' }));
  const result = { items, roleGranted, emailSent };

  const orderRecord = {
    id: 'ord_' + Date.now(), sessionId: session.id,
    productName: matched.map(p => p.name).join(', ') || (hint && hint.productSlug) || 'Unknown',
    discordUser: hint && hint.discordUser, amount: (session.amount_total || 0) / 100,
    status: 'fulfilled', createdAt: Date.now(), result, roleGrants
  };
  orders.push(orderRecord);
  writeJSON(ORDERS_FILE, orders);
  return result;
}

/* ------------------------------------------------------------------
   ROLE EXPIRY: periodically revoke roles whose license duration has
   elapsed. Runs in-process, so this server needs to stay running
   continuously (a normal "always-on" web service works fine; a
   serverless/cold-start host would need a real external cron instead).
------------------------------------------------------------------ */
async function checkExpiredRoles() {
  if (!DISCORD_BOT_TOKEN || !DISCORD_GUILD_ID) return;
  const orders = readJSON(ORDERS_FILE);
  let changed = false;
  for (const order of orders) {
    for (const grant of order.roleGrants || []) {
      if (!grant.revoked && grant.expiresAt && grant.expiresAt < Date.now()) {
        const ok = await revokeDiscordRole(grant.userId, grant.roleId);
        if (ok) { grant.revoked = true; changed = true; console.log(`Revoked expired role ${grant.roleId} from ${grant.userId} (${grant.productName})`); }
      }
    }
  }
  if (changed) writeJSON(ORDERS_FILE, orders);
}
setInterval(checkExpiredRoles, 60 * 60 * 1000); // hourly
checkExpiredRoles();

/* ------------------------------------------------------------------
   STRIPE WEBHOOK: safety net so orders still get fulfilled even if
   the buyer closes the tab before the client calls /api/fulfill.
------------------------------------------------------------------ */
async function handleStripeWebhook(req, res) {
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(200).send('webhook not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    try { await fulfillSession(session, {}); } catch (e) { console.error('webhook fulfill error', e); }
  }
  res.json({ received: true });
}

/* ------------------------------------------------------------------
   DISCORD: grant a role to a member via the bot REST API.
   Your bot needs "Manage Roles" and must sit ABOVE the target role
   in Server Settings → Roles.
------------------------------------------------------------------ */
async function grantDiscordRole(userId, roleId) {
  try {
    const res = await fetch(
      `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${userId}/roles/${roleId}`,
      { method: 'PUT', headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    );
    return res.ok;
  } catch (err) {
    console.error('Discord role grant failed', err);
    return false;
  }
}
async function revokeDiscordRole(userId, roleId) {
  try {
    const res = await fetch(
      `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${userId}/roles/${roleId}`,
      { method: 'DELETE', headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    );
    return res.ok;
  } catch (err) {
    console.error('Discord role revoke failed', err);
    return false;
  }
}

/* ------------------------------------------------------------------
   EMAIL: purchase confirmation via SMTP (nodemailer).
------------------------------------------------------------------ */
let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}
async function sendConfirmationEmail(toEmail, items) {
  if (!transporter) return false;
  try {
    const lines = items.map(p => `• ${p.name}${p.fileUrl ? ` — ${p.fileUrl}` : ''}`).join('\n');
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: toEmail,
      subject: 'Your Yolo Scripts order is ready 🏀',
      text: `Thanks for your purchase!\n\n${lines}\n\nSee you in Discord!`
    });
    return true;
  } catch (err) {
    console.error('Email send failed', err);
    return false;
  }
}
async function sendAdminNotification(items, discordId, buyerEmail, amount) {
  if (!transporter || !process.env.ADMIN_NOTIFY_EMAIL) return;
  try {
    const lines = items.map(p => `• ${p.name}`).join('\n');
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.ADMIN_NOTIFY_EMAIL,
      subject: `🔔 New YoloScripts sale — $${amount.toFixed(2)}`,
      text: `New order fulfilled:\n\n${lines}\n\nBuyer: ${buyerEmail || 'unknown email'}${discordId ? `\nDiscord ID: ${discordId}` : ''}`
    });
  } catch (err) {
    console.error('Admin notification failed', err);
  }
}

/* ------------------------------------------------------------------
   STATIC STOREFRONT: serve index.html / YoloScripts.html / assets
   from this same process so one Render URL hosts site + API.
------------------------------------------------------------------ */
app.use(express.static(__dirname, {
  index: ['index.html', 'YoloScripts.html'],
  extensions: ['html']
}));

app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  const fallback = path.join(__dirname, 'YoloScripts.html');
  res.sendFile(fs.existsSync(indexPath) ? indexPath : fallback);
});

app.listen(PORT, () => {
  console.log(`YoloScripts running on port ${PORT}`);
  console.log(`  Storefront: ${SITE_URL}`);
  console.log(`  Health:     /api/health`);
});
