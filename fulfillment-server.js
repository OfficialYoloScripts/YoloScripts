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

const crypto = require('crypto');

const PORT = process.env.PORT || 4242;
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const SITE_URL = process.env.SITE_URL || 'https://yoloscripts.onrender.com/';
const SITE_ORIGIN = String(SITE_URL).replace(/\/+$/, '');
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || '';
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID || '';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REQUIRED_ROLE_IDS = String(process.env.DISCORD_REQUIRED_ROLE_IDS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
// Accept OWNER_DISCORD_IDS (preferred) or singular OWNER_DISCORD_ID from Render.
const OWNER_DISCORD_IDS = String(
  process.env.OWNER_DISCORD_IDS || process.env.OWNER_DISCORD_ID || '1199408578717560942'
).split(',').map(s => s.trim()).filter(Boolean);
const MANUAL_LOGIN_ENABLED = String(process.env.MANUAL_LOGIN_ENABLED || 'true').toLowerCase() !== 'false';
const YOLO_AUTH_OPEN = String(process.env.YOLO_AUTH_OPEN || '').toLowerCase() === 'true';
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

const DATA_DIR = path.join(__dirname, 'data');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');
const DESKTOP_SESSIONS_FILE = path.join(DATA_DIR, 'desktop_sessions.json');
const LICENSE_BINDINGS_FILE = path.join(DATA_DIR, 'license_bindings.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(PRODUCTS_FILE)) fs.writeFileSync(PRODUCTS_FILE, '[]');
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, '[]');
if (!fs.existsSync(DESKTOP_SESSIONS_FILE)) fs.writeFileSync(DESKTOP_SESSIONS_FILE, '{}');
if (!fs.existsSync(LICENSE_BINDINGS_FILE)) fs.writeFileSync(LICENSE_BINDINGS_FILE, '{}');

// state → { port, machineId, createdAt } for desktop OAuth handshake
const pendingDesktopLogins = new Map();

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
   DESKTOP AUTH (Yolo.exe Discord login — Vanta-style workflow)
   Register this redirect URL in the Discord Developer Portal:
     https://yoloscripts.onrender.com/api/auth/desktop/callback
------------------------------------------------------------------ */
function readSessions() {
  const obj = readJSON(DESKTOP_SESSIONS_FILE);
  return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
}
function writeSessions(obj) { writeJSON(DESKTOP_SESSIONS_FILE, obj); }

function readBindings() {
  const obj = readJSON(LICENSE_BINDINGS_FILE);
  return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
}
function writeBindings(obj) { writeJSON(LICENSE_BINDINGS_FILE, obj); }

function isOwner(discordId) {
  return OWNER_DISCORD_IDS.includes(String(discordId || ''));
}

function productRoleIds() {
  return readJSON(PRODUCTS_FILE)
    .map(p => p && p.discordRoleId)
    .filter(Boolean)
    .map(String);
}

function requiredRoleIds() {
  const fromEnv = DISCORD_REQUIRED_ROLE_IDS.slice();
  const fromProducts = productRoleIds();
  return Array.from(new Set(fromEnv.concat(fromProducts)));
}

async function fetchDiscordUser(accessToken) {
  const res = await fetch('https://discord.com/api/v10/users/@me', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!res.ok) throw new Error('discord user fetch failed');
  return res.json();
}

async function memberHasRequiredRole(discordId) {
  if (isOwner(discordId)) {
    return { entitled: true, label: 'owner', owner: true };
  }
  if (YOLO_AUTH_OPEN) {
    return { entitled: true, label: 'open-auth', owner: false };
  }
  const rolesNeeded = requiredRoleIds();
  if (!DISCORD_BOT_TOKEN || !DISCORD_GUILD_ID) {
    return { entitled: false, label: '', owner: false, error: 'License server is not ready.' };
  }
  if (!rolesNeeded.length) {
    return { entitled: false, label: '', owner: false, error: 'No product roles configured.' };
  }
  const res = await fetch(
    `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${discordId}`,
    { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
  );
  if (res.status === 404) {
    return { entitled: false, label: '', owner: false, error: 'Join the Yolo Discord server after purchase.' };
  }
  if (!res.ok) {
    return { entitled: false, label: '', owner: false, error: 'Could not verify Discord membership.' };
  }
  const member = await res.json();
  const have = new Set((member.roles || []).map(String));
  const hit = rolesNeeded.find(r => have.has(String(r)));
  if (!hit) {
    return { entitled: false, label: '', owner: false, error: 'No active Yolo license on this Discord account.' };
  }
  return { entitled: true, label: 'licensed', owner: false };
}

/** Bind buyer license to one PC. Owner accounts skip machine lock. */
function activateOrCheckMachine(discordId, machineId, owner) {
  if (owner) {
    return { ok: true, owner: true };
  }
  const mid = String(machineId || '').trim().toLowerCase();
  if (!mid || mid.length < 16) {
    return { ok: false, error: 'This PC could not be identified for license activation.' };
  }
  const bindings = readBindings();
  const existing = bindings[String(discordId)];
  if (!existing || !existing.machineId) {
    bindings[String(discordId)] = {
      machineId: mid,
      activatedAt: Date.now()
    };
    writeBindings(bindings);
    return { ok: true, activated: true };
  }
  if (String(existing.machineId).toLowerCase() !== mid) {
    return {
      ok: false,
      error: 'This license is already activated on another PC and cannot be used here.'
    };
  }
  return { ok: true };
}

function avatarUrlFor(user) {
  if (user.avatar) {
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`;
  }
  const idx = Number(user.discriminator || 0) % 5;
  return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
}

function issueDesktopSession(user, entitlement, machineId) {
  const token = crypto.randomBytes(32).toString('hex');
  const sessions = readSessions();
  const expiresAt = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30; // 30 days
  sessions[token] = {
    discordId: user.id,
    username: user.username,
    avatarUrl: avatarUrlFor(user),
    entitled: !!entitlement.entitled,
    entitlementLabel: entitlement.owner ? 'owner' : 'licensed',
    owner: !!entitlement.owner,
    machineId: machineId || '',
    expiresAt,
    createdAt: Date.now()
  };
  writeSessions(sessions);
  return { token, expiresAt, session: sessions[token] };
}

function sessionPayload(token, session) {
  return {
    accessToken: token,
    token,
    expiresAt: session.expiresAt,
    entitled: !!session.entitled,
    entitlementLabel: session.owner ? 'owner' : 'licensed',
    owner: !!session.owner,
    machineBound: !session.owner,
    user: {
      id: session.discordId,
      username: session.username,
      avatarUrl: session.avatarUrl || ''
    }
  };
}

app.get('/api/auth/config', (req, res) => {
  res.json({
    ok: true,
    discordClientId: DISCORD_CLIENT_ID || null,
    manualLoginEnabled: MANUAL_LOGIN_ENABLED,
    guildConfigured: !!(DISCORD_BOT_TOKEN && DISCORD_GUILD_ID),
    requiredRoleCount: requiredRoleIds().length,
    machineLock: true
  });
});

app.get('/api/auth/desktop/login', (req, res) => {
  const port = Number(req.query.port || 0);
  const state = String(req.query.state || '');
  const machineId = String(req.query.machineId || '').trim().toLowerCase();
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    return res.status(500).send('Discord OAuth is not configured (DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET).');
  }
  if (!port || port < 1024 || port > 65535 || !state) {
    return res.status(400).send('Invalid desktop login request.');
  }
  pendingDesktopLogins.set(state, { port, machineId, createdAt: Date.now() });
  const redirectUri = `${SITE_ORIGIN}/api/auth/desktop/callback`;
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: 'code',
    scope: 'identify',
    redirect_uri: redirectUri,
    state,
    prompt: 'consent'
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/api/auth/desktop/callback', async (req, res) => {
  try {
    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    const pending = pendingDesktopLogins.get(state);
    pendingDesktopLogins.delete(state);
    if (!code || !pending) {
      return res.status(400).send('Invalid or expired sign-in state. Return to Yolo and try again.');
    }
    const redirectUri = `${SITE_ORIGIN}/api/auth/desktop/callback`;
    const body = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri
    });
    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    if (!tokenRes.ok) {
      return res.status(400).send('Discord token exchange failed.');
    }
    const tokenJson = await tokenRes.json();
    const user = await fetchDiscordUser(tokenJson.access_token);
    const entitlement = await memberHasRequiredRole(user.id);
    if (!entitlement.entitled) {
      return res.status(403).send(entitlement.error || 'Not entitled to Yolo.');
    }
    const machine = activateOrCheckMachine(user.id, pending.machineId, !!entitlement.owner);
    if (!machine.ok) {
      return res.status(403).send(machine.error || 'License machine check failed.');
    }
    const issued = issueDesktopSession(user, entitlement, pending.machineId);
    const back = `http://127.0.0.1:${pending.port}/ok?token=${encodeURIComponent(issued.token)}`;
    res.redirect(back);
  } catch (err) {
    console.error('desktop callback error', err);
    res.status(500).send('Sign-in failed.');
  }
});

app.get('/api/auth/me', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  const machineId = String(req.headers['x-yolo-machine'] || req.query.machineId || '').trim().toLowerCase();
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const sessions = readSessions();
  const session = sessions[token];
  if (!session) return res.status(401).json({ error: 'invalid session' });
  if (session.expiresAt && session.expiresAt < Math.floor(Date.now() / 1000)) {
    delete sessions[token];
    writeSessions(sessions);
    return res.status(401).json({ error: 'session expired' });
  }
  memberHasRequiredRole(session.discordId).then((entitlement) => {
    session.entitled = !!entitlement.entitled;
    session.owner = !!entitlement.owner;
    session.entitlementLabel = entitlement.owner ? 'owner' : 'licensed';
    sessions[token] = session;
    writeSessions(sessions);
    if (!session.entitled) {
      return res.status(403).json({
        error: entitlement.error || 'Not entitled',
        entitled: false,
        user: { id: session.discordId, username: session.username, avatarUrl: session.avatarUrl }
      });
    }
    const machine = activateOrCheckMachine(session.discordId, machineId || session.machineId, !!entitlement.owner);
    if (!machine.ok) {
      return res.status(403).json({ error: machine.error || 'Wrong PC for this license', entitled: false });
    }
    if (machineId) {
      session.machineId = machineId;
      sessions[token] = session;
      writeSessions(sessions);
    }
    res.json(sessionPayload(token, session));
  }).catch(() => res.json(sessionPayload(token, session)));
});

app.post('/api/auth/manual', async (req, res) => {
  if (!MANUAL_LOGIN_ENABLED) {
    return res.status(403).json({ error: 'Manual Discord ID login is disabled.' });
  }
  const discordId = String((req.body && req.body.discordId) || '').replace(/\D/g, '');
  const machineId = String((req.body && req.body.machineId) || '').trim().toLowerCase();
  if (discordId.length < 17 || discordId.length > 20) {
    return res.status(400).json({ error: 'Enter a valid numeric Discord ID between 17 and 20 digits.' });
  }
  // Manual ID entry is developer-only. Buyers must use Login with Discord.
  if (!isOwner(discordId)) {
    return res.status(403).json({
      error: 'Manual sign-in is only for the developer account. Buyers must use Login with Discord after purchase.'
    });
  }
  try {
    const entitlement = await memberHasRequiredRole(discordId);
    if (!entitlement.entitled) {
      return res.status(403).json({ error: entitlement.error || 'Not entitled', entitled: false });
    }
    let username = discordId;
    let avatarUrl = '';
    if (DISCORD_BOT_TOKEN) {
      const ures = await fetch(`https://discord.com/api/v10/users/${discordId}`, {
        headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
      });
      if (ures.ok) {
        const u = await ures.json();
        username = u.username || username;
        avatarUrl = avatarUrlFor(u);
      }
    }
    const issued = issueDesktopSession(
      { id: discordId, username, avatar: null, discriminator: '0' },
      entitlement,
      machineId
    );
    const sessions = readSessions();
    sessions[issued.token].avatarUrl = avatarUrl || sessions[issued.token].avatarUrl;
    sessions[issued.token].username = username;
    writeSessions(sessions);
    res.json(sessionPayload(issued.token, sessions[issued.token]));
  } catch (err) {
    console.error('manual auth error', err);
    res.status(500).json({ error: err.message || 'manual auth failed' });
  }
});

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
