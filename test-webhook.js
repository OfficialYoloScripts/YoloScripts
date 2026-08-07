/**
 * Local / live webhook tester for YoloScripts.
 *
 * Usage:
 *   node test-webhook.js
 *   node test-webhook.js https://yoloscripts.onrender.com
 *
 * Loads ADMIN_KEY from .env (same as the server).
 */

require('dotenv').config();

const BASE = (process.argv[2] || process.env.TEST_BASE_URL || 'http://localhost:4242').replace(/\/$/, '');
const ADMIN_KEY = process.env.ADMIN_KEY || '';

if (!ADMIN_KEY) {
  console.error('Missing ADMIN_KEY. Set it in .env before running this script.');
  process.exit(1);
}

const payload = {
  source: 'test-webhook.js',
  event: 'devmode.sync',
  syncedAt: new Date().toISOString(),
  products: [
    {
      id: 'prod_test_1',
      name: 'Test Script',
      slug: 'test-script',
      price: 9.99,
      currency: 'USD',
      shortDescription: 'Sample product from test-webhook.js'
    }
  ],
  settings: {
    siteName: 'YoloScripts',
    checkoutApiUrl: 'https://yoloscripts.onrender.com'
  },
  order: {
    id: 'ord_test_1',
    productName: 'Test Script',
    amount: 9.99,
    status: 'pending'
  }
};

async function post(path, headers) {
  const url = BASE + path;
  console.log('\n→ POST', url);
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers
    },
    body: JSON.stringify(payload)
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  console.log('←', res.status, json);
  return res.status;
}

(async () => {
  console.log('Base URL:', BASE);
  console.log('ADMIN_KEY length:', ADMIN_KEY.length);

  // Health (no auth)
  try {
    const health = await fetch(BASE + '/api/health');
    console.log('\n→ GET', BASE + '/api/health');
    console.log('←', health.status, await health.json());
  } catch (err) {
    console.error('\nCould not reach server. Is it running?', err.message);
    process.exit(1);
  }

  // Auth via Authorization: Bearer
  await post('/api/sync', { Authorization: 'Bearer ' + ADMIN_KEY });

  // Auth via x-api-key
  await post('/api/webhook', { 'x-api-key': ADMIN_KEY });

  // Real Devmode sync path (what the website Sync button uses)
  await post('/api/admin/sync-products', { Authorization: 'Bearer ' + ADMIN_KEY });

  console.log('\nDone. Check your server / Render logs for [devmode-webhook] lines.');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
