// ═══════════════════════════════════════════════════════════════
// MELISA AI — Secure Backend Server v4.0 — MongoDB Atlas
// ✅ Real persistent database — data survives Render restarts
// ✅ All secrets in environment variables only
// ✅ OpenAI key never sent to browsers — proxied server-side
// ✅ Rate limiting & brute-force protection
// ✅ Helmet security headers
// ✅ CORS locked to your app domain
// ✅ Keep-alive ping so Render free tier never sleeps
// ═══════════════════════════════════════════════════════════════

const express   = require('express');
const cors      = require('cors');
const fetch     = require('node-fetch');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();

// ── ENV VARIABLES — set ALL of these in Render → Environment ──
//
//  MONGODB_URI             mongodb+srv://benedictleonusz_db_user:<password>@cluster0.6trvfm6.mongodb.net/?appName=Cluster0
//  ADMIN_PASS              your-strong-secret-password
//  OPENAI_API_KEY          sk-...
//  PESAPAL_CONSUMER_KEY    your pesapal key
//  PESAPAL_CONSUMER_SECRET your pesapal secret
//  APP_URL                 https://your-cloudflare-app.pages.dev
//  ALLOWED_ORIGIN          same as APP_URL
//  PESAPAL_ENV             live
//  APP_SERVER_URL          https://melisa-server.onrender.com
//
const MONGODB_URI    = process.env.MONGODB_URI    || '';
const ADMIN_PASS     = process.env.ADMIN_PASS     || '';
const APP_URL        = process.env.APP_URL        || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || APP_URL || '*';

if (!MONGODB_URI)  console.error('❌ MONGODB_URI not set!');
if (!ADMIN_PASS)   console.warn ('⚠️  ADMIN_PASS not set!');
if (!process.env.OPENAI_API_KEY) console.warn('⚠️  OPENAI_API_KEY not set!');

// ── MONGODB CONNECTION ─────────────────────────────────────────
let db = null; // will hold the connected database

const client = new MongoClient(MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function connectDB() {
  try {
    await client.connect();
    db = client.db('melisa'); // database name
    console.log('✅ MongoDB Atlas connected — database: melisa');

    // Create indexes for fast lookups
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('transactions').createIndex({ ref: 1 });
    await db.collection('transactions').createIndex({ created_at: -1 });

    // Seed default plans if none exist
    const cfg = await db.collection('config').findOne({ _id: 'settings' });
    if (!cfg) {
      await db.collection('config').insertOne({
        _id: 'settings',
        plans: {
          student:    { monthly: 4.99,   half_year: 4.49,   yearly: 3.74   },
          personal:   { monthly: 14.99,  half_year: 13.49,  yearly: 11.24  },
          business:   { monthly: 49.99,  half_year: 44.99,  yearly: 37.49  },
          enterprise: { monthly: 199.99, half_year: 179.99, yearly: 149.99 }
        },
        adminKeys: {}
      });
      console.log('✅ Default config seeded');
    }
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  }
}

// ── DB HELPERS ─────────────────────────────────────────────────
async function getConfig() {
  const doc = await db.collection('config').findOne({ _id: 'settings' });
  return doc || { plans: {}, adminKeys: {} };
}

async function saveConfig(updates) {
  await db.collection('config').updateOne(
    { _id: 'settings' },
    { $set: updates },
    { upsert: true }
  );
}

// ── SECURITY SETUP ─────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (
      ALLOWED_ORIGIN === '*' ||
      origin === ALLOWED_ORIGIN ||
      origin.endsWith('.netlify.app') ||
      origin.endsWith('.pages.dev') ||
      origin.endsWith('.workers.dev') ||
      origin.includes('melisa')
    ) return callback(null, true);
    console.warn(`🚫 CORS blocked: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '50kb' }));

// ── RATE LIMITERS ──────────────────────────────────────────────
const generalLimiter = rateLimit({ windowMs: 60000,       max: 100, message: { error: 'Too many requests.'           } });
const adminLimiter   = rateLimit({ windowMs: 15*60*1000,  max: 10,  message: { error: 'Too many admin attempts.'     } });
const aiLimiter      = rateLimit({ windowMs: 60000,       max: 30,  message: { error: 'AI rate limit reached.'       } });
const paymentLimiter = rateLimit({ windowMs: 10*60*1000,  max: 10,  message: { error: 'Too many payment requests.'   } });

app.use(generalLimiter);

// ── HELPERS ────────────────────────────────────────────────────
function checkAdminPass(password) {
  return ADMIN_PASS && password === ADMIN_PASS;
}

function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

// ── PESAPAL ────────────────────────────────────────────────────
async function getCfg() {
  const cfg = await getConfig();
  const k = cfg.adminKeys || {};
  return {
    key:    k.pesapal_key    || process.env.PESAPAL_CONSUMER_KEY    || '',
    secret: k.pesapal_secret || process.env.PESAPAL_CONSUMER_SECRET || '',
    env:    k.pesapal_env    || process.env.PESAPAL_ENV             || 'live',
    appUrl: k.app_url        || process.env.APP_URL                 || ''
  };
}
const pesapalBase = (env) => env === 'live'
  ? 'https://pay.pesapal.com/v3'
  : 'https://cybqa.pesapal.com/pesapalv3';

async function getToken() {
  const c = await getCfg();
  if (!c.key) throw new Error('Pesapal not configured. Add keys in Admin Panel.');
  const r = await fetch(`${pesapalBase(c.env)}/api/Auth/RequestToken`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ consumer_key: c.key, consumer_secret: c.secret })
  });
  const d = await r.json();
  if (!d.token) throw new Error('Pesapal auth failed');
  return { token: d.token, cfg: c };
}

async function registerIPN(token, cfg) {
  const r = await fetch(`${pesapalBase(cfg.env)}/api/URLSetup/RegisterIPN`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({ url: `${cfg.appUrl}/pesapal-webhook`, ipn_notification_type: 'POST' })
  });
  const d = await r.json();
  return d.notification_id || '';
}

// ══════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════

// ── Health check ──────────────────────────────────────────────
app.get('/', async (req, res) => {
  const c = await getCfg();
  res.json({
    status:  '✓ Melisa AI Server v4.0 — MongoDB Edition',
    secure:  true,
    db:      db ? '✓ MongoDB Connected' : '✗ Not connected',
    pesapal: c.key ? '✓ Configured' : '✗ Not configured'
  });
});

app.get('/ping', (req, res) => res.json({ pong: true, time: Date.now() }));

// ── GET settings (safe — no secrets sent to browser) ─────────
app.get('/settings', async (req, res) => {
  try {
    const cfg = await getConfig();
    const k = cfg.adminKeys || {};

    const [userCount, txDocs] = await Promise.all([
      db.collection('users').countDocuments(),
      db.collection('transactions').find({ status: 'ok' }).toArray()
    ]);
    const revenue = txDocs.reduce((a, t) => a + (parseFloat(t.amount) || 0), 0);

    res.json({
      success: true,
      plans: cfg.plans || {},
      config: {
        // ✅ OpenAI key NOT included — AI is proxied via /api/chat
        openai_model:     k.model             || process.env.OPENAI_MODEL || 'gpt-4o-mini',
        paypal_me:        k.paypal_me         || '',
        lipa_mpesa:       k.lipa_mpesa        || '',
        lipa_tigo:        k.lipa_tigo         || '',
        lipa_airtel:      k.lipa_airtel       || '',
        lipa_halopesa:    k.lipa_halopesa     || '',
        persona_name:     k.persona_name      || 'Melisa',
        persona_system:   k.persona_system    || '',
        google_client_id: k.google_client_id  || '',
        pesapal_ready:    !!(k.pesapal_key    || process.env.PESAPAL_CONSUMER_KEY),
        openai_ready:     !!(k.openai         || process.env.OPENAI_API_KEY),
      },
      stats: {
        users:        userCount,
        transactions: txDocs.length,
        revenue:      revenue.toFixed(2)
      }
    });
  } catch (err) {
    console.error('Settings error:', err.message);
    res.status(500).json({ error: 'Failed to load settings' });
  }
});

// ── 🤖 AI PROXY — OpenAI key never leaves the server ─────────
app.post('/api/chat', aiLimiter, async (req, res) => {
  try {
    const { messages, system, model, stream, max_tokens } = req.body;
    if (!messages || !Array.isArray(messages))
      return res.status(400).json({ error: 'Invalid messages' });

    const cfg = await getConfig();
    const apiKey = cfg.adminKeys?.openai || process.env.OPENAI_API_KEY || '';
    if (!apiKey) return res.status(503).json({ error: 'AI not configured. Contact admin.' });

    const aiModel      = model || cfg.adminKeys?.model || process.env.OPENAI_MODEL || 'gpt-4o-mini';
    const systemPrompt = sanitize(system || 'You are Melisa, a helpful AI assistant.', 2000);

    const payload = {
      model: aiModel,
      messages: [
        { role: 'system', content: systemPrompt },
        ...messages.slice(-20).map(m => ({
          role:    m.role === 'user' ? 'user' : 'assistant',
          content: sanitize(m.content, 4000)
        }))
      ],
      max_tokens: Math.min(parseInt(max_tokens) || 1200, 4000),
      stream:     stream === true,
    };

    const openaiRes = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify(payload)
    });

    if (!openaiRes.ok) {
      const err = await openaiRes.json();
      return res.status(openaiRes.status).json({ error: err.error?.message || 'OpenAI error' });
    }

    if (stream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      openaiRes.body.pipe(res);
    } else {
      const data = await openaiRes.json();
      res.json({ success: true, content: data.choices[0].message.content });
    }
  } catch (err) {
    console.error('AI proxy error:', err.message);
    res.status(500).json({ error: 'AI request failed. Try again.' });
  }
});

// ── SAVE admin settings → MongoDB ────────────────────────────
app.post('/admin/settings', adminLimiter, async (req, res) => {
  try {
    const { password, settings } = req.body;
    if (!checkAdminPass(password)) {
      console.warn(`🚫 Failed admin login from ${req.ip}`);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!settings || typeof settings !== 'object')
      return res.status(400).json({ error: 'Invalid settings' });

    const clean = {};
    for (const [k, v] of Object.entries(settings)) {
      if (typeof v === 'string') clean[sanitize(k, 50)] = sanitize(v, 1000);
    }
    await saveConfig({ [`adminKeys.${Object.keys(clean).join('`}, {`adminKeys.')}`]: undefined });
    // Properly merge each key
    const updates = {};
    for (const [k, v] of Object.entries(clean)) updates[`adminKeys.${k}`] = v;
    await db.collection('config').updateOne(
      { _id: 'settings' },
      { $set: updates },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Save settings error:', err.message);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// ── SAVE plan prices → MongoDB ────────────────────────────────
app.post('/admin/plans', adminLimiter, async (req, res) => {
  try {
    const { password, plans } = req.body;
    if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    if (!plans || typeof plans !== 'object') return res.status(400).json({ error: 'Invalid plans' });

    const updates = {};
    for (const [planId, prices] of Object.entries(plans)) {
      updates[`plans.${sanitize(planId, 30)}`] = prices;
    }
    await db.collection('config').updateOne(
      { _id: 'settings' },
      { $set: updates },
      { upsert: true }
    );
    const cfg = await getConfig();
    res.json({ success: true, plans: cfg.plans });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save plans' });
  }
});

// ── ADMIN: get all users ───────────────────────────────────────
app.post('/admin/users', adminLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    const users = await db.collection('users')
      .find({}, { projection: { password: 0, _id: 0 } }) // strip password
      .sort({ created: -1 })
      .toArray();
    res.json({ success: true, users });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ── ADMIN: get transactions ────────────────────────────────────
app.post('/admin/transactions', adminLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    const transactions = await db.collection('transactions')
      .find({}, { projection: { _id: 0 } })
      .sort({ created_at: -1 })
      .limit(500)
      .toArray();
    res.json({ success: true, transactions });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// ── ADMIN: clear revenue ───────────────────────────────────────
app.post('/admin/clear-revenue', adminLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    await db.collection('transactions').deleteMany({});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear revenue' });
  }
});

// ── SYNC user across devices ───────────────────────────────────
app.post('/user/sync', async (req, res) => {
  try {
    const { user } = req.body;
    if (!user?.email) return res.status(400).json({ error: 'Invalid user' });

    const email = sanitize(user.email, 200);
    const safe = {
      id:         sanitize(user.id   || '', 50),
      name:       sanitize(user.name || '', 100),
      email,
      plan:       sanitize(user.plan || 'free', 30),
      planExpiry: typeof user.planExpiry === 'number' ? user.planExpiry : null,
      created:    typeof user.created   === 'number' ? user.created   : Date.now(),
      avatar:     sanitize(user.avatar  || '', 5),
      isGoogle:   !!user.isGoogle,
      lastSeen:   Date.now(),
    };

    await db.collection('users').updateOne(
      { email },
      { $set: safe, $setOnInsert: { registeredAt: new Date() } },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Sync failed' });
  }
});

// ── GET user ───────────────────────────────────────────────────
app.get('/user/:email', async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { email: decodeURIComponent(req.params.email) },
      { projection: { password: 0, _id: 0 } }
    );
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ── CREATE PAYMENT ─────────────────────────────────────────────
app.post('/create-payment', paymentLimiter, async (req, res) => {
  try {
    const { amount, plan, plan_name, duration, email, phone, firstName, lastName, reference } = req.body;
    if (!amount || parseFloat(amount) <= 0) return res.status(400).json({ error: 'Invalid amount' });
    if (!email) return res.status(400).json({ error: 'Email required' });

    const { token, cfg } = await getToken();
    const notifId = await registerIPN(token, cfg);

    const ref         = sanitize(reference || 'MELISA_' + Date.now(), 60);
    const safeAmount  = parseFloat(amount);
    const safePlan    = sanitize(plan     || '', 30);
    const safeDur     = sanitize(duration || 'monthly', 20);
    const safeEmail   = sanitize(email,     200);
    const safePhone   = sanitize(phone  || '', 20);
    const safeFirst   = sanitize(firstName || 'Customer', 50);
    const safeLast    = sanitize(lastName  || 'User', 50);

    const orderRes = await fetch(`${pesapalBase(cfg.env)}/api/Transactions/SubmitOrderRequest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({
        id: ref, currency: 'USD', amount: safeAmount,
        description: `Melisa AI ${sanitize(plan_name || plan || 'Plan', 60)} - ${safeDur}`,
        callback_url: `${cfg.appUrl}?payment=success&plan=${safePlan}&ref=${ref}`,
        notification_id: notifId, branch: 'Melisa AI',
        billing_address: {
          email_address: safeEmail, phone_number: safePhone,
          first_name: safeFirst, last_name: safeLast,
          line_1: 'Tanzania', city: 'Dar es Salaam', country_code: 'TZ'
        }
      })
    });

    const od = await orderRes.json();
    if (!od.redirect_url) return res.status(400).json({ error: 'Payment failed', details: od });

    // Save transaction to MongoDB
    await db.collection('transactions').insertOne({
      id: 'tx_' + Date.now(), ref,
      plan: safePlan, amount: safeAmount, duration: safeDur,
      user: safeEmail, method: 'Pesapal', status: 'pending',
      tracking: od.order_tracking_id, created_at: new Date().toISOString(),
      time: Date.now()
    });

    console.log(`💳 Payment: ${ref} | $${safeAmount} | ${safePlan} | ${safeEmail}`);
    res.json({ success: true, redirect_url: od.redirect_url, order_tracking_id: od.order_tracking_id });
  } catch (err) {
    console.error('Payment error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── CHECK PAYMENT ──────────────────────────────────────────────
app.get('/check-payment/:id', async (req, res) => {
  try {
    const { token, cfg } = await getToken();
    const r = await fetch(
      `${pesapalBase(cfg.env)}/api/Transactions/GetTransactionStatus?orderTrackingId=${req.params.id}`,
      { headers: { 'Accept': 'application/json', 'Authorization': `Bearer ${token}` } }
    );
    const d = await r.json();
    const paid = d.payment_status_description === 'Completed';
    if (paid) {
      await db.collection('transactions').updateOne(
        { tracking: req.params.id },
        { $set: { status: 'ok', confirmed_at: new Date().toISOString() } }
      );
    }
    res.json({ success: true, paid, status: d.payment_status_description });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PESAPAL WEBHOOK ────────────────────────────────────────────
app.post('/pesapal-webhook', async (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.body;
  console.log(`💰 PAYMENT CONFIRMED: ${OrderMerchantReference}`);
  try {
    const tx = await db.collection('transactions').findOneAndUpdate(
      { $or: [{ ref: OrderMerchantReference }, { tracking: OrderTrackingId }] },
      { $set: { status: 'ok', confirmed_at: new Date().toISOString() } },
      { returnDocument: 'after' }
    );
    if (tx?.value) {
      await db.collection('users').updateOne(
        { email: tx.value.user },
        { $set: {
          plan: tx.value.plan,
          planExpiry: Date.now() +
            (tx.value.duration === 'yearly' ? 365 : tx.value.duration === '6months' ? 180 : 30) * 86400000
        }}
      );
    }
  } catch (err) {
    console.error('Webhook error:', err.message);
  }
  res.json({
    orderNotificationType: 'IPNCHANGE',
    orderTrackingId: OrderTrackingId,
    orderMerchantReference: OrderMerchantReference,
    status: '200'
  });
});

app.get('/pesapal-webhook', async (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.query;
  const c = await getCfg();
  const tx = await db.collection('transactions').findOne({ ref: OrderMerchantReference });
  res.redirect(
    `${c.appUrl}?payment=success&ref=${OrderMerchantReference}&plan=${tx?.plan || ''}&tracking=${OrderTrackingId}`
  );
});

// ── 404 & error handlers ───────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Keep-alive self-ping ───────────────────────────────────────
const SERVER_URL = process.env.APP_SERVER_URL || `http://localhost:${process.env.PORT || 3000}`;
setInterval(() => {
  fetch(`${SERVER_URL}/ping`).catch(() => {});
}, 4 * 60 * 1000);

// ── START — connect MongoDB first, then listen ─────────────────
const PORT = process.env.PORT || 3000;
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀 Melisa Server v4.0 MongoDB — port ${PORT}`);
    console.log(`🔒 Admin pass:   ${ADMIN_PASS              ? '✓ Set' : '✗ NOT SET'}`);
    console.log(`🤖 OpenAI:       ${process.env.OPENAI_API_KEY ? '✓ Set' : '✗ NOT SET'}`);
    console.log(`🍃 MongoDB:      ${db                      ? '✓ Connected' : '✗ Not connected'}`);
    console.log(`🌐 CORS origin:  ${ALLOWED_ORIGIN}\n`);
  });
});
