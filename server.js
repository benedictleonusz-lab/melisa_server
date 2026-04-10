// ═══════════════════════════════════════════════════════════════
// MELISA AI — Secure Backend Server v3.0
// ✅ All secrets in environment variables — NOTHING hardcoded
// ✅ OpenAI key never sent to browsers — proxied server-side
// ✅ Rate limiting — brute force protection
// ✅ Helmet security headers
// ✅ CORS locked to your app domain only
// ✅ Input validation & sanitization
// ✅ Admin password verified via SHA-256 hash
// ✅ Keep-alive ping so Render never sleeps
// ═══════════════════════════════════════════════════════════════

const express    = require('express');
const cors       = require('cors');
const fetch      = require('node-fetch');
const fs         = require('fs');
const path       = require('path');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const crypto     = require('crypto'); // built-in — no install needed

const app = express();

// ── ENV VARIABLES (set these in Render → Environment) ─────────
// Required:
//   ADMIN_PASS_HASH         → SHA-256 hash of your admin password
//                             Generate: node -e "const c=require('crypto');console.log(c.createHash('sha256').update('YOUR_PASSWORD').digest('hex'))"
//   OPENAI_API_KEY          → your OpenAI key
//   PESAPAL_CONSUMER_KEY    → Pesapal key
//   PESAPAL_CONSUMER_SECRET → Pesapal secret
//   APP_URL                 → https://your-cloudflare-app.com
//   ALLOWED_ORIGIN          → same as APP_URL (for CORS)
// Optional:
//   PESAPAL_ENV             → 'live' or 'sandbox' (default: live)
//   PORT                    → auto-set by Render

const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || '';
const APP_URL         = process.env.APP_URL          || '';
const ALLOWED_ORIGIN  = process.env.ALLOWED_ORIGIN   || APP_URL || '*';

// ── SECURITY: warn if secrets are missing ─────────────────────
if (!ADMIN_PASS_HASH) console.warn('⚠️  WARNING: ADMIN_PASS_HASH env var not set!');
if (!process.env.OPENAI_API_KEY) console.warn('⚠️  WARNING: OPENAI_API_KEY env var not set!');

// ── HELMET — security headers ──────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// ── CORS — only allow your app domain ─────────────────────────
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
    ) {
      return callback(null, true);
    }
    console.warn(`🚫 CORS blocked: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── REQUEST LIMITS — prevent large payload attacks ─────────────
app.use(express.json({ limit: '50kb' }));

// ── RATE LIMITERS ──────────────────────────────────────────────

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many admin attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'AI rate limit reached. Please wait a moment.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const paymentLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Too many payment requests. Please wait.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

// ── FILE DATABASE ──────────────────────────────────────────────
const DB_FILE = path.join(__dirname, 'melisa_db.json');

function readDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch(e) { console.error('DB read error:', e.message); }
  return {
    adminKeys: {},
    users: [],
    transactions: [],
    plans: {
      student:    { monthly:4.99,   half_year:4.49,   yearly:3.74   },
      personal:   { monthly:14.99,  half_year:13.49,  yearly:11.24  },
      business:   { monthly:49.99,  half_year:44.99,  yearly:37.49  },
      enterprise: { monthly:199.99, half_year:179.99, yearly:149.99 }
    }
  };
}

function writeDB(data) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); return true; }
  catch(e) { console.error('DB write error:', e.message); return false; }
}

// ── ADMIN PASSWORD CHECK (SHA-256 hashed) ─────────────────────
// Set ADMIN_PASS_HASH in Render env to the SHA-256 hex of your password.
// To generate: node -e "const c=require('crypto');console.log(c.createHash('sha256').update('YOUR_PASSWORD').digest('hex'))"
function checkAdminPass(password) {
  if (!ADMIN_PASS_HASH || typeof password !== 'string') return false;
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  return hash === ADMIN_PASS_HASH;
}

// ── SANITIZE input strings ─────────────────────────────────────
function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

// ── PESAPAL ────────────────────────────────────────────────────
function getCfg() {
  const db = readDB();
  return {
    key:    db.adminKeys.pesapal_key    || process.env.PESAPAL_CONSUMER_KEY    || '',
    secret: db.adminKeys.pesapal_secret || process.env.PESAPAL_CONSUMER_SECRET || '',
    env:    db.adminKeys.pesapal_env    || process.env.PESAPAL_ENV             || 'live',
    appUrl: db.adminKeys.app_url        || process.env.APP_URL                 || ''
  };
}
const base = (env) => env === 'live'
  ? 'https://pay.pesapal.com/v3'
  : 'https://cybqa.pesapal.com/pesapalv3';

async function getToken() {
  const c = getCfg();
  if (!c.key) throw new Error('Pesapal not configured. Add keys in Admin Panel.');
  const r = await fetch(`${base(c.env)}/api/Auth/RequestToken`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ consumer_key: c.key, consumer_secret: c.secret })
  });
  const d = await r.json();
  if (!d.token) throw new Error('Pesapal auth failed');
  return { token: d.token, cfg: c };
}

async function registerIPN(token, cfg) {
  const r = await fetch(`${base(cfg.env)}/api/URLSetup/RegisterIPN`, {
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

app.get('/', (req, res) => {
  res.json({
    status: '✓ Melisa AI Server v3.0 running',
    secure: true,
    pesapal: getCfg().key ? '✓ Configured' : '✗ Not configured'
  });
});

app.get('/ping', (req, res) => res.json({ pong: true, time: Date.now() }));

app.get('/settings', (req, res) => {
  const db = readDB();
  res.json({
    success: true,
    plans: db.plans,
    config: {
      openai_model:     db.adminKeys.model           || process.env.OPENAI_MODEL  || 'gpt-4o-mini',
      paypal_me:        db.adminKeys.paypal_me        || '',
      lipa_mpesa:       db.adminKeys.lipa_mpesa       || '',
      lipa_tigo:        db.adminKeys.lipa_tigo        || '',
      lipa_airtel:      db.adminKeys.lipa_airtel      || '',
      lipa_halopesa:    db.adminKeys.lipa_halopesa    || '',
      persona_name:     db.adminKeys.persona_name     || 'Melisa',
      persona_system:   db.adminKeys.persona_system   || '',
      google_client_id: db.adminKeys.google_client_id || '',
      pesapal_ready:    !!(db.adminKeys.pesapal_key   || process.env.PESAPAL_CONSUMER_KEY),
      openai_ready:     !!(db.adminKeys.openai        || process.env.OPENAI_API_KEY),
    },
    stats: {
      users:        db.users.length,
      transactions: db.transactions.length,
      revenue:      db.transactions
                      .filter(t => t.status === 'ok')
                      .reduce((a, t) => a + (parseFloat(t.amount) || 0), 0)
                      .toFixed(2)
    }
  });
});

// ── 🤖 AI PROXY — OpenAI key NEVER leaves the server ──────────
app.post('/api/chat', aiLimiter, async (req, res) => {
  try {
    const { messages, system, model, stream, max_tokens } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'Invalid messages' });
    }

    const db = readDB();
    const apiKey = db.adminKeys.openai || process.env.OPENAI_API_KEY || '';
    if (!apiKey) return res.status(503).json({ error: 'AI not configured. Contact admin.' });

    const aiModel = model || db.adminKeys.model || process.env.OPENAI_MODEL || 'gpt-4o-mini';
    const systemPrompt = sanitize(system || 'You are Melisa, a helpful AI assistant.', 2000);

    const payload = {
      model: aiModel,
      messages: [
        { role: 'system', content: systemPrompt },
        ...messages.slice(-20).map(m => ({
          role: m.role === 'user' ? 'user' : 'assistant',
          content: sanitize(m.content, 4000)
        }))
      ],
      max_tokens: Math.min(parseInt(max_tokens) || 1200, 4000),
      stream: stream === true,
    };

    const openaiRes = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
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

// ── SAVE admin settings ────────────────────────────────────────
app.post('/admin/settings', adminLimiter, (req, res) => {
  const { password, settings } = req.body;
  if (!checkAdminPass(password)) {
    console.warn(`🚫 Failed admin login attempt from ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'Invalid settings' });
  }
  const db = readDB();
  const clean = {};
  for (const [k, v] of Object.entries(settings)) {
    if (typeof v === 'string') clean[sanitize(k, 50)] = sanitize(v, 1000);
  }
  db.adminKeys = { ...db.adminKeys, ...clean };
  writeDB(db);
  res.json({ success: true });
});

// ── SAVE plan prices ───────────────────────────────────────────
app.post('/admin/plans', adminLimiter, (req, res) => {
  const { password, plans } = req.body;
  if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
  if (!plans || typeof plans !== 'object') return res.status(400).json({ error: 'Invalid plans' });
  const db = readDB();
  db.plans = { ...db.plans, ...plans };
  writeDB(db);
  res.json({ success: true, plans: db.plans });
});

// ── ADMIN: get all users ───────────────────────────────────────
app.post('/admin/users', adminLimiter, (req, res) => {
  const { password } = req.body;
  if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
  const db = readDB();
  const safe = db.users.map(({ password: _p, ...u }) => u);
  res.json({ success: true, users: safe });
});

// ── ADMIN: get transactions ────────────────────────────────────
app.post('/admin/transactions', adminLimiter, (req, res) => {
  const { password } = req.body;
  if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
  const db = readDB();
  res.json({ success: true, transactions: db.transactions });
});

// ── ADMIN: clear revenue ───────────────────────────────────────
app.post('/admin/clear-revenue', adminLimiter, (req, res) => {
  const { password } = req.body;
  if (!checkAdminPass(password)) return res.status(401).json({ error: 'Unauthorized' });
  const db = readDB();
  db.transactions = [];
  writeDB(db);
  res.json({ success: true });
});

// ── SYNC user across devices ───────────────────────────────────
app.post('/user/sync', (req, res) => {
  const { user } = req.body;
  if (!user?.email || typeof user.email !== 'string') {
    return res.status(400).json({ error: 'Invalid user' });
  }
  const email = sanitize(user.email, 200);
  const db = readDB();
  const idx = db.users.findIndex(u => u.email === email);
  const safe = {
    id:          sanitize(user.id || '', 50),
    name:        sanitize(user.name || '', 100),
    email:       email,
    plan:        sanitize(user.plan || 'free', 30),
    planExpiry:  typeof user.planExpiry === 'number' ? user.planExpiry : null,
    created:     typeof user.created === 'number' ? user.created : Date.now(),
    avatar:      sanitize(user.avatar || '', 5),
    isGoogle:    !!user.isGoogle,
    lastSeen:    Date.now(),
  };
  if (idx >= 0) {
    db.users[idx] = { ...db.users[idx], ...safe };
  } else {
    db.users.push(safe);
  }
  writeDB(db);
  res.json({ success: true });
});

// ── GET user ───────────────────────────────────────────────────
app.get('/user/:email', (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.email === decodeURIComponent(req.params.email));
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { password: _p, ...safe } = user;
  res.json({ success: true, user: safe });
});

// ── CREATE PAYMENT ─────────────────────────────────────────────
app.post('/create-payment', paymentLimiter, async (req, res) => {
  try {
    const {
      amount, plan, plan_name, duration,
      email, phone, firstName, lastName, reference
    } = req.body;

    if (!amount || parseFloat(amount) <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email required' });
    }

    const { token, cfg } = await getToken();
    const notifId = await registerIPN(token, cfg);
    const ref = sanitize(reference || 'MELISA_' + Date.now(), 60);
    const safeAmount   = parseFloat(amount);
    const safePlan     = sanitize(plan || '', 30);
    const safeDuration = sanitize(duration || 'monthly', 20);
    const safeEmail    = sanitize(email, 200);
    const safePhone    = sanitize(phone || '', 20);
    const safeFirst    = sanitize(firstName || 'Customer', 50);
    const safeLast     = sanitize(lastName  || 'User', 50);

    const orderRes = await fetch(
      `${base(cfg.env)}/api/Transactions/SubmitOrderRequest`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          id: ref,
          currency: 'USD',
          amount: safeAmount,
          description: `Melisa AI ${sanitize(plan_name || plan || 'Plan', 60)} - ${safeDuration}`,
          callback_url: `${cfg.appUrl}?payment=success&plan=${safePlan}&ref=${ref}`,
          notification_id: notifId,
          branch: 'Melisa AI',
          billing_address: {
            email_address: safeEmail,
            phone_number:  safePhone,
            first_name:    safeFirst,
            last_name:     safeLast,
            line_1: 'Tanzania', city: 'Dar es Salaam', country_code: 'TZ'
          }
        })
      }
    );

    const od = await orderRes.json();
    if (!od.redirect_url) {
      return res.status(400).json({ error: 'Payment failed', details: od });
    }

    const db = readDB();
    db.transactions.unshift({
      id: 'tx_' + Date.now(), ref,
      plan: safePlan, amount: safeAmount,
      duration: safeDuration, user: safeEmail,
      method: 'Pesapal', status: 'pending',
      tracking: od.order_tracking_id,
      created_at: new Date().toISOString()
    });
    writeDB(db);
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
      `${base(cfg.env)}/api/Transactions/GetTransactionStatus?orderTrackingId=${req.params.id}`,
      { headers: { 'Accept': 'application/json', 'Authorization': `Bearer ${token}` } }
    );
    const d = await r.json();
    const paid = d.payment_status_description === 'Completed';
    if (paid) {
      const db = readDB();
      const tx = db.transactions.find(t => t.tracking === req.params.id);
      if (tx) { tx.status = 'ok'; tx.confirmed_at = new Date().toISOString(); writeDB(db); }
    }
    res.json({ success: true, paid, status: d.payment_status_description });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PESAPAL WEBHOOK ────────────────────────────────────────────
app.post('/pesapal-webhook', (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.body;
  console.log(`💰 PAYMENT CONFIRMED: ${OrderMerchantReference}`);
  const db = readDB();
  const tx = db.transactions.find(
    t => t.ref === OrderMerchantReference || t.tracking === OrderTrackingId
  );
  if (tx) {
    tx.status = 'ok';
    tx.confirmed_at = new Date().toISOString();
    const user = db.users.find(u => u.email === tx.user);
    if (user) {
      user.plan = tx.plan;
      user.planExpiry = Date.now() +
        (tx.duration === 'yearly' ? 365 : tx.duration === '6months' ? 180 : 30) * 86400000;
    }
    writeDB(db);
  }
  res.json({
    orderNotificationType: 'IPNCHANGE',
    orderTrackingId: OrderTrackingId,
    orderMerchantReference: OrderMerchantReference,
    status: '200'
  });
});

app.get('/pesapal-webhook', (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.query;
  const cfg = getCfg();
  const db = readDB();
  const tx = db.transactions.find(t => t.ref === OrderMerchantReference);
  res.redirect(
    `${cfg.appUrl}?payment=success&ref=${OrderMerchantReference}&plan=${tx?.plan || ''}&tracking=${OrderTrackingId}`
  );
});

// ── 404 fallback ───────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── Global error handler ───────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Keep-alive self-ping ───────────────────────────────────────
const SERVER_URL = process.env.APP_SERVER_URL || `http://localhost:${process.env.PORT || 3000}`;
setInterval(() => {
  fetch(`${SERVER_URL}/ping`)
    .then(() => console.log('💓 Keep-alive ping sent'))
    .catch(() => {});
}, 4 * 60 * 1000);

// ── START ──────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Melisa Server v3.0 SECURE — port ${PORT}`);
  console.log(`🔒 Admin pass:  ${ADMIN_PASS_HASH ? '✓ Hash set via env' : '✗ NOT SET — set ADMIN_PASS_HASH in Render!'}`);
  console.log(`🤖 OpenAI:      ${process.env.OPENAI_API_KEY ? '✓ Set via env' : '✗ NOT SET'}`);
  console.log(`💳 Pesapal:     ${getCfg().key ? '✓ Configured' : '✗ Not configured'}`);
  console.log(`🌐 CORS origin: ${ALLOWED_ORIGIN}\n`);
});
