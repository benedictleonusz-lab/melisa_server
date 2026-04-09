// ═══════════════════════════════════════════════════════
// MELISA AI — Complete Backend Server v2.0
// - Real Pesapal payments
// - Settings saved to database (ALL devices)
// - Admin sets prices and config
// ═══════════════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── FILE DATABASE ─────────────────────────────────────
const DB_FILE = path.join(__dirname, 'melisa_db.json');

function readDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch(e) {}
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
  catch(e) { console.error('DB error:', e.message); return false; }
}

// ── PESAPAL ───────────────────────────────────────────
function getCfg() {
  const db = readDB();
  return {
    key:    db.adminKeys.pesapal_key    || process.env.PESAPAL_CONSUMER_KEY    || '',
    secret: db.adminKeys.pesapal_secret || process.env.PESAPAL_CONSUMER_SECRET || '',
    env:    db.adminKeys.pesapal_env    || process.env.PESAPAL_ENV             || 'live',
    appUrl: db.adminKeys.app_url        || process.env.APP_URL                 || 'https://melisa-ai-companylmt.benedictleonus-z.workers.dev'
  };
}
const base = (env) => env==='live' ? 'https://pay.pesapal.com/v3' : 'https://cybqa.pesapal.com/pesapalv3';

async function getToken() {
  const c = getCfg();
  if (!c.key) throw new Error('Pesapal not configured. Add keys in Admin Panel.');
  const r = await fetch(`${base(c.env)}/api/Auth/RequestToken`,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({consumer_key:c.key,consumer_secret:c.secret})});
  const d = await r.json();
  if (!d.token) throw new Error('Pesapal auth failed');
  return {token:d.token, cfg:c};
}

async function registerIPN(token, cfg) {
  const r = await fetch(`${base(cfg.env)}/api/URLSetup/RegisterIPN`,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${token}`},body:JSON.stringify({url:`${cfg.appUrl}/pesapal-webhook`,ipn_notification_type:'POST'})});
  const d = await r.json();
  return d.notification_id || '';
}

// ══════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════

app.get('/', (req, res) => {
  const c = getCfg();
  res.json({ status:'✓ Melisa AI Server v2.0 running', pesapal: c.key?'✓ Configured':'✗ Not configured', env:c.env });
});

// ── GET settings (loads on any device) ───────────────
app.get('/settings', (req, res) => {
  const db = readDB();
  res.json({
    success: true,
    plans: db.plans,
    config: {
      openai_key:        db.adminKeys.openai          || db.adminKeys.openai_key || process.env.OPENAI_API_KEY || '',
      openai_model:      db.adminKeys.model           || db.adminKeys.openai_model || 'gpt-4o-mini',
      paypal_me:         db.adminKeys.paypal_me       || '',
      lipa_mpesa:        db.adminKeys.lipa_mpesa      || '',
      lipa_tigo:         db.adminKeys.lipa_tigo       || '',
      lipa_airtel:       db.adminKeys.lipa_airtel     || '',
      lipa_halopesa:     db.adminKeys.lipa_halopesa   || '',
      persona_name:      db.adminKeys.persona_name    || 'Melisa',
      persona_system:    db.adminKeys.persona_system  || '',
      google_client_id:  db.adminKeys.google_client_id|| '1045630006139-4a55ju0ns3q9i5gl3bporp73ddchlrei.apps.googleusercontent.com',
      pesapal_ready:     !!(db.adminKeys.pesapal_key  || process.env.PESAPAL_CONSUMER_KEY),
      openai_ready:      !!(db.adminKeys.openai || db.adminKeys.openai_key || process.env.OPENAI_API_KEY),
    },
    stats: {
      users:       db.users.length,
      transactions:db.transactions.length,
      revenue:     db.transactions.filter(t=>t.status==='ok').reduce((a,t)=>a+(parseFloat(t.amount)||0),0).toFixed(2)
    }
  });
});

// ── SAVE settings ─────────────────────────────────────
app.post('/admin/settings', (req, res) => {
  const { password, settings } = req.body;
  const db = readDB();
  const pass = db.adminKeys.admin_pass || process.env.ADMIN_PASS || '2ben@mama3012melisa@053012';
  if (password !== pass) return res.status(401).json({ error: 'Wrong password' });
  db.adminKeys = { ...db.adminKeys, ...settings };
  writeDB(db);
  res.json({ success: true });
});

// ── SAVE plan prices ──────────────────────────────────
app.post('/admin/plans', (req, res) => {
  const { password, plans } = req.body;
  const db = readDB();
  const pass = db.adminKeys.admin_pass || process.env.ADMIN_PASS || '2ben@mama3012melisa@053012';
  if (password !== pass) return res.status(401).json({ error: 'Wrong password' });
  db.plans = { ...db.plans, ...plans };
  writeDB(db);
  res.json({ success: true, plans: db.plans });
});

// ── SYNC user across devices ──────────────────────────
app.post('/user/sync', (req, res) => {
  const { user } = req.body;
  if (!user?.email) return res.status(400).json({ error: 'No user' });
  const db = readDB();
  const idx = db.users.findIndex(u => u.email === user.email);
  const updated = { ...( idx>=0 ? db.users[idx] : {}), ...user, lastSeen: Date.now() };
  if (idx >= 0) db.users[idx] = updated; else db.users.push(updated);
  writeDB(db);
  res.json({ success: true, user: updated });
});

// ── GET user (login from any device) ─────────────────
app.get('/user/:email', (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.email === decodeURIComponent(req.params.email));
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true, user });
});

// ── ADMIN: get all users ──────────────────────────────
app.post('/admin/users', (req, res) => {
  const { password } = req.body;
  const db = readDB();
  const pass = db.adminKeys.admin_pass || process.env.ADMIN_PASS || '2ben@mama3012melisa@053012';
  if (password !== pass) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ success: true, users: db.users });
});

// ── ADMIN: get transactions ───────────────────────────
app.post('/admin/transactions', (req, res) => {
  const { password } = req.body;
  const db = readDB();
  const pass = db.adminKeys.admin_pass || process.env.ADMIN_PASS || '2ben@mama3012melisa@053012';
  if (password !== pass) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ success: true, transactions: db.transactions });
});

// ── ADMIN: clear revenue ──────────────────────────────
app.post('/admin/clear-revenue', (req, res) => {
  const { password } = req.body;
  const db = readDB();
  const pass = db.adminKeys.admin_pass || process.env.ADMIN_PASS || '2ben@mama3012melisa@053012';
  if (password !== pass) return res.status(401).json({ error: 'Unauthorized' });
  db.transactions = [];
  writeDB(db);
  res.json({ success: true });
});

// ── CREATE PAYMENT ────────────────────────────────────
app.post('/create-payment', async (req, res) => {
  try {
    const { amount, plan, plan_name, duration, email, phone, firstName, lastName, reference } = req.body;
    if (!amount || parseFloat(amount) <= 0) return res.status(400).json({ error: 'Invalid amount' });
    const { token, cfg } = await getToken();
    const notifId = await registerIPN(token, cfg);
    const ref = reference || 'MELISA_' + Date.now();
    const orderRes = await fetch(`${base(cfg.env)}/api/Transactions/SubmitOrderRequest`,{
      method:'POST',
      headers:{'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${token}`},
      body:JSON.stringify({
        id:ref, currency:'USD', amount:parseFloat(amount),
        description:`Melisa AI ${plan_name||plan||'Plan'} - ${duration||'Monthly'}`,
        callback_url:`${cfg.appUrl}?payment=success&plan=${plan}&ref=${ref}`,
        notification_id:notifId, branch:'Melisa AI',
        billing_address:{
          email_address:email||'customer@melisaai.com',
          phone_number:phone||'',
          first_name:firstName||'Customer',
          last_name:lastName||'User',
          line_1:'Tanzania',city:'Dar es Salaam',country_code:'TZ'
        }
      })
    });
    const od = await orderRes.json();
    if (!od.redirect_url) return res.status(400).json({ error:'Payment failed', details:od });
    // Log
    const db = readDB();
    db.transactions.unshift({id:'tx_'+Date.now(),ref,plan,amount:parseFloat(amount),duration,user:email,method:'Pesapal',status:'pending',tracking:od.order_tracking_id,created_at:new Date().toISOString()});
    writeDB(db);
    console.log(`💳 Payment: ${ref} | $${amount} | ${plan} | ${email}`);
    res.json({ success:true, redirect_url:od.redirect_url, order_tracking_id:od.order_tracking_id });
  } catch(err) {
    console.error('Payment error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── CHECK PAYMENT ─────────────────────────────────────
app.get('/check-payment/:id', async (req, res) => {
  try {
    const { token, cfg } = await getToken();
    const r = await fetch(`${base(cfg.env)}/api/Transactions/GetTransactionStatus?orderTrackingId=${req.params.id}`,{headers:{'Accept':'application/json','Authorization':`Bearer ${token}`}});
    const d = await r.json();
    const paid = d.payment_status_description === 'Completed';
    if (paid) {
      const db = readDB();
      const tx = db.transactions.find(t => t.tracking === req.params.id);
      if (tx) { tx.status='ok'; tx.confirmed_at=new Date().toISOString(); writeDB(db); }
    }
    res.json({ success:true, paid, status:d.payment_status_description, amount:d.amount, method:d.payment_method });
  } catch(err) { res.status(500).json({ error:err.message }); }
});

// ── PESAPAL WEBHOOK ───────────────────────────────────
app.post('/pesapal-webhook', (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.body;
  console.log(`💰 PAYMENT CONFIRMED: ${OrderMerchantReference}`);
  const db = readDB();
  const tx = db.transactions.find(t => t.ref===OrderMerchantReference || t.tracking===OrderTrackingId);
  if (tx) {
    tx.status='ok'; tx.confirmed_at=new Date().toISOString();
    const user = db.users.find(u => u.email===tx.user);
    if (user) {
      user.plan=tx.plan;
      user.planExpiry=Date.now()+(tx.duration==='yearly'?365:tx.duration==='6months'?180:30)*86400000;
    }
    writeDB(db);
  }
  res.json({ orderNotificationType:'IPNCHANGE', orderTrackingId:OrderTrackingId, orderMerchantReference:OrderMerchantReference, status:'200' });
});

app.get('/pesapal-webhook', (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.query;
  const cfg = getCfg();
  const db = readDB();
  const tx = db.transactions.find(t => t.ref===OrderMerchantReference);
  res.redirect(`${cfg.appUrl}?payment=success&ref=${OrderMerchantReference}&plan=${tx?.plan||''}&tracking=${OrderTrackingId}`);
});

// ── START ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Melisa Server v2.0 on port ${PORT} | Pesapal: ${getCfg().key?'✓':'✗'}`));
