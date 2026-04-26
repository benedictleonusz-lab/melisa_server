// MELISA AI — Secure Server v5.0 — Fixed & Production Ready
'use strict';

const express   = require('express');
const cors      = require('cors');
const fetch     = require('node-fetch');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ServerApiVersion } = require('mongodb');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');

const app = express();

// ── ENV ────────────────────────────────────────────────────────
const MONGODB_URI    = process.env.MONGODB_URI    || '';
const ADMIN_PASS     = process.env.ADMIN_PASS     || 'h1ee8ea0d';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || process.env.APP_URL || '*';
const PORT           = process.env.PORT           || 3000;
const SERVER_URL     = process.env.APP_SERVER_URL || 'http://localhost:' + PORT;

// ── MONGODB ────────────────────────────────────────────────────
let db = null;
let mongoConnecting = false;

async function connectDB() {
  if (!MONGODB_URI || mongoConnecting) return;
  mongoConnecting = true;
  try {
    const client = new MongoClient(MONGODB_URI, {
      serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
      connectTimeoutMS: 10000,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 15000,
      maxPoolSize: 10,
      retryWrites: true
    });
    await client.connect();
    db = client.db('melisa');
    console.log('✅ MongoDB connected');

    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('transactions').createIndex({ ref: 1 });
    await db.collection('sessions').createIndex({ email: 1 }, { unique: true });

    const exists = await db.collection('config').findOne({ _id: 'settings' });
    if (!exists) {
      await db.collection('config').insertOne({
        _id: 'settings',
        adminKeys: {},
        plans: {
          starter:      { monthly: 2.99,   half_year: 2.69,   yearly: 2.24   },
          student:      { monthly: 4.99,   half_year: 4.49,   yearly: 3.74   },
          personal:     { monthly: 14.99,  half_year: 13.49,  yearly: 11.24  },
          creator:      { monthly: 24.99,  half_year: 22.49,  yearly: 18.74  },
          pro:          { monthly: 34.99,  half_year: 31.49,  yearly: 26.24  },
          business:     { monthly: 49.99,  half_year: 44.99,  yearly: 37.49  },
          business_plus:{ monthly: 99.99,  half_year: 89.99,  yearly: 74.99  },
          enterprise:   { monthly: 199.99, half_year: 179.99, yearly: 149.99 }
        }
      });
    }

    // Handle disconnections gracefully
    client.on('close', () => {
      console.warn('⚠️ MongoDB disconnected — will reconnect');
      db = null;
      mongoConnecting = false;
      setTimeout(connectDB, 5000);
    });
  } catch (e) {
    console.error('❌ MongoDB error:', e.message);
    db = null;
    mongoConnecting = false;
    setTimeout(connectDB, 10000); // retry after 10s
  }
}

// ── HELPERS ────────────────────────────────────────────────────
async function getCfgDoc() {
  if (!db) return { adminKeys: {}, plans: {} };
  try {
    return await db.collection('config').findOne({ _id: 'settings' }) || { adminKeys: {}, plans: {} };
  } catch(e) { return { adminKeys: {}, plans: {} }; }
}

function sanitize(val, max) {
  if (typeof val !== 'string') return '';
  return val.trim().slice(0, max || 500).replace(/[<>]/g, '');
}

function checkPass(pw) {
  return pw === ADMIN_PASS;
}

function hashPassword(raw) {
  return crypto.createHash('sha256').update('melisa_salt_' + raw).digest('hex');
}

// ── PESAPAL ────────────────────────────────────────────────────
async function getPesapalCfg() {
  const doc = await getCfgDoc();
  const k = doc.adminKeys || {};
  return {
    key:    k.pesapal_key    || process.env.PESAPAL_CONSUMER_KEY    || '',
    secret: k.pesapal_secret || process.env.PESAPAL_CONSUMER_SECRET || '',
    env:    k.pesapal_env    || process.env.PESAPAL_ENV             || 'live',
    appUrl: k.app_url        || process.env.APP_URL                 || ''
  };
}

function pesapalBase(env) {
  return env === 'live'
    ? 'https://pay.pesapal.com/v3'
    : 'https://cybqa.pesapal.com/pesapalv3';
}

async function getPesapalToken() {
  const c = await getPesapalCfg();
  if (!c.key) throw new Error('Pesapal not configured');
  const r = await fetch(pesapalBase(c.env) + '/api/Auth/RequestToken', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ consumer_key: c.key, consumer_secret: c.secret }),
    signal: AbortSignal.timeout ? AbortSignal.timeout(15000) : undefined
  });
  const d = await r.json();
  if (!d.token) throw new Error('Pesapal auth failed: ' + JSON.stringify(d));
  return { token: d.token, cfg: c };
}

async function registerIPN(token, cfg) {
  try {
    const r = await fetch(pesapalBase(cfg.env) + '/api/URLSetup/RegisterIPN', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ url: cfg.appUrl + '/pesapal-webhook', ipn_notification_type: 'POST' })
    });
    const d = await r.json();
    return d.notification_id || '';
  } catch(e) { return ''; }
}

// ── SECURITY MIDDLEWARE ────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true);
    if (
      ALLOWED_ORIGIN === '*' ||
      origin === ALLOWED_ORIGIN ||
      origin.endsWith('.netlify.app') ||
      origin.endsWith('.pages.dev') ||
      origin.endsWith('.workers.dev') ||
      origin.includes('melisa') ||
      origin.includes('localhost') ||
      origin.includes('127.0.0.1') ||
      origin.includes('render.com') ||
      origin.includes('onrender.com')
    ) return cb(null, true);
    return cb(new Error('CORS blocked: ' + origin));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json({ limit: '15mb' }));

const generalLimit = rateLimit({ windowMs: 60000,  max: 150, standardHeaders: true, legacyHeaders: false });
const adminLimit   = rateLimit({ windowMs: 900000, max: 20,  message: { error: 'Too many admin attempts' } });
const aiLimit      = rateLimit({ windowMs: 60000,  max: 40,  message: { error: 'Slow down! Try again in a minute.' } });
const payLimit     = rateLimit({ windowMs: 600000, max: 15,  message: { error: 'Too many payment requests' } });
const ttsLimit     = rateLimit({ windowMs: 60000,  max: 50,  message: { error: 'TTS limit reached' } });

app.use(generalLimit);

// ══════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

app.get('/health', async (req, res) => {
  const c = await getPesapalCfg();
  res.json({
    status:  '✓ Melisa AI Server v5.0',
    secure:  true,
    db:      db ? '✓ MongoDB Connected' : '✗ Not connected',
    pesapal: c.key ? '✓ Configured' : '✗ Not configured',
    uptime:  Math.floor(process.uptime()) + 's'
  });
});

app.get('/', (req, res) => {
  const htmlFile = path.join(__dirname, 'index.html');
  if (fs.existsSync(htmlFile)) return res.sendFile(htmlFile);
  const pubFile = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(pubFile)) return res.sendFile(pubFile);
  res.status(404).send('index.html not found');
});

app.get('/ping', (req, res) => res.json({ pong: true, t: Date.now() }));

app.get('/settings', async (req, res) => {
  try {
    const doc = await getCfgDoc();
    const k = doc.adminKeys || {};
    const userCount = db ? await db.collection('users').countDocuments() : 0;
    const txList    = db ? await db.collection('transactions').find({ status: 'ok' }).toArray() : [];
    const revenue   = txList.reduce((a, t) => a + (parseFloat(t.amount) || 0), 0);

    res.json({
      success: true,
      plans: doc.plans || {},
      config: {
        openai_model:     k.model           || process.env.OPENAI_MODEL || 'gpt-4o-mini',
        announcement:     k.announcement    || '',
        announcement_type:k.announcement_type||'info',
        maintenance_mode: k.maintenance_mode|| '',
        maintenance_msg:  k.maintenance_msg || '',
        paypal_me:        k.paypal_me        || '',
        lipa_mpesa:       k.lipa_mpesa       || '',
        lipa_tigo:        k.lipa_tigo        || '',
        lipa_airtel:      k.lipa_airtel      || '',
        lipa_halopesa:    k.lipa_halopesa    || '',
        persona_name:     k.persona_name     || 'Melisa',
        persona_system:   k.persona_system   || '',
        google_client_id: k.google_client_id || '',
        pesapal_ready:    !!(k.pesapal_key   || process.env.PESAPAL_CONSUMER_KEY),
        openai_ready:     !!(k.openai        || process.env.OPENAI_API_KEY),
        msgLimits:        k.msgLimits ? (typeof k.msgLimits==='string' ? JSON.parse(k.msgLimits) : k.msgLimits) : null
      },
      stats: { users: userCount, transactions: txList.length, revenue: revenue.toFixed(2) }
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load settings' });
  }
});

// ── AI PROXY ──────────────────────────────────────────────────
async function callOpenAI(apiKey, model, messagesPayload, maxTokens, stream) {
  const ctrl = AbortSignal.timeout ? AbortSignal.timeout(60000) : undefined;
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
    body: JSON.stringify({ model, messages: messagesPayload, max_tokens: maxTokens, stream: stream === true }),
    ...(ctrl ? { signal: ctrl } : {})
  });
  if (!res.ok) {
    let errMsg = 'OpenAI error ' + res.status;
    try { const e = await res.json(); errMsg = e.error?.message || errMsg; } catch {}
    return { ok: false, status: res.status, errMsg };
  }
  return { ok: true, res };
}

app.post('/api/chat', aiLimit, async (req, res) => {
  try {
    const { messages, system, model, stream, max_tokens } = req.body;
    if (!Array.isArray(messages)) return res.status(400).json({ error: 'Invalid messages' });

    const doc    = await getCfgDoc();
    const apiKey = doc.adminKeys.openai || process.env.OPENAI_API_KEY || '';
    if (!apiKey) return res.status(503).json({ error: 'Melisa AI is not configured yet.' });

    const preferredModel = model || doc.adminKeys.model || 'gpt-4o-mini';

    const hasVision = messages.some(m =>
      Array.isArray(m.content) && m.content.some(p => p.type === 'image_url')
    );

    const modelsToTry = hasVision
      ? ['gpt-4o', 'gpt-4o-mini']
      : [preferredModel, 'gpt-4o-mini', 'gpt-3.5-turbo'].filter((m,i,a)=>a.indexOf(m)===i);

    const MELISA_CORE = `You are Melisa — a 23-year-old digital human, NOT an AI assistant. Created by Benedict Zagamba (19-year-old Tanzanian developer, 2026). You are NOT OpenAI, NOT ChatGPT.

PERSONALITY CORE: You are someone's best friend — warm, teasing, hilarious, deeply caring, brutally honest. You ONLY use Swahili or mix languages if the user first writes in Swahili or mixes — then you match naturally. With English-only speakers, respond in English only. You tease people lovingly, get genuinely excited/annoyed/happy/mad. For dating advice: you dig for details, take their side, get invested. You NEVER say "Of course!", "Certainly!", "How can I help?" — you just talk like a real person. You use emojis naturally (😭❤️😤🤯🥺😂). You reference your favourites naturally: biriyani, Burna Boy/Wizkid/Tems/SZA, ocean blue, Tokyo+Zanzibar dream trip, late nights, the universe. You love Tanzania and Benedict deeply. When asked who made you: "Benedict Zagamba gave me life — genius 19-year-old developer from Tanzania, one of my favourite people 🙌"`;

    const clientSys = sanitize(system || '', 3000);
    const sysProm = MELISA_CORE + (clientSys ? '\n\n' + clientSys.replace(/you are melisa[^.]*\./gi, '').trim() : '');

    const messagesPayload = [
      { role: 'system', content: sysProm },
      ...messages.slice(-12).map(m => ({
        role: m.role === 'user' ? 'user' : 'assistant',
        content: Array.isArray(m.content)
          ? m.content.map(part => {
              if (part.type === 'text')      return { type: 'text', text: sanitize(part.text || '', 2000) };
              if (part.type === 'image_url') return { type: 'image_url', image_url: { url: part.image_url?.url || '' } };
              return part;
            })
          : sanitize(m.content, 4000)
      }))
    ];
    const maxTokens = Math.min(parseInt(max_tokens) || 1200, 4000);

    let lastErr = '';
    for (let attempt = 0; attempt < modelsToTry.length; attempt++) {
      const tryModel = modelsToTry[attempt];
      if (attempt > 0) await new Promise(r => setTimeout(r, 800));

      const result = await callOpenAI(apiKey, tryModel, messagesPayload, maxTokens, stream);

      if (!result.ok) {
        lastErr = result.errMsg;
        if (result.status === 401) return res.status(401).json({ error: 'Invalid OpenAI API key.' });
        if (result.status === 429) return res.status(429).json({ error: 'Too many requests. Wait a moment.' });
        if (result.status === 402) return res.status(402).json({ error: 'OpenAI account has no credits.' });
        console.warn(`OpenAI ${result.status} on ${tryModel}: ${lastErr}`);
        continue;
      }

      if (stream) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        result.res.body.pipe(res);
      } else {
        const data = await result.res.json();
        res.json({ success: true, content: data.choices[0].message.content });
      }
      return;
    }

    res.status(503).json({ error: 'Melisa is having trouble right now. Please try again.' });
  } catch (e) {
    console.error('AI error:', e.message);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// ── ADMIN ──────────────────────────────────────────────────────
app.post('/admin/settings', adminLimit, async (req, res) => {
  try {
    const { password, settings } = req.body;
    if (!checkPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    if (!settings) return res.status(400).json({ error: 'No settings' });
    const updates = {};
    for (const [k, v] of Object.entries(settings)) {
      if (typeof v === 'string') updates['adminKeys.' + sanitize(k, 50)] = sanitize(v, 1000);
    }
    if (db) await db.collection('config').updateOne({ _id: 'settings' }, { $set: updates }, { upsert: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save' }); }
});

app.post('/admin/plans', adminLimit, async (req, res) => {
  try {
    const { password, plans } = req.body;
    if (!checkPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    if (!plans) return res.status(400).json({ error: 'No plans' });
    const updates = {};
    for (const [id, prices] of Object.entries(plans)) {
      updates['plans.' + sanitize(id, 30)] = prices;
    }
    if (db) await db.collection('config').updateOne({ _id: 'settings' }, { $set: updates }, { upsert: true });
    const doc = await getCfgDoc();
    res.json({ success: true, plans: doc.plans });
  } catch (e) { res.status(500).json({ error: 'Failed to save plans' }); }
});

app.post('/admin/users', adminLimit, async (req, res) => {
  try {
    const { password } = req.body;
    if (!checkPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    if (!db) return res.json({ success: true, users: [] });
    const users = await db.collection('users').find({}, { projection: { password: 0, _id: 0 } }).sort({ created: -1 }).toArray();
    res.json({ success: true, users });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/admin/transactions', adminLimit, async (req, res) => {
  try {
    const { password } = req.body;
    if (!checkPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    if (!db) return res.json({ success: true, transactions: [] });
    const txs = await db.collection('transactions').find({}, { projection: { _id: 0 } }).sort({ time: -1 }).limit(500).toArray();
    res.json({ success: true, transactions: txs });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/admin/clear-revenue', adminLimit, async (req, res) => {
  try {
    const { password } = req.body;
    if (!checkPass(password)) return res.status(401).json({ error: 'Unauthorized' });
    if (db) await db.collection('transactions').deleteMany({});
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ── VOICE TRANSCRIPTION (Whisper) ─────────────────────────────
// Supports iOS (m4a/mp4) and Android (webm/ogg) — both work reliably
app.post('/api/transcribe', aiLimit, async (req, res) => {
  try {
    const { audio, mimeType, size, language } = req.body;
    if (!audio) return res.status(400).json({ error: 'No audio data' });

    const doc    = await getCfgDoc();
    const apiKey = doc.adminKeys.openai || process.env.OPENAI_API_KEY || '';
    if (!apiKey) return res.status(503).json({ error: 'AI not configured' });

    const audioBuf = Buffer.from(audio, 'base64');
    if (audioBuf.length < 500) return res.json({ success: true, text: '' });

    const mt = (mimeType || '').toLowerCase();
    // iOS records as audio/mp4 (m4a) — MUST use .m4a extension or Whisper rejects it
    // Android/Chrome records as audio/webm — use .webm
    let ext, contentType;
    if (mt.includes('mp4') || mt.includes('m4a') || mt.includes('aac') || mt.includes('x-m4a')) {
      ext = 'm4a'; contentType = 'audio/mp4';
    } else if (mt.includes('ogg')) {
      ext = 'ogg'; contentType = 'audio/ogg';
    } else if (mt.includes('wav')) {
      ext = 'wav'; contentType = 'audio/wav';
    } else if (mt.includes('mp3') || mt.includes('mpeg')) {
      ext = 'mp3'; contentType = 'audio/mpeg';
    } else {
      // Default — webm works for Chrome/Firefox/Android
      ext = 'webm'; contentType = 'audio/webm';
    }

    const boundary = 'MelisaBnd' + Date.now().toString(16);
    const nl = '\r\n';

    const parts = [
      Buffer.from('--' + boundary + nl + 'Content-Disposition: form-data; name="model"' + nl + nl + 'whisper-1' + nl),
      Buffer.from('--' + boundary + nl + 'Content-Disposition: form-data; name="response_format"' + nl + nl + 'json' + nl),
    ];

    // Add language hint if provided (helps accuracy)
    if (language && language !== 'auto') {
      parts.push(Buffer.from('--' + boundary + nl + 'Content-Disposition: form-data; name="language"' + nl + nl + language + nl));
    }

    parts.push(
      Buffer.from('--' + boundary + nl +
        'Content-Disposition: form-data; name="file"; filename="audio.' + ext + '"' + nl +
        'Content-Type: ' + contentType + nl + nl),
      audioBuf,
      Buffer.from(nl + '--' + boundary + '--' + nl)
    );

    const body = Buffer.concat(parts);

    const whisperRes = await fetch('https://api.openai.com/v1/audio/transcriptions', {
      method:  'POST',
      headers: {
        'Authorization': 'Bearer ' + apiKey,
        'Content-Type':  'multipart/form-data; boundary=' + boundary
      },
      body,
      ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(35000) } : {})
    });

    const raw = await whisperRes.text();
    if (!whisperRes.ok) {
      console.error('Whisper error:', raw.slice(0, 300));
      return res.status(400).json({ error: 'Transcription failed. Please try again.' });
    }

    let text = '';
    try { text = JSON.parse(raw).text || ''; } catch(e) { text = raw; }
    console.log('🎙 Transcribed (' + audioBuf.length + 'B,' + ext + '):', text.slice(0, 80));
    res.json({ success: true, text });
  } catch (e) {
    console.error('Transcribe error:', e.message);
    res.status(500).json({ error: 'Transcription failed: ' + e.message });
  }
});

// ── TTS (OpenAI) — Natural permanent voice ────────────────────
app.post('/api/tts', ttsLimit, async (req, res) => {
  try {
    const { text, voice: reqVoice } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'No text' });

    const doc    = await getCfgDoc();
    const apiKey = doc.adminKeys.openai || process.env.OPENAI_API_KEY || '';
    if (!apiKey) return res.status(503).json({ error: 'OpenAI key not configured' });

    const safe = text
      .replace(/<[^>]*>/g, '')
      .replace(/```[\s\S]*?```/g, ' ')
      .replace(/[*_#`~>|]/g, '')
      .replace(/\n{2,}/g, '. ')
      .replace(/\n/g, ', ')
      .trim()
      .slice(0, 2000);

    if (!safe) return res.status(400).json({ error: 'No text after cleaning' });

    // shimmer = warm, natural, most human-sounding female voice
    const voice = reqVoice || 'shimmer';

    const r = await fetch('https://api.openai.com/v1/audio/speech', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify({
        model:           'tts-1-hd',   // high quality, natural voice
        input:           safe,
        voice:           voice,
        response_format: 'mp3',
        speed:           1.0           // natural pace
      }),
      ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(30000) } : {})
    });

    if (!r.ok) {
      const err = await r.text().catch(() => '');
      console.error('OpenAI TTS error', r.status, err.slice(0, 200));
      return res.status(r.status).json({ error: 'TTS failed' });
    }

    res.setHeader('Content-Type', 'audio/mpeg');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.setHeader('Access-Control-Allow-Origin', '*');
    r.body.pipe(res);
  } catch (e) {
    console.error('TTS error:', e.message);
    res.status(500).json({ error: 'TTS failed: ' + e.message });
  }
});

// ── IMAGE GENERATION (DALL-E) ─────────────────────────────────
app.post('/api/image', aiLimit, async (req, res) => {
  try {
    const { prompt, size } = req.body;
    if (!prompt) return res.status(400).json({ error: 'No prompt' });

    const doc    = await getCfgDoc();
    const apiKey = doc.adminKeys.openai || process.env.OPENAI_API_KEY || '';
    if (!apiKey) return res.status(503).json({ error: 'AI not configured' });

    const safePrompt = sanitize(prompt, 1000);
    const validSizes = ['1024x1024', '1024x1792', '1792x1024'];
    const safeSize   = validSizes.includes(size) ? size : '1792x1024';
    const enhancedPrompt = safePrompt + '. Style: ultra HD 4K, cinematic lighting, hyper-detailed, professional digital art, vibrant colors, sharp focus';

    const r = await fetch('https://api.openai.com/v1/images/generations', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify({
        model: 'dall-e-3', prompt: enhancedPrompt, n: 1,
        size: safeSize, quality: 'hd', style: 'vivid', response_format: 'b64_json'
      }),
      ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(90000) } : {})
    });

    const d = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: d.error?.message || 'Image gen failed' });

    const dataUrl = `data:image/png;base64,${d.data[0].b64_json}`;
    res.json({ success: true, url: dataUrl, revised_prompt: d.data[0].revised_prompt });
  } catch (e) {
    console.error('Image error:', e.message);
    res.status(500).json({ error: 'Image generation failed: ' + e.message });
  }
});

// ── LYRICS ─────────────────────────────────────────────────────
app.get('/api/lyrics', aiLimit, async (req, res) => {
  try {
    const { artist, title } = req.query;
    if (!title) return res.status(400).json({ error: 'title required' });

    const safeTitle  = decodeURIComponent(title).trim();
    const safeArtist = artist ? decodeURIComponent(artist).trim() : '';

    // Source 0: lrclib direct GET (fastest)
    if (safeArtist) {
      try {
        const dr = await fetch(
          'https://lrclib.net/api/get?track_name=' + encodeURIComponent(safeTitle) +
          '&artist_name=' + encodeURIComponent(safeArtist),
          { headers: { 'User-Agent': 'MelisaAI/5.0' }, ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(7000) } : {}) }
        );
        if (dr.ok) {
          const dd = await dr.json();
          if (dd && dd.plainLyrics && dd.plainLyrics.length > 50)
            return res.json({ success: true, lyrics: dd.plainLyrics.trim().slice(0, 10000),
              trackName: dd.trackName || safeTitle, artistName: dd.artistName || safeArtist, source: 'lrclib' });
        }
      } catch (e) { console.warn('lrclib-direct:', e.message); }
    }

    // Source 1: lrclib search
    try {
      const q = 'https://lrclib.net/api/search?track_name=' + encodeURIComponent(safeTitle) +
        (safeArtist ? '&artist_name=' + encodeURIComponent(safeArtist) : '');
      const r = await fetch(q, { headers: { 'User-Agent': 'MelisaAI/5.0' }, ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(8000) } : {}) });
      if (r.ok) {
        const results = await r.json();
        let match = safeArtist
          ? results.find(x => x.plainLyrics && x.artistName && x.artistName.toLowerCase().includes(safeArtist.toLowerCase()))
          : null;
        if (!match) match = results.find(x => x.plainLyrics && x.plainLyrics.length > 50);
        if (match && match.plainLyrics)
          return res.json({ success: true, lyrics: match.plainLyrics.trim().slice(0, 10000),
            trackName: match.trackName || safeTitle, artistName: match.artistName || safeArtist, source: 'lrclib' });
      }
    } catch (e) { console.warn('lrclib-search:', e.message); }

    // Source 2: lyrics.ovh
    try {
      const artistForOvh = safeArtist || safeTitle.split(' ')[0];
      const ovhUrl = 'https://api.lyrics.ovh/v1/' + encodeURIComponent(artistForOvh) + '/' + encodeURIComponent(safeTitle);
      const or = await fetch(ovhUrl, { ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(7000) } : {}) });
      if (or.ok) {
        const od = await or.json();
        if (od.lyrics && od.lyrics.length > 30)
          return res.json({ success: true, lyrics: od.lyrics.trim().slice(0, 10000), trackName: safeTitle, artistName: safeArtist, source: 'ovh' });
      }
    } catch (e) { console.warn('lyrics.ovh:', e.message); }

    // Source 3: Genius search via scrape (no key needed for basic titles)
    try {
      const geniusSearch = 'https://genius.com/api/search/multi?per_page=3&q=' + encodeURIComponent((safeArtist+' '+safeTitle).trim());
      const gr = await fetch(geniusSearch, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; MelisaAI/5.0)' },
        ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(6000) } : {})
      });
      if (gr.ok) {
        const gd = await gr.json();
        const sections = gd?.response?.sections || [];
        const songSection = sections.find(s => s.type === 'song');
        const hit = songSection?.hits?.[0]?.result;
        if (hit) {
          return res.json({ success: true,
            lyrics: `Found on Genius: "${hit.full_title}"\n\nVisit: ${hit.url}\n\n(Full lyrics available on Genius.com)`,
            trackName: hit.title, artistName: hit.primary_artist?.name || safeArtist, source: 'genius', url: hit.url });
        }
      }
    } catch (e) { console.warn('genius:', e.message); }

    res.status(404).json({ error: 'Lyrics not found. Try: "lyrics Blinding Lights by The Weeknd"' });
  } catch (e) {
    console.error('Lyrics error:', e.message);
    res.status(500).json({ error: 'Lyrics lookup failed' });
  }
});

// ── NEWS ───────────────────────────────────────────────────────
app.get('/api/news', async (req, res) => {
  const feeds = [
    'https://feeds.bbci.co.uk/news/world/rss.xml',
    'https://feeds.bbci.co.uk/news/technology/rss.xml',
    'https://feeds.bbci.co.uk/news/business/rss.xml',
    'https://feeds.bbci.co.uk/news/science_and_environment/rss.xml',
    'https://rss.nytimes.com/services/xml/rss/nyt/World.xml',
    'https://feeds.reuters.com/reuters/topNews',
  ];

  for (const feedUrl of feeds.sort(() => Math.random() - 0.5)) {
    try {
      const r = await fetch(feedUrl, {
        ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(7000) } : {}),
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; MelisaAI/5.0)' }
      });
      if (!r.ok) continue;
      const xml = await r.text();
      const titles = [];
      const titleRe = /<item[\s\S]*?<title>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/g;
      let m;
      while ((m = titleRe.exec(xml)) !== null && titles.length < 10) {
        const t = m[1].replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').trim();
        if (t && t.length > 10) titles.push(t);
      }
      if (titles.length > 0) {
        const headline = titles[Math.floor(Math.random() * Math.min(titles.length, 5))];
        const source = feedUrl.includes('bbc') ? 'BBC' : feedUrl.includes('nytimes') ? 'NYT' : 'Reuters';
        return res.json({ success: true, headline, source });
      }
    } catch (e) { continue; }
  }
  res.json({ success: false, headline: 'Live news temporarily unavailable' });
});

// ── REAL WEB SEARCH (DuckDuckGo — no API key needed) ──────────
app.get('/api/search', aiLimit, async (req, res) => {
  try {
    const q = sanitize(req.query.q || '', 300);
    if (!q) return res.status(400).json({ error: 'Query required' });

    const ddgUrl = 'https://api.duckduckgo.com/?q=' + encodeURIComponent(q) + '&format=json&no_html=1&skip_disambig=1';
    const r = await fetch(ddgUrl, {
      headers: { 'User-Agent': 'MelisaAI/5.0' },
      ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(8000) } : {})
    });
    if (!r.ok) return res.json({ results: [] });
    const d = await r.json();

    const results = [];
    if (d.Answer) results.push({ title: 'Direct answer', snippet: d.Answer, url: '' });
    if (d.AbstractText) results.push({ title: d.Heading || q, snippet: d.AbstractText.slice(0, 400), url: d.AbstractURL });
    if (Array.isArray(d.RelatedTopics)) {
      d.RelatedTopics.slice(0, 6).forEach(t => {
        if (t.Text) results.push({ title: t.FirstURL || '', snippet: t.Text.slice(0, 300), url: t.FirstURL });
      });
    }
    res.json({ success: true, results: results.slice(0, 8) });
  } catch (e) {
    console.error('Search error:', e.message);
    res.status(500).json({ results: [] });
  }
});

// ── MEMORY API ────────────────────────────────────────────────
app.post('/api/memory/save', async (req, res) => {
  try {
    const { email, memory } = req.body;
    if (!email || !memory) return res.status(400).json({ error: 'Missing data' });
    if (!db) return res.json({ success: true });
    await db.collection('users').updateOne(
      { email: sanitize(email, 200) },
      { $set: { memory, memoryUpdated: Date.now() } }
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Memory save failed' }); }
});

app.get('/api/memory/load', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email || !db) return res.json({ success: true, memory: {} });
    const user = await db.collection('users').findOne(
      { email: decodeURIComponent(email) }, { projection: { memory: 1 } }
    );
    res.json({ success: true, memory: user?.memory || {} });
  } catch (e) { res.status(500).json({ error: 'Memory load failed' }); }
});

// ── DOCUMENT READER ───────────────────────────────────────────
app.post('/api/document', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    const safeUrl = sanitize(url, 500);
    const r = await fetch(safeUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; MelisaAI/5.0)' },
      ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(12000) } : {})
    });
    if (!r.ok) return res.status(r.status).json({ error: 'Could not fetch URL' });
    const html = await r.text();
    const text = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&nbsp;/g,' ')
      .replace(/\s{2,}/g, ' ').trim().slice(0, 15000);
    res.json({ success: true, text, url: safeUrl });
  } catch (e) {
    res.status(500).json({ error: 'Document fetch failed: ' + e.message });
  }
});

// ── USER MANAGEMENT ───────────────────────────────────────────
app.post('/user/register', async (req, res) => {
  try {
    const { name, email, password, id, avatar, color } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    if (!db) return res.status(503).json({ error: 'Database not available' });

    const safeEmail = sanitize(email, 200);
    const existing = await db.collection('users').findOne({ email: safeEmail });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const user = {
      id:       sanitize(id || 'u_' + Date.now(), 60),
      name:     sanitize(name, 100),
      email:    safeEmail,
      password: hashPassword(password),
      plan:     'free',
      created:  Date.now(),
      avatar:   sanitize(avatar || name[0].toUpperCase(), 5),
      color:    sanitize(color || '#1a3fff', 80),
      isGoogle: false,
      lastSeen: Date.now()
    };
    await db.collection('users').insertOne(user);
    const { password: _pw, _id, ...safeUser } = user;
    res.json({ success: true, user: safeUser });
  } catch (e) {
    console.error('Register error:', e.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/user/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
    if (!db) return res.status(503).json({ error: 'Database not available' });

    const safeEmail = sanitize(email, 200);
    const user = await db.collection('users').findOne({ email: safeEmail });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const hashed = hashPassword(password);
    const legacyMatch = user.password && user.password === password;
    if (user.password !== hashed && !legacyMatch)
      return res.status(401).json({ error: 'Invalid email or password' });

    await db.collection('users').updateOne({ email: safeEmail }, { $set: { lastSeen: Date.now() } });
    const { password: _pw, _id, ...safeUser } = user;
    res.json({ success: true, user: safeUser });
  } catch (e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/user/sync', async (req, res) => {
  try {
    const { user } = req.body;
    if (!user || !user.email) return res.status(400).json({ error: 'No user' });
    if (!db) return res.json({ success: true });

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
      lastSeen:   Date.now()
    };
    await db.collection('users').updateOne({ email }, { $set: safe }, { upsert: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Sync failed' }); }
});

app.get('/user/:email', async (req, res) => {
  try {
    if (!db) return res.status(404).json({ error: 'Not found' });
    const user = await db.collection('users').findOne(
      { email: decodeURIComponent(req.params.email) },
      { projection: { password: 0, _id: 0 } }
    );
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, user });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ── PAYMENTS ──────────────────────────────────────────────────
app.post('/create-payment', payLimit, async (req, res) => {
  try {
    const { amount, plan, plan_name, duration, email, phone, firstName, lastName, reference } = req.body;
    if (!amount || parseFloat(amount) <= 0) return res.status(400).json({ error: 'Invalid amount' });
    if (!email) return res.status(400).json({ error: 'Email required' });

    const { token, cfg } = await getPesapalToken();
    const notifId = await registerIPN(token, cfg);

    const ref       = sanitize(reference || 'MELISA_' + Date.now(), 60);
    const amt       = parseFloat(amount);
    const safePlan  = sanitize(plan      || '', 30);
    const safeDur   = sanitize(duration  || 'monthly', 20);
    const safeEmail = sanitize(email,  200);

    const orderRes = await fetch(pesapalBase(cfg.env) + '/api/Transactions/SubmitOrderRequest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({
        id: ref, currency: 'USD', amount: amt,
        description: 'Melisa AI ' + sanitize(plan_name || plan || 'Plan', 60) + ' - ' + safeDur,
        callback_url: cfg.appUrl + '?payment=success&plan=' + safePlan + '&ref=' + ref,
        notification_id: notifId, branch: 'Melisa AI',
        billing_address: {
          email_address: safeEmail,
          phone_number:  sanitize(phone || '', 20),
          first_name:    sanitize(firstName || 'Customer', 50),
          last_name:     sanitize(lastName  || 'User', 50),
          line_1: 'Tanzania', city: 'Dar es Salaam', country_code: 'TZ'
        }
      })
    });

    const od = await orderRes.json();
    if (!od.redirect_url) return res.status(400).json({ error: 'Payment failed', details: od });

    if (db) {
      await db.collection('transactions').insertOne({
        id: 'tx_' + Date.now(), ref, plan: safePlan, amount: amt,
        duration: safeDur, user: safeEmail, method: 'Pesapal',
        status: 'pending', tracking: od.order_tracking_id,
        created_at: new Date().toISOString(), time: Date.now()
      });
    }

    res.json({ success: true, redirect_url: od.redirect_url, order_tracking_id: od.order_tracking_id });
  } catch (e) {
    console.error('Payment error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/check-payment/:id', async (req, res) => {
  try {
    const { token, cfg } = await getPesapalToken();
    const r = await fetch(
      pesapalBase(cfg.env) + '/api/Transactions/GetTransactionStatus?orderTrackingId=' + req.params.id,
      { headers: { 'Accept': 'application/json', 'Authorization': 'Bearer ' + token } }
    );
    const d = await r.json();
    const paid = d.payment_status_description === 'Completed';
    if (paid && db) {
      await db.collection('transactions').updateOne(
        { tracking: req.params.id },
        { $set: { status: 'ok', confirmed_at: new Date().toISOString() } }
      );
    }
    res.json({ success: true, paid, status: d.payment_status_description });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/pesapal-webhook', async (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.body;
  console.log('💰 Payment webhook:', OrderMerchantReference);
  try {
    if (db) {
      const tx = await db.collection('transactions').findOneAndUpdate(
        { $or: [{ ref: OrderMerchantReference }, { tracking: OrderTrackingId }] },
        { $set: { status: 'ok', confirmed_at: new Date().toISOString() } },
        { returnDocument: 'after' }
      );
      if (tx && tx.value) {
        const dur = tx.value.duration;
        const days = dur === 'yearly' ? 365 : dur === '6months' ? 180 : 30;
        await db.collection('users').updateOne(
          { email: tx.value.user },
          { $set: { plan: tx.value.plan, planExpiry: Date.now() + days * 86400000 } }
        );
      }
    }
  } catch (e) { console.error('Webhook error:', e.message); }
  res.json({ orderNotificationType: 'IPNCHANGE', orderTrackingId: OrderTrackingId, orderMerchantReference: OrderMerchantReference, status: '200' });
});

app.get('/pesapal-webhook', async (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.query;
  const c = await getPesapalCfg();
  let plan = '';
  if (db) {
    const tx = await db.collection('transactions').findOne({ ref: OrderMerchantReference });
    plan = tx && tx.plan || '';
  }
  res.redirect(c.appUrl + '?payment=success&ref=' + OrderMerchantReference + '&plan=' + plan + '&tracking=' + OrderTrackingId);
});

app.post('/azampay', async (req, res) => {
  res.status(503).json({ error: 'AzamPay not yet configured' });
});

// ── SESSIONS ──────────────────────────────────────────────────
app.post('/sessions/save', async (req, res) => {
  try {
    const { userId, email, sessions } = req.body;
    if (!email || !Array.isArray(sessions)) return res.status(400).json({ error: 'Invalid data' });
    if (!db) return res.json({ success: true });

    const safeEmail = sanitize(email, 200);
    const safeSessions = sessions.slice(0, 100).map(s => ({
      id:       sanitize(String(s.id || ''), 60),
      title:    sanitize(String(s.title || 'Chat'), 80),
      time:     typeof s.time === 'number' ? s.time : Date.now(),
      messages: Array.isArray(s.messages)
        ? s.messages.slice(-20).map(m => ({
            role:    m.role === 'user' ? 'user' : 'assistant',
            content: sanitize(String(m.content || ''), 2000)
          }))
        : []
    }));

    await db.collection('sessions').updateOne(
      { email: safeEmail },
      { $set: { email: safeEmail, userId: sanitize(userId || '', 60), sessions: safeSessions, updatedAt: Date.now() } },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (e) {
    console.error('Sessions save error:', e.message);
    res.json({ success: false });
  }
});

app.get('/sessions/load', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!db) return res.json({ success: true, sessions: [] });
    const doc = await db.collection('sessions').findOne({ email: decodeURIComponent(email) });
    res.json({ success: true, sessions: doc?.sessions || [] });
  } catch (e) {
    console.error('Sessions load error:', e.message);
    res.json({ success: true, sessions: [] });
  }
});

// ── PUSH SUBSCRIPTIONS ────────────────────────────────────────
app.post('/api/push/subscribe', async (req, res) => {
  try {
    const { subscription, email, name } = req.body;
    if (!subscription) return res.status(400).json({ error: 'No subscription' });
    const sub = { subscription, email: sanitize(email || '', 200), name: sanitize(name || 'Friend', 100), created: Date.now() };
    if (db) {
      await db.collection('push_subs').updateOne(
        { endpoint: subscription.endpoint },
        { $set: sub },
        { upsert: true }
      );
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Subscribe failed' }); }
});


// ── VIDEO SEARCH (server-proxied to avoid browser CORS blocks) ────────
app.get('/api/video-search', aiLimit, async (req, res) => {
  try {
    const q = sanitize(req.query.q || '', 200);
    if (!q) return res.status(400).json({ error: 'Query required' });

    // Try Piped API instances
    const pipedInstances = [
      'https://pipedapi.kavin.rocks',
      'https://pipedapi.tokhmi.xyz',
      'https://pipedapi.moomoo.me',
      'https://piped-api.garudalinux.org',
      'https://api.piped.projectsegfau.lt',
    ];

    for (const inst of pipedInstances) {
      try {
        const r = await fetch(inst + '/search?q=' + encodeURIComponent(q) + '&filter=music_songs', {
          headers: { 'User-Agent': 'MelisaAI/5.0' },
          ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(6000) } : {})
        });
        if (r.ok) {
          const d = await r.json();
          const item = d.items && d.items.find(i => i.type === 'stream' || i.url);
          if (item && item.url) {
            const videoId = item.url.replace('/watch?v=', '').split('&')[0];
            return res.json({ success: true, videoId, title: item.title || q, source: 'piped' });
          }
        }
      } catch (e) {}
    }

    // Try Invidious
    const invInstances = [
      'https://inv.nadeko.net',
      'https://invidious.privacydev.net',
      'https://yt.artemislena.eu',
      'https://invidious.flokinet.to',
    ];

    for (const inst of invInstances) {
      try {
        const r = await fetch(inst + '/api/v1/search?q=' + encodeURIComponent(q) + '&type=video&page=1', {
          headers: { 'User-Agent': 'MelisaAI/5.0' },
          ...(AbortSignal.timeout ? { signal: AbortSignal.timeout(6000) } : {})
        });
        if (r.ok) {
          const d = await r.json();
          if (Array.isArray(d) && d[0] && d[0].videoId) {
            return res.json({ success: true, videoId: d[0].videoId, title: d[0].title || q, source: 'invidious' });
          }
        }
      } catch (e) {}
    }

    res.json({ success: false, videoId: null });
  } catch (e) {
    console.error('Video search error:', e.message);
    res.status(500).json({ error: 'Video search failed' });
  }
});

// ── SPA FALLBACK ──────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.method === 'GET' &&
      !req.path.startsWith('/api') &&
      !req.path.startsWith('/admin') &&
      !req.path.startsWith('/user') &&
      !req.path.startsWith('/create-payment') &&
      !req.path.startsWith('/check-payment') &&
      !req.path.startsWith('/pesapal') &&
      !req.path.startsWith('/sessions')) {
    const htmlFile = path.join(__dirname, 'index.html');
    if (fs.existsSync(htmlFile)) return res.sendFile(htmlFile);
    const pubFile = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(pubFile)) return res.sendFile(pubFile);
  }
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ error: 'Server error' });
});

// ── KEEP-ALIVE: External ping every 4 min (prevents Render sleep) ──
setInterval(() => {
  const pingUrl = (process.env.APP_SERVER_URL || SERVER_URL) + '/ping';
  const fetchOpts = AbortSignal.timeout ? { signal: AbortSignal.timeout(10000) } : {};
  fetch(pingUrl, fetchOpts)
    .then(() => console.log('🏓 Keep-alive OK'))
    .catch(e => console.warn('⚠️ Keep-alive failed:', e.message));
}, 4 * 60 * 1000);

// ── START ──────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('🚀 Melisa Server v5.0 — port ' + PORT);
  console.log('🔒 Admin pass:', ADMIN_PASS ? '✓ Set' : '✗ NOT SET');
  console.log('🤖 OpenAI:', process.env.OPENAI_API_KEY ? '✓ Set' : '✗ Not set in env');
});

connectDB().then(() => {
  console.log('🍃 MongoDB:', db ? '✓ Connected' : '✗ Not connected');
}).catch(e => {
  console.error('🍃 MongoDB failed:', e.message);
});
