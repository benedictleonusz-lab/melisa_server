// ═══════════════════════════════════════════════════════
// MELISA AI — Payment Backend Server
// Handles Pesapal payments — receives real money for Benedict
// Host this on Glitch.com for free
// ═══════════════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());

// ── CONFIG — Set these in Glitch .env ─────────────────
const PESAPAL_KEY    = process.env.PESAPAL_CONSUMER_KEY    || '';
const PESAPAL_SECRET = process.env.PESAPAL_CONSUMER_SECRET || '';
const PESAPAL_ENV    = process.env.PESAPAL_ENV             || 'live';
const APP_URL        = process.env.APP_URL                 || 'https://melisa-official-website.netlify.app';

const PESAPAL_BASE = PESAPAL_ENV === 'live'
  ? 'https://pay.pesapal.com/v3'
  : 'https://cybqa.pesapal.com/pesapalv3';

// ── HELPER: Get Pesapal auth token ────────────────────
async function getPesapalToken() {
  const res = await fetch(`${PESAPAL_BASE}/api/Auth/RequestToken`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ consumer_key: PESAPAL_KEY, consumer_secret: PESAPAL_SECRET })
  });
  const data = await res.json();
  if (!data.token) throw new Error('Pesapal auth failed: ' + JSON.stringify(data));
  return data.token;
}

// ── HELPER: Register IPN notification URL ─────────────
async function registerIPN(token) {
  const res = await fetch(`${PESAPAL_BASE}/api/URLSetup/RegisterIPN`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      url: `${APP_URL.replace('netlify.app', 'glitch.me')}/pesapal-webhook`,
      ipn_notification_type: 'POST'
    })
  });
  const data = await res.json();
  return data.notification_id || '';
}

// ── ROUTE: Health check ───────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'Melisa AI Payment Server is running ✓',
    pesapal: PESAPAL_KEY ? '✓ Configured' : '✗ Not configured',
    environment: PESAPAL_ENV
  });
});

// ── ROUTE: Create Pesapal payment order ───────────────
app.post('/create-payment', async (req, res) => {
  try {
    const { amount, plan, plan_name, duration, email, phone, firstName, lastName, reference } = req.body;

    if (!PESAPAL_KEY || !PESAPAL_SECRET) {
      return res.status(400).json({
        error: 'Payment not configured yet. Admin needs to add Pesapal keys in Glitch .env file.'
      });
    }

    if (!amount || parseFloat(amount) <= 0) {
      return res.status(400).json({ error: 'Invalid payment amount' });
    }

    const token = await getPesapalToken();
    const notificationId = await registerIPN(token);
    const ref = reference || 'MELISA_' + Date.now();

    const orderRes = await fetch(`${PESAPAL_BASE}/api/Transactions/SubmitOrderRequest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        id: ref,
        currency: 'USD',
        amount: parseFloat(amount),
        description: `Melisa AI ${plan_name || plan || 'Plan'} - ${duration || 'Monthly'}`,
        callback_url: `${APP_URL}?payment=success&plan=${plan}&ref=${ref}`,
        notification_id: notificationId,
        branch: 'Melisa AI',
        billing_address: {
          email_address: email || 'customer@melisaai.com',
          phone_number: phone || '',
          first_name: firstName || 'Customer',
          last_name: lastName || 'User',
          line_1: 'Tanzania',
          city: 'Dar es Salaam',
          country_code: 'TZ'
        }
      })
    });

    const orderData = await orderRes.json();

    if (!orderData.redirect_url) {
      console.error('Pesapal order error:', orderData);
      return res.status(400).json({
        error: 'Could not create payment. Please try again.',
        details: orderData
      });
    }

    console.log(`✓ Payment order created: ${ref} | Amount: $${amount} | Plan: ${plan}`);

    res.json({
      success: true,
      redirect_url: orderData.redirect_url,
      order_tracking_id: orderData.order_tracking_id,
      merchant_reference: ref
    });

  } catch (err) {
    console.error('Payment error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── ROUTE: Check payment status ───────────────────────
app.get('/check-payment/:trackingId', async (req, res) => {
  try {
    const token = await getPesapalToken();
    const statusRes = await fetch(
      `${PESAPAL_BASE}/api/Transactions/GetTransactionStatus?orderTrackingId=${req.params.trackingId}`,
      {
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      }
    );
    const data = await statusRes.json();
    res.json({
      success: true,
      paid: data.payment_status_description === 'Completed',
      status: data.payment_status_description,
      amount: data.amount,
      method: data.payment_method,
      currency: data.currency
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ROUTE: Pesapal webhook (payment confirmed) ────────
app.post('/pesapal-webhook', async (req, res) => {
  try {
    const { OrderTrackingId, OrderMerchantReference } = req.body;
    console.log(`💰 Payment confirmed! Tracking: ${OrderTrackingId} | Ref: ${OrderMerchantReference}`);
    // Acknowledge receipt
    res.json({ orderNotificationType: 'IPNCHANGE', orderTrackingId: OrderTrackingId, orderMerchantReference: OrderMerchantReference, status: '200' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ROUTE: Webhook redirect from Pesapal ─────────────
app.get('/pesapal-webhook', async (req, res) => {
  const { OrderTrackingId, OrderMerchantReference } = req.query;
  console.log(`💰 Payment redirect! Tracking: ${OrderTrackingId}`);
  res.redirect(`${APP_URL}?payment=success&ref=${OrderMerchantReference}&tracking=${OrderTrackingId}`);
});

// ── START SERVER ──────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Melisa Payment Server running on port ${PORT}`);
  console.log(`🔑 Pesapal: ${PESAPAL_KEY ? 'Configured ✓' : 'Not configured ✗'}`);
  console.log(`🌍 App URL: ${APP_URL}`);
});
