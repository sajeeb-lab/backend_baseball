const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const axios    = require('axios');
const mongoose = require('mongoose');
const FormData = require('form-data');
const crypto   = require('crypto');
const nodemailer = require('nodemailer');
const Stripe   = require('stripe');

// ── STRIPE INIT ───────────────────────────────────────────────
const stripe = process.env.STRIPE_SECRET_KEY
  ? Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

// ── EMAIL TRANSPORTER ─────────────────────────────────────────
function createTransporter() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

async function sendOTPEmail(toEmail, otp, purpose) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️  EMAIL_USER / EMAIL_PASS not set — skipping email send. OTP:', otp);
    return;
  }
  const subject = purpose === 'reset'
    ? 'Ambassadors Baseball – Password Reset Code'
    : 'Ambassadors Baseball – Verify Your Identity';
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;border:1px solid #dce3ec;border-radius:8px">
      <div style="background:#0a1628;padding:16px 20px;border-radius:6px 6px 0 0;margin:-24px -24px 24px">
        <h2 style="color:#fff;margin:0;font-size:1.1rem;letter-spacing:.05em;text-transform:uppercase">Ambassadors Baseball</h2>
      </div>
      <p style="color:#1a1a2e;font-size:.95rem;margin-bottom:8px">
        ${purpose === 'reset'
          ? 'You requested a password reset. Use the code below to set a new password:'
          : 'Use the code below to verify your identity and change your password:'}
      </p>
      <div style="text-align:center;margin:24px 0">
        <span style="display:inline-block;background:#f4f6f9;border:2px dashed #c8102e;border-radius:8px;padding:14px 32px;font-size:2rem;font-weight:700;letter-spacing:.35em;color:#0a1628;font-family:monospace">${otp}</span>
      </div>
      <p style="color:#5a6a7a;font-size:.82rem;margin:0">This code expires in <strong>10 minutes</strong>. If you didn't request this, you can safely ignore this email.</p>
    </div>`;
  await createTransporter().sendMail({
    from: `"Ambassadors Baseball" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject,
    html,
  });
}

function generateOTP() {
  return String(Math.floor(100000 + crypto.randomInt(900000))).padStart(6, '0');
}

// ── ENV VALIDATION ────────────────────────────────────────────────
const REQUIRED_ENV = ['MONGODB_URI', 'JWT_SECRET', 'GHL_API_KEY', 'GHL_LOCATION_ID'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
  console.error('❌  Missing required environment variables:', missingEnv.join(', '));
  process.exit(1);
}

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.options('*', cors());

// ── STRIPE WEBHOOK — must receive raw body, register BEFORE express.json() ──
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) return res.status(500).json({ message: 'Stripe not configured' });

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('⚠️  Stripe webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { playerPaymentId, paymentType } = session.metadata || {};
    const amountPaid = session.amount_total / 100; // cents → dollars

    if (playerPaymentId) {
      try {
        const existing = await PlayerPayment.findById(playerPaymentId);
        if (existing) {
          const today = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
          const update = {};

          if (paymentType === 'deposit') {
            const newAmountPaid = (existing.amount_paid || 0) + amountPaid;
            const newBalance    = Math.max(0, (existing.total_fee || 0) - newAmountPaid);
            update.deposit_paid      = true;
            update.deposit_paid_date = today;
            update.amount_paid       = newAmountPaid;
            update.balance           = newBalance;
            update.status            = newBalance <= 0 ? 'Paid' : 'Partial';
          } else if (paymentType === 'full' || paymentType === 'remainder') {
            update.amount_paid = existing.total_fee;
            update.balance     = 0;
            update.status      = 'Paid';
            if (paymentType === 'deposit') {
              update.deposit_paid      = true;
              update.deposit_paid_date = today;
            }
          } else if (paymentType === 'installment') {
            const newAmountPaid = (existing.amount_paid || 0) + amountPaid;
            const newBalance    = Math.max(0, (existing.total_fee || 0) - newAmountPaid);
            update.amount_paid = newAmountPaid;
            update.balance     = newBalance;
            update.status      = newBalance <= 0 ? 'Paid' : 'Partial';
          }

          await PlayerPayment.findByIdAndUpdate(playerPaymentId, update);
          console.log(`✅  Stripe payment recorded — playerPaymentId=${playerPaymentId} type=${paymentType}`);
        }
      } catch (dbErr) {
        console.error('❌  Failed to update PlayerPayment after Stripe webhook:', dbErr.message);
      }
    }
  }

  res.json({ received: true });
});

app.use(express.json({ limit: '10mb' }));

// ── MONGODB CONNECTION ────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => { console.error('❌  MongoDB connection error:', err); process.exit(1); });

// ════════════════════════════════════════════════════════════════
//  MONGOOSE SCHEMAS & MODELS
// ════════════════════════════════════════════════════════════════

const coachSchema = new mongoose.Schema({
  first_name:   { type: String, required: true },
  last_name:    { type: String, required: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone:        { type: String, default: '' },
  team_name:    { type: String, default: '' },
  state:        { type: String, default: '' },
  location:     { type: String, default: '' },
  age_group:    { type: String, default: '' },
  password:     { type: String, required: true },
  email_public: { type: String, default: '' },
  phone_public: { type: String, default: '' },
  bio:          { type: String, default: '' },
  image_url:    { type: String, default: '' },
  team_details: { type: String, default: '' },
  assistant1:   { type: mongoose.Schema.Types.Mixed, default: {} },
  assistant2:   { type: mongoose.Schema.Types.Mixed, default: {} },
  active:             { type: Boolean, default: true },
  otp_code:           { type: String,  default: null },
  otp_expiry:         { type: Date,    default: null },
  otp_purpose:        { type: String,  default: null },
  reset_token:        { type: String,  default: null },
  reset_token_expiry: { type: Date,    default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
coachSchema.index({ active: 1 });

const tryoutSchema = new mongoose.Schema({
  coach_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  date:     { type: String, default: '' },
  time:     { type: String, default: '' },
  location: { type: String, default: '' },
  fee:      { type: String, default: 'Free' },
  city:     { type: String, default: '' },
  state:    { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
tryoutSchema.index({ coach_id: 1 });

const tryoutRegistrationSchema = new mongoose.Schema({
  coach_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  completed_by: { type: String, default: '' },
  name:         { type: String, default: '' },
  address:      { type: String, default: '' },
  city:         { type: String, default: '' },
  state:        { type: String, default: '' },
  zip:          { type: String, default: '' },
  cell:         { type: String, default: '' },
  email:        { type: String, default: '' },
  player_name:  { type: String, default: '' },
  age:          { type: String, default: '' },
  dob:          { type: String, default: '' },
  hw:           { type: String, default: '' },
  pos1:         { type: String, default: '' },
  pos2:         { type: String, default: '' },
  tryout_date:  { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
tryoutRegistrationSchema.index({ coach_id: 1 });

const playerSchema = new mongoose.Schema({
  coach_id:         { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  name:             { type: String, required: true },
  jersey:           { type: String, default: '' },
  jersey_2:         { type: String, default: '' },
  grad_year:        { type: String, default: '' },
  position:         { type: String, default: '' },
  pos2:             { type: String, default: '' },
  hw:               { type: String, default: '' },
  city:             { type: String, default: '' },
  state:            { type: String, default: '' },
  address:          { type: String, default: '' },
  zip:              { type: String, default: '' },
  email:            { type: String, default: '' },
  cell:             { type: String, default: '' },
  dob:              { type: String, default: '' },
  bats:             { type: String, default: '' },
  throws:           { type: String, default: '' },
  high_school:      { type: String, default: '' },
  mother_first:     { type: String, default: '' },
  mother_last:      { type: String, default: '' },
  mother_cell:      { type: String, default: '' },
  mother_email:     { type: String, default: '' },
  father_first:     { type: String, default: '' },
  father_last:      { type: String, default: '' },
  father_cell:      { type: String, default: '' },
  father_email:     { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
playerSchema.index({ coach_id: 1 });

const scheduleSchema = new mongoose.Schema({
  coach_id:   { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  date:       { type: String, default: '' },
  start_date: { type: String, default: '' },
  end_date:   { type: String, default: '' },
  event:      { type: String, default: '' },
  city:       { type: String, default: '' },
  state:      { type: String, default: '' },
  result:     { type: String, default: 'Upcoming' },
  date_sort:  { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
scheduleSchema.index({ coach_id: 1, date_sort: 1 });

const teamFinancialsSchema = new mongoose.Schema({
  coach_id:           { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true, unique: true },
  player_fee:         { type: Number, default: 0 },
  payment_deadline:   { type: String, default: '' },
  full_pay_only:      { type: Boolean, default: true },
  deposit_enabled:    { type: Boolean, default: false },
  deposit_amount:     { type: Number, default: 250 },
  monthly_payments:   { type: Boolean, default: false },
  installment_months: { type: Number, default: 3 },

  ghl_product_full:        { type: String, default: '' },
  ghl_product_deposit:     { type: String, default: '' },
  ghl_product_remainder:   { type: String, default: '' },
  ghl_product_installment: { type: String, default: '' },

  ghl_price_full:        { type: String, default: '' },
  ghl_price_deposit:     { type: String, default: '' },
  ghl_price_remainder:   { type: String, default: '' },
  ghl_price_installment: { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });

const playerPaymentSchema = new mongoose.Schema({
  coach_id:          { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  player_id:         { type: mongoose.Schema.Types.ObjectId, ref: 'Player', default: null },
  player_name:       { type: String, default: '' },
  total_fee:         { type: Number, default: 0 },
  deposit_amount:    { type: Number, default: 0 },
  deposit_paid:      { type: Boolean, default: false },
  deposit_paid_date: { type: String, default: '' },
  payment_plan:      { type: mongoose.Schema.Types.Mixed, default: [] },
  amount_paid:       { type: Number, default: 0 },
  balance:           { type: Number, default: 0 },
  status:            { type: String, default: 'Pending' },
  registered_date:   { type: String, default: '' },
  payment_deadline:  { type: String, default: '' },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
playerPaymentSchema.index({ coach_id: 1 });

const budgetSchema = new mongoose.Schema({
  coach_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  date:         { type: String, default: '' },
  players:      { type: Number, default: 0 },
  seasons:      { type: Number, default: 0 },
  num_events:   { type: Number, default: 0 },
  event_cost:   { type: Number, default: 0 },
  tournaments:  { type: Number, default: 0 },
  head_pay:     { type: Number, default: 0 },
  asst_pay:     { type: Number, default: 0 },
  rentals:      { type: Number, default: 0 },
  gas:          { type: Number, default: 0 },
  hotel_nights: { type: Number, default: 0 },
  hotel_avg:    { type: Number, default: 0 },
  hotels:       { type: Number, default: 0 },
  num_uniforms: { type: Number, default: 0 },
  uniform_cost: { type: Number, default: 0 },
  uniforms:     { type: Number, default: 0 },
  equipment:    { type: Number, default: 0 },
  insurance:    { type: Number, default: 0 },
  ambassadors:  { type: Number, default: 0 },
  others:       { type: mongoose.Schema.Types.Mixed, default: [] },
  total:        { type: Number, default: 0 },
  per_player:   { type: Number, default: 0 },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
budgetSchema.index({ coach_id: 1 });

// ── MODELS ────────────────────────────────────────────────────────
const Coach              = mongoose.model('Coach',              coachSchema);
const Tryout             = mongoose.model('Tryout',             tryoutSchema);
const TryoutRegistration = mongoose.model('TryoutRegistration', tryoutRegistrationSchema);
const Player             = mongoose.model('Player',             playerSchema);
const Schedule           = mongoose.model('Schedule',           scheduleSchema);
const TeamFinancials     = mongoose.model('TeamFinancials',     teamFinancialsSchema);
const PlayerPayment      = mongoose.model('PlayerPayment',      playerPaymentSchema);
const Budget             = mongoose.model('Budget',             budgetSchema);

// ════════════════════════════════════════════════════════════════
//  GHL HELPERS
// ════════════════════════════════════════════════════════════════

const GHL_HEADERS = () => ({
  'Authorization': `Bearer ${process.env.GHL_API_KEY}`,
  'Content-Type':  'application/json',
  'Accept':        'application/json',
  'Version':       '2021-07-28',
});

// ── GHL MEDIA UPLOAD ──────────────────────────────────────────
async function uploadImageToGHL(base64, fileName, mimeType) {
  const buffer = Buffer.from(base64, 'base64');
  const form   = new FormData();
  form.append('file', buffer, { filename: fileName, contentType: mimeType || 'image/jpeg' });
  form.append('fileAltText', fileName);

  const response = await axios.post(
    'https://services.leadconnectorhq.com/medias/upload-file',
    form,
    {
      headers: {
        'Authorization': `Bearer ${process.env.GHL_API_KEY}`,
        'Version':       '2021-07-28',
        ...form.getHeaders(),
      },
      params: { locationId: process.env.GHL_LOCATION_ID },
    }
  );

  const url = response.data?.url;
  if (!url) throw new Error('GHL upload succeeded but no URL returned: ' + JSON.stringify(response.data));
  return url;
}

// ── GHL PRODUCT + PRICE CREATION ─────────────────────────────
/**
 * Creates a GHL product then a price under it.
 *
 * GHL docs confirm:
 *   - amount is in DOLLARS  (e.g. 250, not 25000)
 *   - type uses underscore  "one_time" | "recurring"
 *   - locationId required on BOTH product AND price payloads
 *
 * @param {string}      name       - Display name for product and price
 * @param {number}      amount     - Dollar amount e.g. 250
 * @param {object|null} recurring  - null = one_time; { interval: 'month', intervalCount: 1 } = recurring
 * @returns {{ productId: string, priceId: string }}
 */
async function createGHLProductWithPrice(name, amount, recurring = null) {
  // ── Step 1: Create product ────────────────────────────────
  let productId;
  try {
    const productRes = await axios.post(
      'https://services.leadconnectorhq.com/products/',
      {
        locationId:  process.env.GHL_LOCATION_ID,
        name,
        productType: 'SERVICE',
      },
      { headers: GHL_HEADERS() }
    );

    productId = productRes.data?._id
      || productRes.data?.product?._id
      || productRes.data?.id;

    if (!productId) {
      throw new Error('No product ID in response: ' + JSON.stringify(productRes.data));
    }
    console.log(`📦  GHL product created: "${name}" → ${productId}`);
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    throw new Error(`GHL create product failed for "${name}": ${detail}`);
  }

  // ── Step 2: Create price ──────────────────────────────────
  const pricePayload = {
    locationId: process.env.GHL_LOCATION_ID,
    name,
    amount:     Number(amount),
    currency:   'USD',
    type:       recurring ? 'recurring' : 'one_time',
  };

  if (recurring) {
    pricePayload.recurring = {
      interval:      recurring.interval,
      intervalCount: recurring.intervalCount,
    };
  }

  let priceId;
  try {
    const priceRes = await axios.post(
      `https://services.leadconnectorhq.com/products/${productId}/price`,
      pricePayload,
      { headers: GHL_HEADERS() }
    );

    priceId = priceRes.data?._id
      || priceRes.data?.price?._id
      || priceRes.data?.id;

    if (!priceId) {
      throw new Error('No price ID in response: ' + JSON.stringify(priceRes.data));
    }
    console.log(`💰  GHL price created: "${name}" $${amount} → priceId=${priceId}`);
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error(`❌  GHL price creation failed (orphan productId=${productId}):`, detail);
    throw new Error(`GHL create price failed for "${name}": ${detail}`);
  }

  return { productId, priceId };
}

/**
 * Deletes a GHL product by ID. Best-effort — never throws.
 */
async function deleteGHLProduct(productId) {
  if (!productId) return;
  try {
    await axios.delete(
      `https://services.leadconnectorhq.com/products/${productId}`,
      { headers: GHL_HEADERS() }
    );
    console.log(`🗑️  GHL product deleted: ${productId}`);
  } catch (err) {
    console.warn(`⚠️  Could not delete GHL product ${productId}:`, err.response?.data || err.message);
  }
}

// ── GHL CONTACT UPSERT (tryout registration) ──────────────────
async function upsertGHLContact({ completedBy, name, address, city, state, zip, cell, email,
                                   playerName, age, dob, hw, pos1, pos2, tryoutDate }) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) {
    return { success: false, error: 'GHL env vars not set' };
  }
  const nameParts = (name || '').trim().split(' ');
  let formattedDob = '';
  if (dob) { const d = new Date(dob); if (!isNaN(d)) formattedDob = d.toISOString().split('T')[0]; }
  let formattedTryoutDate = '';
  if (tryoutDate) { const d = new Date(tryoutDate); if (!isNaN(d)) formattedTryoutDate = d.toISOString(); }

  try {
    const response = await axios.post(
      'https://services.leadconnectorhq.com/contacts/upsert',
      {
        locationId:  process.env.GHL_LOCATION_ID,
        firstName:   nameParts[0] || '',
        lastName:    nameParts.slice(1).join(' ') || '',
        email:       email   || '',
        phone:       cell    || '',
        address1:    address || '',
        city:        city    || '',
        state:       state   || '',
        postalCode:  zip     || '',
        dateOfBirth: formattedDob,
        tags: ['Baseball Tryout'],
        customFields: [
          { key: 'player_name',    value: playerName          || '' },
          { key: 'position_1',     value: pos1                || '' },
          { key: 'position_2',     value: pos2                || '' },
          { key: 'age',            value: age                 || '' },
          { key: 'completed_by',   value: completedBy         || '' },
          { key: 'tryout_date',    value: formattedTryoutDate      },
          { key: 'height__weight', value: hw                  || '' },
        ],
      },
      { headers: GHL_HEADERS() }
    );
    return { success: true, contactId: response.data?.contact?.id || '' };
  } catch (err) {
    const errMsg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error('GHL contact upsert error:', errMsg);
    return { success: false, error: errMsg };
  }
}

// ── GHL PLAYER UPSERT ─────────────────────────────────────────
async function upsertGHLPlayer({
  name, email, cell, dob, bats, throws, hw,
  jersey, jersey2, gradYear, position, pos2,
  address, city, state, zip, highSchool,
  motherFirst, motherLast, motherCell, motherEmail,
  fatherFirst, fatherLast, fatherCell, fatherEmail,
  teamName,
}) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) return;
  try {
    await axios.post(
      'https://services.leadconnectorhq.com/contacts/upsert',
      {
        locationId: process.env.GHL_LOCATION_ID,
        // Contact main identity = Father
        firstName:  fatherFirst  || '',
        lastName:   fatherLast   || '',
        email:      fatherEmail  || '',
        phone:      fatherCell   || '',
        // Address = Player's address
        address1:   address      || '',
        city:       city         || '',
        state:      state        || '',
        postalCode: zip          || '',
        tags: ['Player'],
        customFields: [
          // Player info
          { key: 'players_name',      value: name         || '' },
          { key: 'player_dob',        value: dob          || '' },
          { key: 'player_email',      value: email        || '' },
          { key: 'player_cell',       value: cell         || '' },
          { key: 'bats',              value: bats         || '' },
          { key: 'throws',            value: throws       || '' },
          { key: 'jersey_number_1',   value: jersey       || '' },
          { key: 'jersey_number_2',   value: jersey2      || '' },
          { key: 'htwt',              value: hw           || '' },
          { key: 'grad_year',         value: gradYear     || '' },
          { key: 'high_school',       value: highSchool   || '' },
          { key: 'player_address',    value: address      || '' },
          { key: 'position1',         value: position     || '' },
          { key: 'position2',         value: pos2         || '' },
          { key: 'team_name',         value: teamName     || '' },
          // Mother info
          { key: 'mother_first_name', value: motherFirst  || '' },
          { key: 'mother_last_name',  value: motherLast   || '' },
          { key: 'mother_cell',       value: motherCell   || '' },
          { key: 'mother_email',      value: motherEmail  || '' },
        ],
      },
      { headers: GHL_HEADERS() }
    );
    console.log(`✅  GHL player upserted: ${fatherFirst} ${fatherLast} (${fatherEmail})`);
  } catch (err) {
    console.error('GHL player upsert error:', err.response?.data ? JSON.stringify(err.response.data) : err.message);
  }
}

// ── GHL COACH UPSERT ──────────────────────────────────────────
async function upsertGHLCoach({ firstName, lastName, email, phone, teamName, state, city, ageGroup, bio }) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) return;
  try {
    await axios.post(
      'https://services.leadconnectorhq.com/contacts/upsert',
      {
        locationId: process.env.GHL_LOCATION_ID,
        firstName:  firstName || '',
        lastName:   lastName  || '',
        email:      email     || '',
        phone:      phone     || '',
        city:       city      || '',
        state:      state     || '',
        tags:       ['Head Coach Name'],
        customFields: [
          { key: 'team_name',  value: teamName  || '' },
          { key: 'age_group',  value: ageGroup  || '' },
          { key: 'bio',        value: bio       || '' },
        ],
      },
      { headers: GHL_HEADERS() }
    );
  } catch (err) {
    console.error('GHL coach upsert error:', err.response?.data ? JSON.stringify(err.response.data) : err.message);
  }
}

// ════════════════════════════════════════════════════════════════
//  AUTH HELPERS
// ════════════════════════════════════════════════════════════════

const signToken = id => jwt.sign({ coachId: id }, process.env.JWT_SECRET, { expiresIn: '7d' });

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token provided' });
  try {
    const { coachId } = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    req.coachId = coachId;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
  try {
    const payload = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    if (payload.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// ════════════════════════════════════════════════════════════════
//  NORMALIZERS
// ════════════════════════════════════════════════════════════════

function normalizeCoach(c) {
  return {
    _id:         c._id,
    firstName:   c.first_name   || '',
    lastName:    c.last_name    || '',
    emailPublic: c.email_public || '',
    phonePublic: c.phone_public || '',
    bio:         c.bio          || '',
    image:       c.image_url    || '',
    teamName:    c.team_name    || '',
    state:       c.state        || '',
    location:    c.location     || '',
    ageGroup:    c.age_group    || '',
    teamDetails: c.team_details || '',
    assistant1:  c.assistant1   || {},
    assistant2:  c.assistant2   || {},
  };
}

function normalizeTryout(t) {
  return {
    _id:      t._id,
    date:     t.date     || '',
    time:     t.time     || '',
    location: t.location || '',
    fee:      t.fee      || 'Free',
    city:     t.city     || '',
    state:    t.state    || '',
  };
}

function normalizePlayer(p) {
  return {
    _id:          p._id,
    name:         p.name         || '',
    jersey:       p.jersey       || '',
    jersey2:      p.jersey_2     || '',
    gradYear:     p.grad_year    || '',
    position:     p.position     || '',
    pos2:         p.pos2         || '',
    hw:           p.hw           || '',
    city:         p.city         || '',
    state:        p.state        || '',
    address:      p.address      || '',
    zip:          p.zip          || '',
    email:        p.email        || '',
    cell:         p.cell         || '',
    dob:          p.dob          || '',
    bats:         p.bats         || '',
    throws:       p.throws       || '',
    highSchool:   p.high_school  || '',
    motherFirst:  p.mother_first || '',
    motherLast:   p.mother_last  || '',
    motherCell:   p.mother_cell  || '',
    motherEmail:  p.mother_email || '',
    fatherFirst:  p.father_first || '',
    fatherLast:   p.father_last  || '',
    fatherCell:   p.father_cell  || '',
    fatherEmail:  p.father_email || '',
  };
}

function normalizeGame(g) {
  return {
    _id:       g._id,
    startDate: g.start_date || '',
    endDate:   g.end_date   || '',
    event:     g.event      || '',
    city:      g.city       || '',
    state:     g.state      || '',
    result:    g.result     || 'Upcoming',
  };
}

// ════════════════════════════════════════════════════════════════
//  TEMP: GET GHL CUSTOM FIELDS
// ════════════════════════════════════════════════════════════════
app.get('/api/ghl-fields', async (req, res) => {
  try {
    const response = await axios.get(
      `https://services.leadconnectorhq.com/contacts/custom-fields?locationId=${process.env.GHL_LOCATION_ID}`,
      { headers: GHL_HEADERS() }
    );
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/coach/register
app.post('/api/coach/register', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, teamName, state, ageGroup, password } = req.body;
    if (!firstName || !lastName || !email || !phone || !teamName || !password)
      return res.status(400).json({ message: 'All fields are required' });
    if (password.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters' });

    const existing = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(409).json({ message: 'An account with this email already exists' });

    const hashed = await bcrypt.hash(password, 12);
    await Coach.create({
      first_name:   firstName,
      last_name:    lastName,
      email:        email.toLowerCase().trim(),
      phone,
      team_name:    teamName,
      state:        state ? state.toUpperCase() : '',
      age_group:    ageGroup || '',
      password:     hashed,
      email_public: email.toLowerCase().trim(),
      phone_public: phone,
    });

    await upsertGHLCoach({ firstName, lastName, email, phone, teamName });
    res.status(201).json({ message: 'Account created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// POST /api/coach/login
app.post('/api/coach/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required' });

    const coach = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (!coach) return res.status(401).json({ message: 'Invalid email or password' });
    if (!(await bcrypt.compare(password, coach.password)))
      return res.status(401).json({ message: 'Invalid email or password' });

    res.json({
      token: signToken(coach._id),
      coach: { _id: coach._id, firstName: coach.first_name, lastName: coach.last_name, teamName: coach.team_name }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/forgot-password
app.post('/api/coach/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const coach = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (!coach) return res.json({ message: 'If that email exists, a 6-digit code has been sent.' });

    const otp    = generateOTP();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    await Coach.findByIdAndUpdate(coach._id, {
      otp_code:    otp,
      otp_expiry:  expiry,
      otp_purpose: 'reset',
    });

    await sendOTPEmail(coach.email, otp, 'reset');

    res.json({
      message: 'If that email exists, a 6-digit code has been sent.',
      ...((!process.env.EMAIL_USER) && { devOtp: otp }),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/verify-otp-reset
app.post('/api/coach/verify-otp-reset', async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    if (!email || !otp || !password)
      return res.status(400).json({ message: 'Email, OTP, and new password are required' });
    if (password.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters' });

    const coach = await Coach.findOne({ email: email.toLowerCase().trim() });
    if (!coach || coach.otp_purpose !== 'reset' || coach.otp_code !== otp || new Date() > coach.otp_expiry)
      return res.status(400).json({ message: 'OTP is invalid or has expired' });

    const hashed = await bcrypt.hash(password, 12);
    await Coach.findByIdAndUpdate(coach._id, {
      password:    hashed,
      otp_code:    null,
      otp_expiry:  null,
      otp_purpose: null,
    });

    res.json({ message: 'Password updated successfully. You can now log in.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════════
//  COACH DASHBOARD ROUTES (protected)
// ════════════════════════════════════════════════════════════════

// GET /api/coach/me
app.get('/api/coach/me', requireAuth, async (req, res) => {
  try {
    const coach = await Coach.findById(req.coachId).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ coach: normalizeCoach(coach) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/coach/update-profile
app.put('/api/coach/update-profile', requireAuth, async (req, res) => {
  try {
    const map = {
      firstName:   'first_name',
      lastName:    'last_name',
      emailPublic: 'email_public',
      phonePublic: 'phone_public',
      bio:         'bio',
      imageUrl:    'image_url',
      teamName:    'team_name',
      state:       'state',
      location:    'location',
      ageGroup:    'age_group',
      teamDetails: 'team_details',
    };
    const update = {};
    Object.entries(map).forEach(([jsKey, dbKey]) => {
      if (req.body[jsKey] !== undefined) update[dbKey] = req.body[jsKey];
    });
    if (update.state) update.state = update.state.toUpperCase();

    const coach = await Coach.findByIdAndUpdate(req.coachId, update, { new: true }).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });

    await upsertGHLCoach({
      firstName: coach.first_name,
      lastName:  coach.last_name,
      email:     coach.email_public,
      phone:     coach.phone_public,
      teamName:  coach.team_name,
      state:     coach.state,
      city:      coach.location,
      ageGroup:  coach.age_group,
      bio:       coach.bio,
    });

    res.json({ message: 'Saved', coach: normalizeCoach(coach) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// PUT /api/coach/update-assistants
app.put('/api/coach/update-assistants', requireAuth, async (req, res) => {
  try {
    const update = {};
    if (req.body.assistant1 !== undefined) update.assistant1 = req.body.assistant1;
    if (req.body.assistant2 !== undefined) update.assistant2 = req.body.assistant2;

    const coach = await Coach.findByIdAndUpdate(req.coachId, update, { new: true }).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ message: 'Saved', coach: normalizeCoach(coach) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// POST /api/coach/upload-image
app.post('/api/coach/upload-image', requireAuth, async (req, res) => {
  try {
    const { base64, fileName, mimeType, saveToProfile, slot } = req.body;
    if (!base64 || !fileName) return res.status(400).json({ message: 'base64 and fileName required' });

    const imageUrl = await uploadImageToGHL(base64, fileName, mimeType);

    if (saveToProfile || slot === 'head') {
      await Coach.findByIdAndUpdate(req.coachId, { image_url: imageUrl });
    }

    if (slot === 'asst1' || slot === 'asst2') {
      const col   = slot === 'asst1' ? 'assistant1' : 'assistant2';
      const coach = await Coach.findById(req.coachId);
      if (coach) {
        const updated = { ...(coach[col] || {}), image: imageUrl };
        await Coach.findByIdAndUpdate(req.coachId, { [col]: updated });
      }
    }

    res.json({ message: 'Uploaded', imageUrl });
  } catch (err) {
    console.error('GHL upload error:', err.message);
    res.status(500).json({ message: err.message || 'Upload failed' });
  }
});

// DELETE /api/coach/delete-image
app.delete('/api/coach/delete-image', requireAuth, async (req, res) => {
  try {
    const { slot } = req.body;
    if (!slot) return res.status(400).json({ message: 'slot required' });

    if (slot === 'head') {
      await Coach.findByIdAndUpdate(req.coachId, { image_url: '' });
    } else {
      const col   = slot === 'asst1' ? 'assistant1' : 'assistant2';
      const coach = await Coach.findById(req.coachId);
      if (coach && coach[col]) {
        const updated = { ...coach[col], image: '' };
        await Coach.findByIdAndUpdate(req.coachId, { [col]: updated });
      }
    }
    res.json({ message: 'Image reference removed' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Delete failed' });
  }
});

// ── TRYOUT ROUTES ─────────────────────────────────────────────

app.get('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const tryouts = await Tryout.find({ coach_id: req.coachId }).sort({ created_at: 1 });
    res.json({ tryouts: tryouts.map(normalizeTryout) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const { date, time, location, fee, city, state } = req.body;
    if (!date || !time || !location || !fee)
      return res.status(400).json({ message: 'date, time, location and fee are all required' });
    const tryout = await Tryout.create({
      coach_id: req.coachId, date, time, location, fee,
      city: city || '', state: state || '',
    });
    res.status(201).json({ message: 'Tryout added', tryout: normalizeTryout(tryout) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.put('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    const { date, time, location, fee, city, state } = req.body;
    if (!date || !time || !location)
      return res.status(400).json({ message: 'date, time and location are required' });
    const tryout = await Tryout.findOneAndUpdate(
      { _id: req.params.tryoutId, coach_id: req.coachId },
      { date, time, location, fee: fee || 'Free', city: city || '', state: state || '' },
      { new: true }
    );
    if (!tryout) return res.status(404).json({ message: 'Tryout not found' });
    res.json({ message: 'Tryout updated', tryout: normalizeTryout(tryout) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.delete('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    await Tryout.findOneAndDelete({ _id: req.params.tryoutId, coach_id: req.coachId });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.get('/api/coach/tryout-registrations', requireAuth, async (req, res) => {
  try {
    const data = await TryoutRegistration.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ registrations: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── SCHEDULE ROUTES ───────────────────────────────────────────

app.get('/api/coach/schedule', requireAuth, async (req, res) => {
  try {
    const data = await Schedule.find({ coach_id: req.coachId }).sort({ date_sort: 1 });
    res.json({ schedule: data.map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/coach/schedule', requireAuth, async (req, res) => {
  try {
    const { startDate, endDate, event, city, state } = req.body;
    if (!startDate || !endDate || !event)
      return res.status(400).json({ message: 'Start date, end date, and event are required' });
    const game = await Schedule.create({
      coach_id:   req.coachId,
      date:       startDate,
      start_date: startDate,
      end_date:   endDate,
      event,
      city:       city  || '',
      state:      state || '',
      date_sort:  startDate,
    });
    res.status(201).json({ message: 'Game added', game: normalizeGame(game) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    const { startDate, endDate, event, city, state } = req.body;
    if (!startDate || !endDate || !event)
      return res.status(400).json({ message: 'Start date, end date, and event are required' });
    const game = await Schedule.findOneAndUpdate(
      { _id: req.params.gameId, coach_id: req.coachId },
      { date: startDate, start_date: startDate, end_date: endDate, event, city: city || '', state: state || '', date_sort: startDate },
      { new: true }
    );
    if (!game) return res.status(404).json({ message: 'Game not found' });
    res.json({ message: 'Game updated', game: normalizeGame(game) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    await Schedule.findOneAndDelete({ _id: req.params.gameId, coach_id: req.coachId });
    res.json({ message: 'Game deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── FINANCIALS ROUTES ─────────────────────────────────────────

app.get('/api/coach/financials', requireAuth, async (req, res) => {
  try {
    const data = await TeamFinancials.findOne({ coach_id: req.coachId });
    res.json({ financials: data || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/coach/financials
// Creates or updates financial settings and syncs GHL products/prices.
//
// Rules:
//   • Deposit OFF  → only Full Payment product in GHL
//   • Deposit ON   → only Deposit + Remaining Balance products in GHL (no Full Payment)
//   • Monthly payments can exist alongside either of the above
//   • Fee change   → delete all old GHL products and recreate fresh
//   • Toggle OFF   → delete that product, clear stored IDs
//   • GHL failure  → logs error but always saves to MongoDB
app.post('/api/coach/financials', requireAuth, async (req, res) => {
  try {
    const {
      playerFee,
      paymentDeadline,
      fullPayOnly,
      depositEnabled,
      depositAmount,
      monthlyPayments,
      installmentMonths,
    } = req.body;

    // ── Fetch coach team name for GHL product labels ──────────
    const coach = await Coach.findById(req.coachId).select('team_name');
    const teamLabel = coach?.team_name || 'Team';

    // ── Fetch existing record ─────────────────────────────────
    const existing = await TeamFinancials.findOne({ coach_id: req.coachId });

    // ── Dollar amounts ────────────────────────────────────────
    const fee         = Number(playerFee)         || 0;
    const deposit     = Number(depositAmount)     || 250;
    const months      = Number(installmentMonths) || 3;
    const remainder   = Math.max(0, fee - deposit);
    const installment = months > 0
      ? Math.round((fee / months) * 100) / 100
      : fee;

    // ── Did the player fee change since last save? ────────────
    const feeChanged = !!existing && existing.player_fee !== fee;

    // ── Build the MongoDB update object ──────────────────────
    const update = {
      coach_id:           req.coachId,
      player_fee:         fee,
      payment_deadline:   paymentDeadline || '',
      full_pay_only:      fullPayOnly !== false,
      deposit_enabled:    !!depositEnabled,
      deposit_amount:     deposit,
      monthly_payments:   !!monthlyPayments,
      installment_months: months,
    };

    // ── GHL product/price sync ────────────────────────────────
    try {
      // carry() returns the stored ID if fee is unchanged, '' if fee changed (forces recreation)
      const carry = (field) => feeChanged ? '' : (existing?.[field] || '');

      update.ghl_product_full        = carry('ghl_product_full');
      update.ghl_price_full          = carry('ghl_price_full');
      update.ghl_product_deposit     = carry('ghl_product_deposit');
      update.ghl_price_deposit       = carry('ghl_price_deposit');
      update.ghl_product_remainder   = carry('ghl_product_remainder');
      update.ghl_price_remainder     = carry('ghl_price_remainder');
      update.ghl_product_installment = carry('ghl_product_installment');
      update.ghl_price_installment   = carry('ghl_price_installment');

      // If fee changed, delete all old GHL products first
      if (feeChanged && existing) {
        console.log('💱  Fee changed — deleting old GHL products and recreating...');
        await Promise.all([
          deleteGHLProduct(existing.ghl_product_full),
          deleteGHLProduct(existing.ghl_product_deposit),
          deleteGHLProduct(existing.ghl_product_remainder),
          deleteGHLProduct(existing.ghl_product_installment),
        ]);
      }

      // ── Full pay product (ONLY when deposit is OFF) ───────
      if (!depositEnabled) {
        if (fee > 0 && !update.ghl_product_full) {
          const { productId, priceId } = await createGHLProductWithPrice(
            `${teamLabel} – Full Payment ($${fee})`,
            fee
          );
          update.ghl_product_full = productId;
          update.ghl_price_full   = priceId;
        }
      } else {
        // Deposit is ON — full pay product is not needed; delete if it exists
        if (existing?.ghl_product_full && !feeChanged) {
          await deleteGHLProduct(existing.ghl_product_full);
        }
        update.ghl_product_full = '';
        update.ghl_price_full   = '';
      }

      // ── Deposit product (ONLY when deposit is ON) ─────────
      if (depositEnabled && deposit > 0) {
        if (!update.ghl_product_deposit) {
          const { productId, priceId } = await createGHLProductWithPrice(
            `${teamLabel} – Deposit ($${deposit})`,
            deposit
          );
          update.ghl_product_deposit = productId;
          update.ghl_price_deposit   = priceId;
        }
      } else {
        // Deposit toggled OFF — delete if it existed and this isn't a fee-change wipe
        if (existing?.ghl_product_deposit && !feeChanged) {
          await deleteGHLProduct(existing.ghl_product_deposit);
        }
        update.ghl_product_deposit = '';
        update.ghl_price_deposit   = '';
      }

      // ── Remainder product (balance after deposit, ONLY when deposit is ON) ──
      if (depositEnabled && remainder > 0) {
        if (!update.ghl_product_remainder) {
          const { productId, priceId } = await createGHLProductWithPrice(
            `${teamLabel} – Remaining Balance ($${remainder})`,
            remainder
          );
          update.ghl_product_remainder = productId;
          update.ghl_price_remainder   = priceId;
        }
      } else {
        if (existing?.ghl_product_remainder && !feeChanged) {
          await deleteGHLProduct(existing.ghl_product_remainder);
        }
        update.ghl_product_remainder = '';
        update.ghl_price_remainder   = '';
      }

      // ── Monthly installment product ───────────────────────
      if (monthlyPayments && installment > 0) {
        if (!update.ghl_product_installment) {
          const { productId, priceId } = await createGHLProductWithPrice(
            `${teamLabel} – Monthly Installment ($${installment}/mo × ${months})`,
            installment,
            { interval: 'month', intervalCount: 1 }
          );
          update.ghl_product_installment = productId;
          update.ghl_price_installment   = priceId;
        }
      } else {
        if (existing?.ghl_product_installment && !feeChanged) {
          await deleteGHLProduct(existing.ghl_product_installment);
        }
        update.ghl_product_installment = '';
        update.ghl_price_installment   = '';
      }

    } catch (ghlErr) {
      // GHL errors are non-fatal — always fall through to the DB save
      console.error('⚠️  GHL product sync error:', ghlErr.response?.data || ghlErr.message);
    }

    // ── Persist to MongoDB ────────────────────────────────────
    const data = await TeamFinancials.findOneAndUpdate(
      { coach_id: req.coachId },
      update,
      { upsert: true, new: true }
    );

    res.json({ message: 'Saved', financials: data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

// ── STRIPE CHECKOUT ───────────────────────────────────────────
// POST /api/checkout
// Body: { coachId, paymentType, playerPaymentId, successUrl, cancelUrl }
// paymentType: 'full' | 'deposit' | 'remainder' | 'installment'
app.post('/api/checkout', async (req, res) => {
  if (!stripe) return res.status(500).json({ message: 'Stripe is not configured on the server' });

  try {
    const { coachId, paymentType, playerPaymentId, successUrl, cancelUrl } = req.body;
    if (!coachId || !paymentType || !playerPaymentId) {
      return res.status(400).json({ message: 'coachId, paymentType, and playerPaymentId are required' });
    }

    // ── Get team financials to build the product name ─────────
    const financials = await TeamFinancials.findOne({ coach_id: coachId });
    if (!financials) return res.status(404).json({ message: 'Team financials not found' });

    const coach = await Coach.findById(coachId).select('team_name');
    const teamLabel = coach?.team_name || 'Team';

    const fee         = financials.player_fee     || 0;
    const deposit     = financials.deposit_amount || 250;
    const months      = financials.installment_months || 3;
    const remainder   = Math.max(0, fee - deposit);
    const installment = months > 0 ? Math.round((fee / months) * 100) / 100 : fee;

    // ── Map paymentType → exact Stripe product name ───────────
    const productNameMap = {
      full:        `${teamLabel} – Full Payment ($${fee})`,
      deposit:     `${teamLabel} – Deposit ($${deposit})`,
      remainder:   `${teamLabel} – Remaining Balance ($${remainder})`,
      installment: `${teamLabel} – Monthly Installment ($${installment}/mo × ${months})`,
    };

    const productName = productNameMap[paymentType];
    if (!productName) return res.status(400).json({ message: `Unknown paymentType: ${paymentType}` });

    // ── Search Stripe for the product by exact name ───────────
    const productSearch = await stripe.products.search({
      query: `name:"${productName}"`,
      limit: 1,
    });

    if (!productSearch.data.length) {
      return res.status(404).json({ message: `Stripe product not found: "${productName}". It may still be syncing — please try again in a moment.` });
    }

    const stripeProduct = productSearch.data[0];

    // ── Get the active price for this product ─────────────────
    const prices = await stripe.prices.list({ product: stripeProduct.id, active: true, limit: 1 });
    if (!prices.data.length) {
      return res.status(404).json({ message: `No active price found for Stripe product: "${productName}"` });
    }

    const priceId = prices.data[0].id;

    // ── Create checkout session ───────────────────────────────
    const session = await stripe.checkout.sessions.create({
      mode: paymentType === 'installment' ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: successUrl || `${req.headers.origin || 'https://yoursite.com'}?payment=success`,
      cancel_url:  cancelUrl  || `${req.headers.origin || 'https://yoursite.com'}?payment=cancelled`,
      metadata: {
        playerPaymentId,
        paymentType,
        coachId,
      },
    });

    console.log(`🛒  Stripe checkout created — type=${paymentType} product="${productName}" session=${session.id}`);
    res.json({ url: session.url });

  } catch (err) {
    console.error('❌  Stripe checkout error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── PLAYER PAYMENTS ROUTES ────────────────────────────────────

app.get('/api/coach/player-payments', requireAuth, async (req, res) => {
  try {
    const data = await PlayerPayment.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ payments: data || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/coach/player-payments', async (req, res) => {
  try {
    const { coachId, playerId, playerName, totalFee, depositAmount,
            paymentPlan, balance, registeredDate, paymentDeadline } = req.body;
    if (!coachId) return res.status(400).json({ message: 'coachId is required' });
    const data = await PlayerPayment.create({
      coach_id:         coachId,
      player_id:        playerId        || null,
      player_name:      playerName      || '',
      total_fee:        totalFee        || 0,
      deposit_amount:   depositAmount   || 0,
      deposit_paid:     false,
      payment_plan:     paymentPlan     || [],
      amount_paid:      0,
      balance:          balance         || totalFee || 0,
      status:           'Pending',
      registered_date:  registeredDate  || '',
      payment_deadline: paymentDeadline || '',
    });
    res.status(201).json({ message: 'Payment record created', payment: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/coach/player-payments/:paymentId', async (req, res) => {
  try {
    const { depositPaid, depositPaidDate, paymentPlan, amountPaid, balance, status } = req.body;
    const update = {};
    if (depositPaid !== undefined)     update.deposit_paid      = depositPaid;
    if (depositPaidDate !== undefined) update.deposit_paid_date = depositPaidDate;
    if (paymentPlan !== undefined)     update.payment_plan      = paymentPlan;
    if (amountPaid !== undefined)      update.amount_paid       = amountPaid;
    if (balance !== undefined)         update.balance           = balance;
    if (status !== undefined)          update.status            = status;
    const data = await PlayerPayment.findByIdAndUpdate(req.params.paymentId, update, { new: true });
    if (!data) return res.status(404).json({ message: 'Payment not found' });
    res.json({ message: 'Updated', payment: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/coach/player-payments/:paymentId', requireAuth, async (req, res) => {
  try {
    await PlayerPayment.findOneAndDelete({ _id: req.params.paymentId, coach_id: req.coachId });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── BUDGET ROUTES ─────────────────────────────────────────────

app.get('/api/coach/budgets', requireAuth, async (req, res) => {
  try {
    const data = await Budget.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ budgets: data || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/coach/budgets', requireAuth, async (req, res) => {
  try {
    const {
      date, players, seasons, numEvents, eventCost, tournaments,
      headPay, asstPay, rentals, gas, hotelNights, hotelAvg, hotels,
      numUniforms, uniformCost, uniforms, equipment, insurance,
      ambassadors, others, total, perPlayer
    } = req.body;
    const data = await Budget.create({
      coach_id:     req.coachId,
      date,
      players:      players      || 0,
      seasons:      seasons      || 0,
      num_events:   numEvents    || 0,
      event_cost:   eventCost    || 0,
      tournaments:  tournaments  || 0,
      head_pay:     headPay      || 0,
      asst_pay:     asstPay      || 0,
      rentals:      rentals      || 0,
      gas:          gas          || 0,
      hotel_nights: hotelNights  || 0,
      hotel_avg:    hotelAvg     || 0,
      hotels:       hotels       || 0,
      num_uniforms: numUniforms  || 0,
      uniform_cost: uniformCost  || 0,
      uniforms:     uniforms     || 0,
      equipment:    equipment    || 0,
      insurance:    insurance    || 0,
      ambassadors:  ambassadors  || 0,
      others:       others       || [],
      total:        total        || 0,
      per_player:   perPlayer    || 0,
    });
    res.status(201).json({ message: 'Budget saved', budget: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/coach/budgets/:budgetId', requireAuth, async (req, res) => {
  try {
    const {
      players, seasons, numEvents, eventCost, tournaments,
      headPay, asstPay, rentals, gas, hotelNights, hotelAvg, hotels,
      numUniforms, uniformCost, uniforms, equipment, insurance,
      ambassadors, others, total, perPlayer
    } = req.body;
    const data = await Budget.findOneAndUpdate(
      { _id: req.params.budgetId, coach_id: req.coachId },
      {
        players:      players      || 0,
        seasons:      seasons      || 0,
        num_events:   numEvents    || 0,
        event_cost:   eventCost    || 0,
        tournaments:  tournaments  || 0,
        head_pay:     headPay      || 0,
        asst_pay:     asstPay      || 0,
        rentals:      rentals      || 0,
        gas:          gas          || 0,
        hotel_nights: hotelNights  || 0,
        hotel_avg:    hotelAvg     || 0,
        hotels:       hotels       || 0,
        num_uniforms: numUniforms  || 0,
        uniform_cost: uniformCost  || 0,
        uniforms:     uniforms     || 0,
        equipment:    equipment    || 0,
        insurance:    insurance    || 0,
        ambassadors:  ambassadors  || 450,
        others:       others       || [],
        total:        total        || 0,
        per_player:   perPlayer    || 0,
      },
      { new: true }
    );
    if (!data) return res.status(404).json({ message: 'Budget not found' });
    res.json({ message: 'Budget updated', budget: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/coach/budgets/:budgetId', requireAuth, async (req, res) => {
  try {
    await Budget.findOneAndDelete({ _id: req.params.budgetId, coach_id: req.coachId });
    res.json({ message: 'Budget deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════════════════════════════

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== (process.env.ADMIN_USERNAME || 'admin') ||
      password !== (process.env.ADMIN_PASSWORD || 'admin123'))
    return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.get('/api/admin/coaches', requireAdmin, async (req, res) => {
  try {
    const coaches = await Coach.find().select('-password').sort({ created_at: -1 });
    const regCounts = await TryoutRegistration.aggregate([
      { $group: { _id: '$coach_id', count: { $sum: 1 } } }
    ]);
    const countMap = {};
    regCounts.forEach(r => { countMap[r._id.toString()] = r.count; });
    res.json({ coaches: coaches.map(c => ({
      id:                c._id,
      firstName:         c.first_name,
      lastName:          c.last_name,
      email:             c.email,
      phone:             c.phone,
      teamName:          c.team_name,
      state:             c.state,
      location:          c.location,
      ageGroup:          c.age_group,
      image:             c.image_url || '',
      active:            c.active !== false,
      createdAt:         c.created_at,
      registrationCount: countMap[c._id.toString()] || 0,
    }))});
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/coaches/:id', requireAdmin, async (req, res) => {
  try {
    const c = await Coach.findById(req.params.id).select('-password');
    if (!c) return res.status(404).json({ message: 'Coach not found' });
    const [tryouts, regs, roster, schedule] = await Promise.all([
      Tryout.find({ coach_id: c._id }),
      TryoutRegistration.find({ coach_id: c._id }).sort({ created_at: -1 }),
      Player.find({ coach_id: c._id }),
      Schedule.find({ coach_id: c._id }).sort({ date_sort: 1 }),
    ]);
    res.json({
      coach: {
        id: c._id, firstName: c.first_name, lastName: c.last_name,
        email: c.email, phone: c.phone, teamName: c.team_name,
        state: c.state, location: c.location, ageGroup: c.age_group,
        image: c.image_url || '', bio: c.bio || '',
        emailPublic: c.email_public || '', phonePublic: c.phone_public || '',
        assistant1: c.assistant1 || {}, assistant2: c.assistant2 || {},
        active: c.active !== false, createdAt: c.created_at,
      },
      tryouts, registrations: regs, roster, schedule,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/coaches/:id/toggle-active', requireAdmin, async (req, res) => {
  try {
    const { active } = req.body;
    await Coach.findByIdAndUpdate(req.params.id, { active });
    res.json({ message: active ? 'Coach activated' : 'Coach deactivated', active });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/coaches/:id/edit', requireAdmin, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, teamName, state, location, ageGroup } = req.body;
    await Coach.findByIdAndUpdate(req.params.id, {
      first_name: firstName, last_name: lastName, email,
      phone, team_name: teamName, state, location, age_group: ageGroup,
    });
    res.json({ message: 'Coach updated' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/admin/coaches/:id/token — generate a coach JWT so admin can act as that coach
app.get('/api/admin/coaches/:id/token', requireAdmin, async (req, res) => {
  try {
    const coach = await Coach.findById(req.params.id).select('_id');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    const token = signToken(coach._id);
    res.json({ token, coachId: coach._id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ════════════════════════════════════════════════════════════════

app.get('/api/teams', async (req, res) => {
  try {
    const teams = await Coach.find({ active: { $ne: false } })
      .select('first_name last_name team_name state location age_group image_url');
    res.json({ teams: teams.map(t => ({
      _id:      t._id,
      teamName: t.team_name  || '',
      state:    t.state      || '',
      location: t.location   || '',
      ageGroup: t.age_group  || '',
      imageUrl: t.image_url  || '',
    }))});
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/teams/:id', async (req, res) => {
  try {
    const team = await Coach.findById(req.params.id)
      .select('first_name last_name email_public phone_public bio image_url team_name state location age_group team_details assistant1 assistant2');
    if (!team) return res.status(404).json({ message: 'Team not found' });
    res.json({ team: normalizeCoach(team) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/teams/:id/tryouts', async (req, res) => {
  try {
    const tryouts = await Tryout.find({ coach_id: req.params.id }).sort({ created_at: 1 });
    res.json({ tryouts: tryouts.map(normalizeTryout) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/teams/:id/roster', async (req, res) => {
  try {
    const players = await Player.find({ coach_id: req.params.id }).sort({ created_at: 1 });
    res.json({ players: players.map(normalizePlayer) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/teams/:id/roster', async (req, res) => {
  try {
    const {
      name, jersey, jersey2, gradYear, position, pos2, hw, city, state,
      address, zip, email, cell, dob, bats, throws, highSchool,
      motherFirst, motherLast, motherCell, motherEmail,
      fatherFirst, fatherLast, fatherCell, fatherEmail,
      teamName,
    } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });
    const player = await Player.create({
      coach_id:     req.params.id,
      name,
      jersey:       jersey      || '',
      jersey_2:     jersey2     || '',
      grad_year:    gradYear    || '',
      position:     position    || '',
      pos2:         pos2        || '',
      hw:           hw          || '',
      city:         city        || '',
      state:        state       || '',
      address:      address     || '',
      zip:          zip         || '',
      email:        email       || '',
      cell:         cell        || '',
      dob:          dob         || '',
      bats:         bats        || '',
      throws:       throws      || '',
      high_school:  highSchool  || '',
      mother_first: motherFirst || '',
      mother_last:  motherLast  || '',
      mother_cell:  motherCell  || '',
      mother_email: motherEmail || '',
      father_first: fatherFirst || '',
      father_last:  fatherLast  || '',
      father_cell:  fatherCell  || '',
      father_email: fatherEmail || '',
    });
    await upsertGHLPlayer({
      name, email, cell, dob, bats, throws, hw,
      jersey, jersey2, gradYear, position, pos2,
      address, city, state, zip, highSchool,
      motherFirst, motherLast, motherCell, motherEmail,
      fatherFirst, fatherLast, fatherCell, fatherEmail,
      teamName,
    });
    res.status(201).json({ message: 'Player registered', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.put('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    const {
      name, jersey, jersey2, gradYear, position, pos2, hw, city, state,
      address, zip, email, cell, dob, bats, throws, highSchool,
      motherFirst, motherLast, motherCell, motherEmail,
      fatherFirst, fatherLast, fatherCell, fatherEmail,
    } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });
    const player = await Player.findOneAndUpdate(
      { _id: req.params.playerId, coach_id: req.params.id },
      {
        name,
        jersey:       jersey      || '',
        jersey_2:     jersey2     || '',
        grad_year:    gradYear    || '',
        position:     position    || '',
        pos2:         pos2        || '',
        hw:           hw          || '',
        city:         city        || '',
        state:        state       || '',
        address:      address     || '',
        zip:          zip         || '',
        email:        email       || '',
        cell:         cell        || '',
        dob:          dob         || '',
        bats:         bats        || '',
        throws:       throws      || '',
        high_school:  highSchool  || '',
        mother_first: motherFirst || '',
        mother_last:  motherLast  || '',
        mother_cell:  motherCell  || '',
        mother_email: motherEmail || '',
        father_first: fatherFirst || '',
        father_last:  fatherLast  || '',
        father_cell:  fatherCell  || '',
        father_email: fatherEmail || '',
      },
      { new: true }
    );
    if (!player) return res.status(404).json({ message: 'Player not found' });
    res.json({ message: 'Player updated', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.delete('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    await Player.findOneAndDelete({ _id: req.params.playerId, coach_id: req.params.id });
    res.json({ message: 'Player deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

app.get('/api/teams/:id/schedule', async (req, res) => {
  try {
    const data = await Schedule.find({ coach_id: req.params.id }).sort({ date_sort: 1 });
    res.json({ schedule: data.map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/teams/:id/financials', async (req, res) => {
  try {
    const data = await TeamFinancials.findOne({ coach_id: req.params.id });
    res.json({ financials: data || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/teams/:id/tryout-registrations', async (req, res) => {
  try {
    const { completedBy, name, address, city, state, zip, cell, email,
            playerName, age, dob, hw, pos1, pos2, tryoutDate } = req.body;
    if (!name || !playerName) return res.status(400).json({ message: 'Name and player name are required' });

    const reg = await TryoutRegistration.create({
      coach_id:     req.params.id,
      completed_by: completedBy || '',
      name,
      address:      address     || '',
      city:         city        || '',
      state:        state       || '',
      zip:          zip         || '',
      cell:         cell        || '',
      email:        email       || '',
      player_name:  playerName,
      age:          age         || '',
      dob:          dob         || '',
      hw:           hw          || '',
      pos1:         pos1        || '',
      pos2:         pos2        || '',
      tryout_date:  tryoutDate  || '',
    });

    const ghlResult = await upsertGHLContact({
      completedBy, name, address, city, state, zip, cell, email,
      playerName, age, dob, hw, pos1, pos2, tryoutDate,
    });

    res.status(201).json({ message: 'Registration submitted', registration: reg, ghl: ghlResult });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Vercel serverless — no app.listen needed
module.exports = app;
