const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const axios    = require('axios');
const mongoose = require('mongoose');
const FormData = require('form-data');
const crypto   = require('crypto');

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
  reset_token:        { type: String, default: null },
  reset_token_expiry: { type: Date,   default: null },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
// Indexes
coachSchema.index({ email: 1 });
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
  coach_id:  { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true },
  name:      { type: String, required: true },
  jersey:    { type: String, default: '' },
  grad_year: { type: String, default: '' },
  position:  { type: String, default: '' },
  hw:        { type: String, default: '' },
  city:      { type: String, default: '' },
  state:     { type: String, default: '' },
  email:     { type: String, default: '' },
  cell:      { type: String, default: '' },
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
  coach_id:         { type: mongoose.Schema.Types.ObjectId, ref: 'Coach', required: true, unique: true },
  player_fee:       { type: Number, default: 0 },
  payment_deadline: { type: String, default: '' },
  full_pay_only:    { type: Boolean, default: true },
  deposit_enabled:  { type: Boolean, default: false },
  deposit_amount:   { type: Number, default: 250 },
  monthly_payments: { type: Boolean, default: false },
}, { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } });
teamFinancialsSchema.index({ coach_id: 1 });

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

// ── GHL MEDIA UPLOAD ──────────────────────────────────────────
async function uploadImageToGHL(base64, fileName, mimeType) {
  const buffer = Buffer.from(base64, 'base64');
  const form   = new FormData();
  form.append('file', buffer, { filename: fileName, contentType: mimeType || 'image/jpeg' });
  form.append('fileAltText', fileName);
  // Note: do NOT pass hosted=true — that requires a URL, not raw bytes

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
    const response = await axios.post('https://services.leadconnectorhq.com/contacts/upsert', {
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
    }, { headers: { 'Authorization': `Bearer ${process.env.GHL_API_KEY}`, 'Content-Type': 'application/json', 'Version': '2021-07-28' } });
    return { success: true, contactId: response.data?.contact?.id || '' };
  } catch (err) {
    const errMsg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error('GHL contact upsert error:', errMsg);
    return { success: false, error: errMsg };
  }
}

// ── GHL PLAYER UPSERT ─────────────────────────────────────────
async function upsertGHLPlayer({ name, email, cell, city, state, position, jersey, gradYear, hw }) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) return;
  const nameParts = (name || '').trim().split(' ');
  try {
    await axios.post('https://services.leadconnectorhq.com/contacts/upsert', {
      locationId: process.env.GHL_LOCATION_ID,
      firstName:  nameParts[0] || '',
      lastName:   nameParts.slice(1).join(' ') || '',
      email:  email || '',
      phone:  cell  || '',
      city:   city  || '',
      state:  state || '',
      tags:   ['Player'],
      customFields: [
        { key: 'players_name',  value: name     || '' },
        { key: 'position',      value: position || '' },
        { key: 'grad_year',     value: gradYear || '' },
        { key: 'jersey_number', value: jersey   || '' },
        { key: 'ht__wt',        value: hw       || '' },
      ],
    }, { headers: { 'Authorization': `Bearer ${process.env.GHL_API_KEY}`, 'Content-Type': 'application/json', 'Version': '2021-07-28' } });
  } catch (err) {
    console.error('GHL player upsert error:', err.response?.data ? JSON.stringify(err.response.data) : err.message);
  }
}

// ── GHL COACH UPSERT ──────────────────────────────────────────
async function upsertGHLCoach({ firstName, lastName, email, phone, teamName, state, city, ageGroup, bio }) {
  if (!process.env.GHL_API_KEY || !process.env.GHL_LOCATION_ID) return;
  try {
    await axios.post('https://services.leadconnectorhq.com/contacts/upsert', {
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
    }, { headers: { 'Authorization': `Bearer ${process.env.GHL_API_KEY}`, 'Content-Type': 'application/json', 'Version': '2021-07-28' } });
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
    _id:      p._id,
    name:     p.name      || '',
    jersey:   p.jersey    || '',
    gradYear: p.grad_year || '',
    position: p.position  || '',
    hw:       p.hw        || '',
    city:     p.city      || '',
    state:    p.state     || '',
    email:    p.email     || '',
    cell:     p.cell      || '',
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
      { headers: { 'Authorization': `Bearer ${process.env.GHL_API_KEY}`, 'Content-Type': 'application/json', 'Version': '2021-07-28' } }
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

    upsertGHLCoach({ firstName, lastName, email, phone, teamName });
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
    // Always return success to avoid user enumeration
    if (!coach) return res.json({ message: 'If that email exists, a reset link has been sent.' });

    const token  = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await Coach.findByIdAndUpdate(coach._id, {
      reset_token:        token,
      reset_token_expiry: expiry,
    });

    // Build reset URL — uses the frontend origin sent in request, or falls back to env var
    const origin   = req.headers.origin || process.env.FRONTEND_URL || 'https://your-frontend.vercel.app';
    const resetUrl = `${origin}/reset-password.html?token=${token}`;

    // In production you would email this link. For now we return it in the response
    // so you can wire up your email provider (SendGrid, Resend, etc.) without friction.
    res.json({
      message:  'If that email exists, a reset link has been sent.',
      resetUrl, // ← remove / hide this once email is wired up
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/reset-password
app.post('/api/coach/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ message: 'Token and new password are required' });
    if (password.length < 8)  return res.status(400).json({ message: 'Password must be at least 8 characters' });

    const coach = await Coach.findOne({
      reset_token:        token,
      reset_token_expiry: { $gt: new Date() },
    });
    if (!coach) return res.status(400).json({ message: 'Reset link is invalid or has expired' });

    const hashed = await bcrypt.hash(password, 12);
    await Coach.findByIdAndUpdate(coach._id, {
      password:           hashed,
      reset_token:        null,
      reset_token_expiry: null,
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

    upsertGHLCoach({
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

// ── IMAGE UPLOAD (GHL Media) ──────────────────────────────────
// POST /api/coach/upload-image
app.post('/api/coach/upload-image', requireAuth, async (req, res) => {
  try {
    const { base64, fileName, mimeType, saveToProfile, slot } = req.body;
    if (!base64 || !fileName) return res.status(400).json({ message: 'base64 and fileName required' });

    const imageUrl = await uploadImageToGHL(base64, fileName, mimeType);

    // Save to correct field
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
// Note: GHL has no public delete API — we only clear the URL from DB
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

// GET /api/coach/tryouts
app.get('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const tryouts = await Tryout.find({ coach_id: req.coachId }).sort({ created_at: 1 });
    res.json({ tryouts: tryouts.map(normalizeTryout) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/tryouts
app.post('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const { date, time, location, fee, city, state } = req.body;
    if (!date || !time || !location || !fee)
      return res.status(400).json({ message: 'date, time, location and fee are all required' });
    const tryout = await Tryout.create({ coach_id: req.coachId, date, time, location, fee, city: city||'', state: state||'' });
    res.status(201).json({ message: 'Tryout added', tryout: normalizeTryout(tryout) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// PUT /api/coach/tryouts/:tryoutId
app.put('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    const { date, time, location, fee, city, state } = req.body;
    if (!date || !time || !location)
      return res.status(400).json({ message: 'date, time and location are required' });
    const tryout = await Tryout.findOneAndUpdate(
      { _id: req.params.tryoutId, coach_id: req.coachId },
      { date, time, location, fee: fee||'Free', city: city||'', state: state||'' },
      { new: true }
    );
    if (!tryout) return res.status(404).json({ message: 'Tryout not found' });
    res.json({ message: 'Tryout updated', tryout: normalizeTryout(tryout) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// DELETE /api/coach/tryouts/:tryoutId
app.delete('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    await Tryout.findOneAndDelete({ _id: req.params.tryoutId, coach_id: req.coachId });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// GET /api/coach/tryout-registrations
app.get('/api/coach/tryout-registrations', requireAuth, async (req, res) => {
  try {
    const data = await TryoutRegistration.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ registrations: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── SCHEDULE ROUTES ───────────────────────────────────────────

// GET /api/coach/schedule
app.get('/api/coach/schedule', requireAuth, async (req, res) => {
  try {
    const data = await Schedule.find({ coach_id: req.coachId }).sort({ date_sort: 1 });
    res.json({ schedule: data.map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/coach/schedule
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
      city:       city||'',
      state:      state||'',
      date_sort:  startDate,
    });
    res.status(201).json({ message: 'Game added', game: normalizeGame(game) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/coach/schedule/:gameId
app.put('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    const { startDate, endDate, event, city, state } = req.body;
    if (!startDate || !endDate || !event)
      return res.status(400).json({ message: 'Start date, end date, and event are required' });
    const game = await Schedule.findOneAndUpdate(
      { _id: req.params.gameId, coach_id: req.coachId },
      { date: startDate, start_date: startDate, end_date: endDate, event, city: city||'', state: state||'', date_sort: startDate },
      { new: true }
    );
    if (!game) return res.status(404).json({ message: 'Game not found' });
    res.json({ message: 'Game updated', game: normalizeGame(game) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE /api/coach/schedule/:gameId
app.delete('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    await Schedule.findOneAndDelete({ _id: req.params.gameId, coach_id: req.coachId });
    res.json({ message: 'Game deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── FINANCIALS ROUTES ─────────────────────────────────────────

// GET /api/coach/financials
app.get('/api/coach/financials', requireAuth, async (req, res) => {
  try {
    const data = await TeamFinancials.findOne({ coach_id: req.coachId });
    res.json({ financials: data || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/coach/financials
app.post('/api/coach/financials', requireAuth, async (req, res) => {
  try {
    const { playerFee, paymentDeadline, fullPayOnly, depositEnabled, depositAmount, monthlyPayments } = req.body;
    const data = await TeamFinancials.findOneAndUpdate(
      { coach_id: req.coachId },
      {
        coach_id:         req.coachId,
        player_fee:       playerFee       || 0,
        payment_deadline: paymentDeadline || '',
        full_pay_only:    fullPayOnly     !== false,
        deposit_enabled:  depositEnabled  || false,
        deposit_amount:   depositAmount   || 250,
        monthly_payments: monthlyPayments || false,
      },
      { upsert: true, new: true }
    );
    res.json({ message: 'Saved', financials: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── PLAYER PAYMENTS ROUTES ────────────────────────────────────

// GET /api/coach/player-payments
app.get('/api/coach/player-payments', requireAuth, async (req, res) => {
  try {
    const data = await PlayerPayment.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ payments: data || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/coach/player-payments (public — called from team page)
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

// PUT /api/coach/player-payments/:paymentId
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

// DELETE /api/coach/player-payments/:paymentId
app.delete('/api/coach/player-payments/:paymentId', requireAuth, async (req, res) => {
  try {
    await PlayerPayment.findOneAndDelete({ _id: req.params.paymentId, coach_id: req.coachId });
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── BUDGET ROUTES ─────────────────────────────────────────────

// GET /api/coach/budgets
app.get('/api/coach/budgets', requireAuth, async (req, res) => {
  try {
    const data = await Budget.find({ coach_id: req.coachId }).sort({ created_at: -1 });
    res.json({ budgets: data || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/coach/budgets
app.post('/api/coach/budgets', requireAuth, async (req, res) => {
  try {
    const {
      date, players, seasons, numEvents, eventCost, tournaments,
      headPay, asstPay, rentals, gas, hotelNights, hotelAvg, hotels,
      numUniforms, uniformCost, uniforms, equipment, insurance,
      ambassadors, others, total, perPlayer
    } = req.body;
    const data = await Budget.create({
      coach_id: req.coachId, date,
      players: players||0, seasons: seasons||0, num_events: numEvents||0, event_cost: eventCost||0,
      tournaments: tournaments||0, head_pay: headPay||0, asst_pay: asstPay||0,
      rentals: rentals||0, gas: gas||0, hotel_nights: hotelNights||0, hotel_avg: hotelAvg||0,
      hotels: hotels||0, num_uniforms: numUniforms||0, uniform_cost: uniformCost||0,
      uniforms: uniforms||0, equipment: equipment||0, insurance: insurance||0,
      ambassadors: ambassadors||0, others: others||[], total: total||0, per_player: perPlayer||0,
    });
    res.status(201).json({ message: 'Budget saved', budget: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/coach/budgets/:budgetId
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
        players: players||0, seasons: seasons||0, num_events: numEvents||0, event_cost: eventCost||0,
        tournaments: tournaments||0, head_pay: headPay||0, asst_pay: asstPay||0,
        rentals: rentals||0, gas: gas||0, hotel_nights: hotelNights||0, hotel_avg: hotelAvg||0,
        hotels: hotels||0, num_uniforms: numUniforms||0, uniform_cost: uniformCost||0,
        uniforms: uniforms||0, equipment: equipment||0, insurance: insurance||0,
        ambassadors: ambassadors||450, others: others||[], total: total||0, per_player: perPlayer||0,
      },
      { new: true }
    );
    if (!data) return res.status(404).json({ message: 'Budget not found' });
    res.json({ message: 'Budget updated', budget: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE /api/coach/budgets/:budgetId
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

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username !== (process.env.ADMIN_USERNAME || 'admin') ||
      password !== (process.env.ADMIN_PASSWORD || 'admin123'))
    return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

// GET /api/admin/coaches
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

// GET /api/admin/coaches/:id
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

// PUT /api/admin/coaches/:id/toggle-active
app.put('/api/admin/coaches/:id/toggle-active', requireAdmin, async (req, res) => {
  try {
    const { active } = req.body;
    await Coach.findByIdAndUpdate(req.params.id, { active });
    res.json({ message: active ? 'Coach activated' : 'Coach deactivated', active });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/admin/coaches/:id/edit
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

// ════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ════════════════════════════════════════════════════════════════

// GET /api/teams
app.get('/api/teams', async (req, res) => {
  try {
    // active: true OR active field doesn't exist (migrated coaches without the field)
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

// GET /api/teams/:id
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

// GET /api/teams/:id/tryouts
app.get('/api/teams/:id/tryouts', async (req, res) => {
  try {
    const tryouts = await Tryout.find({ coach_id: req.params.id }).sort({ created_at: 1 });
    res.json({ tryouts: tryouts.map(normalizeTryout) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/teams/:id/roster
app.get('/api/teams/:id/roster', async (req, res) => {
  try {
    const players = await Player.find({ coach_id: req.params.id }).sort({ created_at: 1 });
    res.json({ players: players.map(normalizePlayer) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/teams/:id/roster
app.post('/api/teams/:id/roster', async (req, res) => {
  try {
    const { name, jersey, gradYear, position, hw, city, state, email, cell } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });
    const player = await Player.create({
      coach_id: req.params.id, name, jersey,
      grad_year: gradYear, position, hw, city, state,
      email: email||'', cell: cell||''
    });
    upsertGHLPlayer({ name, email, cell, city, state, position, jersey, gradYear, hw });
    res.status(201).json({ message: 'Player registered', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// PUT /api/teams/:id/roster/:playerId
app.put('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    const { name, jersey, gradYear, position, hw, city, state, email, cell } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });
    const player = await Player.findOneAndUpdate(
      { _id: req.params.playerId, coach_id: req.params.id },
      { name, jersey, grad_year: gradYear, position, hw, city, state, email, cell },
      { new: true }
    );
    if (!player) return res.status(404).json({ message: 'Player not found' });
    res.json({ message: 'Player updated', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// DELETE /api/teams/:id/roster/:playerId
app.delete('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    await Player.findOneAndDelete({ _id: req.params.playerId, coach_id: req.params.id });
    res.json({ message: 'Player deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// GET /api/teams/:id/schedule
app.get('/api/teams/:id/schedule', async (req, res) => {
  try {
    const data = await Schedule.find({ coach_id: req.params.id }).sort({ date_sort: 1 });
    res.json({ schedule: data.map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/teams/:id/financials
app.get('/api/teams/:id/financials', async (req, res) => {
  try {
    const data = await TeamFinancials.findOne({ coach_id: req.params.id });
    res.json({ financials: data || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/teams/:id/tryout-registrations
app.post('/api/teams/:id/tryout-registrations', async (req, res) => {
  try {
    const { completedBy, name, address, city, state, zip, cell, email,
            playerName, age, dob, hw, pos1, pos2, tryoutDate } = req.body;
    if (!name || !playerName) return res.status(400).json({ message: 'Name and player name are required' });

    const reg = await TryoutRegistration.create({
      coach_id:     req.params.id,
      completed_by: completedBy||'', name,
      address: address||'', city: city||'', state: state||'', zip: zip||'',
      cell: cell||'', email: email||'',
      player_name: playerName, age: age||'', dob: dob||'', hw: hw||'',
      pos1: pos1||'', pos2: pos2||'', tryout_date: tryoutDate||''
    });

    const ghlResult = await upsertGHLContact({
      completedBy, name, address, city, state, zip, cell, email,
      playerName, age, dob, hw, pos1, pos2, tryoutDate
    });

    res.status(201).json({ message: 'Registration submitted', registration: reg, ghl: ghlResult });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// Vercel serverless — no app.listen needed
module.exports = app;
