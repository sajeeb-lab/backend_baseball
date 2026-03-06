const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── MONGOOSE CONNECTION (reuse across serverless calls) ──────────
let isConnected = false;
async function connectDB() {
  if (isConnected) return;
  await mongoose.connect(process.env.MONGODB_URI);
  isConnected = true;
}

// ── SCHEMAS ──────────────────────────────────────────────────────
const AssistantSchema = new mongoose.Schema({
  name:  { type: String, default: '' },
  role:  { type: String, default: 'Assistant Coach' },
  email: { type: String, default: '' },
  cell:  { type: String, default: '' },
  bio:   { type: String, default: '' },
}, { _id: false });

const TryoutSchema = new mongoose.Schema({
  date:     { type: String, required: true },
  time:     { type: String, required: true },
  location: { type: String, required: true },
  fee:      { type: String, required: true },
}, { timestamps: true });

const CoachSchema = new mongoose.Schema({
  firstName:   { type: String, required: true, trim: true },
  lastName:    { type: String, required: true, trim: true },
  email:       { type: String, required: true, unique: true, trim: true, lowercase: true },
  phone:       { type: String, required: true, trim: true },
  password:    { type: String, required: true },
  teamName:    { type: String, required: true, trim: true },
  state:       { type: String, default: '', trim: true },
  location:    { type: String, default: '', trim: true },
  ageGroup:    { type: String, default: '', trim: true },
  emailPublic: { type: String, default: '' },
  phonePublic: { type: String, default: '' },
  bio:         { type: String, default: '' },
  image:       { type: String, default: '' },
  assistant1:  { type: AssistantSchema, default: () => ({}) },
  assistant2:  { type: AssistantSchema, default: () => ({}) },
  tryouts:     { type: [TryoutSchema], default: [] },
}, { timestamps: true });

const Coach = mongoose.models.Coach || mongoose.model('Coach', CoachSchema);

// ── AUTH HELPERS ─────────────────────────────────────────────────
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

// ── DB MIDDLEWARE ─────────────────────────────────────────────────
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    res.status(500).json({ message: 'Database connection failed' });
  }
});

// ════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/coach/register
app.post('/api/coach/register', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, teamName, password } = req.body;
    if (!firstName || !lastName || !email || !phone || !teamName || !password)
      return res.status(400).json({ message: 'All fields are required' });
    if (password.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    if (await Coach.findOne({ email: email.toLowerCase() }))
      return res.status(409).json({ message: 'An account with this email already exists' });

    const hashed = await bcrypt.hash(password, 12);
    await Coach.create({
      firstName, lastName,
      email:       email.toLowerCase(),
      phone,       teamName,
      password:    hashed,
      emailPublic: email.toLowerCase(),
      phonePublic: phone,
    });
    res.status(201).json({ message: 'Account created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/login
app.post('/api/coach/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required' });
    const coach = await Coach.findOne({ email: email.toLowerCase() });
    if (!coach || !(await bcrypt.compare(password, coach.password)))
      return res.status(401).json({ message: 'Invalid email or password' });
    res.json({
      token: signToken(coach._id),
      coach: { _id: coach._id, firstName: coach.firstName, lastName: coach.lastName, teamName: coach.teamName }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════════
//  DASHBOARD ROUTES (protected)
// ════════════════════════════════════════════════════════════════

// GET /api/coach/me
app.get('/api/coach/me', requireAuth, async (req, res) => {
  try {
    const coach = await Coach.findById(req.coachId).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ coach });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/coach/update-profile
app.put('/api/coach/update-profile', requireAuth, async (req, res) => {
  try {
    const allowed = ['firstName','lastName','emailPublic','phonePublic','bio','image','teamName','state','location','ageGroup'];
    const update  = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });
    if (update.state) update.state = update.state.toUpperCase();
    const coach = await Coach.findByIdAndUpdate(req.coachId, update, { new: true }).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ message: 'Saved', coach });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/coach/update-assistants
app.put('/api/coach/update-assistants', requireAuth, async (req, res) => {
  try {
    const update = {};
    if (req.body.assistant1) update.assistant1 = req.body.assistant1;
    if (req.body.assistant2) update.assistant2 = req.body.assistant2;
    const coach = await Coach.findByIdAndUpdate(req.coachId, update, { new: true }).select('-password');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ message: 'Saved', coach });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/coach/tryouts
app.get('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const coach = await Coach.findById(req.coachId).select('tryouts');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ tryouts: coach.tryouts });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/coach/tryouts
app.post('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const { date, time, location, fee } = req.body;
    if (!date || !time || !location || !fee)
      return res.status(400).json({ message: 'date, time, location and fee are all required' });
    const coach = await Coach.findByIdAndUpdate(
      req.coachId,
      { $push: { tryouts: { date, time, location, fee } } },
      { new: true }
    ).select('tryouts');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.status(201).json({ message: 'Tryout added', tryouts: coach.tryouts });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE /api/coach/tryouts/:tryoutId
app.delete('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    const coach = await Coach.findByIdAndUpdate(
      req.coachId,
      { $pull: { tryouts: { _id: req.params.tryoutId } } },
      { new: true }
    ).select('tryouts');
    if (!coach) return res.status(404).json({ message: 'Coach not found' });
    res.json({ message: 'Deleted', tryouts: coach.tryouts });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES (index.html + team.html)
// ════════════════════════════════════════════════════════════════

// GET /api/teams
app.get('/api/teams', async (req, res) => {
  try {
    const teams = await Coach.find({}, 'firstName lastName teamName state location ageGroup').lean();
    res.json({ teams });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/teams/:id
app.get('/api/teams/:id', async (req, res) => {
  try {
    const team = await Coach.findById(req.params.id).select('-password -email -phone').lean();
    if (!team) return res.status(404).json({ message: 'Team not found' });
    res.json({ team });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/teams/:id/tryouts
app.get('/api/teams/:id/tryouts', async (req, res) => {
  try {
    const team = await Coach.findById(req.params.id).select('tryouts').lean();
    if (!team) return res.status(404).json({ message: 'Team not found' });
    res.json({ tryouts: team.tryouts });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = app;