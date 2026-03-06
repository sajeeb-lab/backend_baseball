const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.options('*', cors());
app.use(express.json({ limit: '10mb' }));

// ── SUPABASE CLIENT ───────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

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

    // Check if email exists
    const { data: existing } = await supabase
      .from('coaches')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();
    if (existing) return res.status(409).json({ message: 'An account with this email already exists' });

    const hashed = await bcrypt.hash(password, 12);
    const { error } = await supabase.from('coaches').insert({
      first_name:   firstName,
      last_name:    lastName,
      email:        email.toLowerCase(),
      phone,
      team_name:    teamName,
      password:     hashed,
      email_public: email.toLowerCase(),
      phone_public: phone,
    });
    if (error) throw error;
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

    const { data: coach, error } = await supabase
      .from('coaches')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();
    if (error || !coach) return res.status(401).json({ message: 'Invalid email or password' });
    if (!(await bcrypt.compare(password, coach.password)))
      return res.status(401).json({ message: 'Invalid email or password' });

    res.json({
      token: signToken(coach.id),
      coach: { _id: coach.id, firstName: coach.first_name, lastName: coach.last_name, teamName: coach.team_name }
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
    const { data: coach, error } = await supabase
      .from('coaches')
      .select('id, first_name, last_name, email_public, phone_public, bio, image_url, team_name, state, location, age_group, assistant1, assistant2')
      .eq('id', req.coachId)
      .single();
    if (error || !coach) return res.status(404).json({ message: 'Coach not found' });

    // Normalize for frontend
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
    };
    const update = {};
    Object.entries(map).forEach(([jsKey, dbKey]) => {
      if (req.body[jsKey] !== undefined) update[dbKey] = req.body[jsKey];
    });
    if (update.state) update.state = update.state.toUpperCase();

    const { data: coach, error } = await supabase
      .from('coaches')
      .update(update)
      .eq('id', req.coachId)
      .select('id, first_name, last_name, email_public, phone_public, bio, image_url, team_name, state, location, age_group, assistant1, assistant2')
      .single();
    if (error) throw error;
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

    const { data: coach, error } = await supabase
      .from('coaches')
      .update(update)
      .eq('id', req.coachId)
      .select('id, first_name, last_name, email_public, phone_public, bio, image_url, team_name, state, location, age_group, assistant1, assistant2')
      .single();
    if (error) throw error;
    res.json({ message: 'Saved', coach: normalizeCoach(coach) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// GET /api/coach/tryouts
app.get('/api/coach/tryouts', requireAuth, async (req, res) => {
  try {
    const { data: tryouts, error } = await supabase
      .from('tryouts')
      .select('*')
      .eq('coach_id', req.coachId)
      .order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ tryouts: tryouts.map(normalizeTryout) });
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

    const { data: tryout, error } = await supabase
      .from('tryouts')
      .insert({ coach_id: req.coachId, date, time, location, fee })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ message: 'Tryout added', tryout: normalizeTryout(tryout) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// DELETE /api/coach/tryouts/:tryoutId
app.delete('/api/coach/tryouts/:tryoutId', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase
      .from('tryouts')
      .delete()
      .eq('id', req.params.tryoutId)
      .eq('coach_id', req.coachId);
    if (error) throw error;
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// ── IMAGE UPLOAD ──────────────────────────────────────────────────
// POST /api/coach/upload-image
// Pass saveToProfile: true only for head coach photo
app.post('/api/coach/upload-image', requireAuth, async (req, res) => {
  try {
    const { base64, fileName, mimeType, saveToProfile } = req.body;
    if (!base64 || !fileName) return res.status(400).json({ message: 'base64 and fileName required' });

    const buffer   = Buffer.from(base64, 'base64');
    const ext      = fileName.split('.').pop().toLowerCase() || 'jpg';
    // Use fixed filename based on slot so re-uploads overwrite the old file
    const slot     = req.body.slot || 'head'; // 'head' | 'asst1' | 'asst2'
    const filePath = `coaches/${req.coachId}/${slot}.${ext}`;

    const { error: uploadError } = await supabase.storage
      .from('images')
      .upload(filePath, buffer, { contentType: mimeType || 'image/jpeg', upsert: true });
    if (uploadError) throw uploadError;

    const { data: { publicUrl } } = supabase.storage.from('images').getPublicUrl(filePath);

    // Only save to coaches table if this is the head coach profile photo
    if (saveToProfile) {
      await supabase.from('coaches').update({ image_url: publicUrl }).eq('id', req.coachId);
    }

    res.json({ message: 'Uploaded', imageUrl: publicUrl });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Upload failed' });
  }
});

// ════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES (index.html + team.html)
// ════════════════════════════════════════════════════════════════

// GET /api/teams
app.get('/api/teams', async (req, res) => {
  try {
    const { data: teams, error } = await supabase
      .from('coaches')
      .select('id, first_name, last_name, team_name, state, location, age_group, image_url');
    if (error) throw error;
    res.json({ teams: teams.map(t => ({
      _id:      t.id,
      teamName: t.team_name,
      state:    t.state,
      location: t.location,
      ageGroup: t.age_group,
      imageUrl: t.image_url,
    }))});
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/teams/:id
app.get('/api/teams/:id', async (req, res) => {
  try {
    const { data: team, error } = await supabase
      .from('coaches')
      .select('id, first_name, last_name, email_public, phone_public, bio, image_url, team_name, state, location, age_group, assistant1, assistant2')
      .eq('id', req.params.id)
      .single();
    if (error || !team) return res.status(404).json({ message: 'Team not found' });
    res.json({ team: normalizeCoach(team) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/teams/:id/tryouts
app.get('/api/teams/:id/tryouts', async (req, res) => {
  try {
    const { data: tryouts, error } = await supabase
      .from('tryouts')
      .select('*')
      .eq('coach_id', req.params.id)
      .order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ tryouts: tryouts.map(normalizeTryout) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/teams/:id/roster
app.post('/api/teams/:id/roster', async (req, res) => {
  try {
    const { name, jersey, gradYear, position, hw, city, state } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });

    const { data: player, error } = await supabase
      .from('players')
      .insert({ coach_id: req.params.id, name, jersey, grad_year: gradYear, position, hw, city, state })
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ message: 'Player registered', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// GET /api/teams/:id/roster
app.get('/api/teams/:id/roster', async (req, res) => {
  try {
    const { data: players, error } = await supabase
      .from('players')
      .select('*')
      .eq('coach_id', req.params.id)
      .order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ players: players.map(normalizePlayer) });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════════
//  NORMALIZERS — convert snake_case DB fields to camelCase
// ════════════════════════════════════════════════════════════════
function normalizeCoach(c) {
  return {
    _id:         c.id,
    firstName:   c.first_name,
    lastName:    c.last_name,
    emailPublic: c.email_public  || '',
    phonePublic: c.phone_public  || '',
    bio:         c.bio           || '',
    image:       c.image_url     || '',
    teamName:    c.team_name,
    state:       c.state         || '',
    location:    c.location      || '',
    ageGroup:    c.age_group     || '',
    assistant1:  c.assistant1    || {},
    assistant2:  c.assistant2    || {},
  };
}

function normalizeTryout(t) {
  return { _id: t.id, date: t.date, time: t.time, location: t.location, fee: t.fee };
}

function normalizePlayer(p) {
  return {
    _id:      p.id,
    name:     p.name,
    jersey:   p.jersey   || '',
    gradYear: p.grad_year|| '',
    position: p.position || '',
    hw:       p.hw       || '',
    city:     p.city     || '',
    state:    p.state    || '',
  };
}


// PUT /api/teams/:id/roster/:playerId — edit a player
app.put('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    const { name, jersey, gradYear, position, hw, city, state } = req.body;
    if (!name) return res.status(400).json({ message: 'Player name is required' });

    const { data: player, error } = await supabase
      .from('players')
      .update({ name, jersey, grad_year: gradYear, position, hw, city, state })
      .eq('id', req.params.playerId)
      .eq('coach_id', req.params.id)
      .select()
      .single();
    if (error) throw error;
    res.json({ message: 'Player updated', player: normalizePlayer(player) });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

// DELETE /api/teams/:id/roster/:playerId — delete a player
app.delete('/api/teams/:id/roster/:playerId', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase
      .from('players')
      .delete()
      .eq('id', req.params.playerId)
      .eq('coach_id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Player deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Server error' });
  }
});

module.exports = app;
module.exports.default = app;
