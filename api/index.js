const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const axios   = require('axios');
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

// ── GHL HELPER ────────────────────────────────────────────────────
async function upsertGHLContact({ completedBy, name, address, city, state, zip, cell, email,
                                   playerName, age, dob, hw, pos1, pos2, tryoutDate }) {
  const GHL_API_KEY     = process.env.GHL_API_KEY;
  const GHL_LOCATION_ID = process.env.GHL_LOCATION_ID;

  if (!GHL_API_KEY || !GHL_LOCATION_ID) {
    console.error('GHL ERROR: GHL_API_KEY or GHL_LOCATION_ID env vars are missing');
    return { success: false, error: 'GHL env vars not set' };
  }

  const nameParts = (name || '').trim().split(' ');
  const firstName = nameParts[0] || '';
  const lastName  = nameParts.slice(1).join(' ') || '';

  let formattedDob = '';
  if (dob) {
    const d = new Date(dob);
    if (!isNaN(d)) formattedDob = d.toISOString().split('T')[0];
  }

  let formattedTryoutDate = '';
  if (tryoutDate) {
    const d = new Date(tryoutDate);
    if (!isNaN(d)) formattedTryoutDate = d.toISOString();
  }

  const payload = {
    locationId: GHL_LOCATION_ID,
    firstName,
    lastName,
    email:      email   || '',
    phone:      cell    || '',
    address1:   address || '',
    city:       city    || '',
    state:      state   || '',
    postalCode: zip     || '',
    dateOfBirth: formattedDob,
    tags: ['Baseball Tryout'],
    customFields: [
      { key: 'player_name',   value: playerName      || '' },
      { key: 'position_1',    value: pos1            || '' },
      { key: 'position_2',    value: pos2            || '' },
      { key: 'age',           value: age             || '' },
      { key: 'completed_by',  value: completedBy     || '' },
      { key: 'tryout_date',   value: formattedTryoutDate  },
      { key: 'height__weight',value: hw              || '' },
    ],
  };

  console.log('GHL payload:', JSON.stringify(payload, null, 2));

  try {
    const response = await axios.post('https://services.leadconnectorhq.com/contacts/upsert', payload, {
      headers: {
        'Authorization': `Bearer ${GHL_API_KEY}`,
        'Content-Type':  'application/json',
        'Version':       '2021-07-28',
      },
    });
    console.log('GHL contact upserted successfully. Contact ID:', response.data?.contact?.id || 'unknown');
    return { success: true, contactId: response.data?.contact?.id || '' };
  } catch (err) {
    const errMsg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error('GHL upsert error:', errMsg);
    return { success: false, error: errMsg };
  }
}

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

// ── TEMP: GET GHL CUSTOM FIELDS (remove after getting IDs) ──────
app.get('/api/ghl-fields', async (req, res) => {
  try {
    const response = await axios.get(
      `https://services.leadconnectorhq.com/contacts/custom-fields?locationId=${process.env.GHL_LOCATION_ID}`,
      {
        headers: {
          'Authorization': `Bearer ${process.env.GHL_API_KEY}`,
          'Content-Type': 'application/json',
          'Version': '2021-07-28',
        }
      }
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
    const slot     = req.body.slot || 'head'; // 'head' | 'asst1' | 'asst2'
    // Get the real extension from mimeType to avoid corrupting images
    // Delete all existing files for this slot first (clean slate)
    const allExts = ['jpg','jpeg','png','webp','gif'];
    await supabase.storage.from('images').remove(allExts.map(e => `coaches/${req.coachId}/${slot}.${e}`));

    // Use original extension from mime type
    const mimeToExt = { 'image/jpeg':'jpg', 'image/jpg':'jpg', 'image/png':'png', 'image/webp':'webp', 'image/gif':'gif' };
    const ext       = mimeToExt[mimeType] || 'jpg';
    const filePath  = `coaches/${req.coachId}/${slot}.${ext}`;

    const { error: uploadError } = await supabase.storage
      .from('images')
      .upload(filePath, buffer, { contentType: mimeType || 'image/jpeg', upsert: false });
    if (uploadError) throw uploadError;

    const { data: { publicUrl } } = supabase.storage.from('images').getPublicUrl(filePath);

    // Append cache-busting timestamp so CDN always serves the fresh image
    const cacheBustedUrl = `${publicUrl}?t=${Date.now()}`;

    // Only save to coaches table if this is the head coach profile photo
    if (saveToProfile) {
      await supabase.from('coaches').update({ image_url: cacheBustedUrl }).eq('id', req.coachId);
    }

    res.json({ message: 'Uploaded', imageUrl: cacheBustedUrl });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Upload failed' });
  }
});

// DELETE /api/coach/delete-image
app.delete('/api/coach/delete-image', requireAuth, async (req, res) => {
  try {
    const { slot } = req.body; // 'head' | 'asst1' | 'asst2'
    if (!slot) return res.status(400).json({ message: 'slot required' });

    // Remove all possible extensions for this slot
    const allExts = ['jpg','jpeg','png','webp','gif'];
    const paths = allExts.map(e => `coaches/${req.coachId}/${slot}.${e}`);
    await supabase.storage.from('images').remove(paths);

    // Clear from DB
    if (slot === 'head') {
      await supabase.from('coaches').update({ image_url: null }).eq('id', req.coachId);
    } else {
      // Clear image from assistant jsonb
      const col = slot === 'asst1' ? 'assistant1' : 'assistant2';
      const { data: coach } = await supabase.from('coaches').select(col).eq('id', req.coachId).single();
      if (coach && coach[col]) {
        const updated = { ...coach[col], image: '' };
        await supabase.from('coaches').update({ [col]: updated }).eq('id', req.coachId);
      }
    }
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message || 'Delete failed' });
  }
});


// ════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════════════════════════════

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

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
  if (username !== adminUser || password !== adminPass) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

// GET /api/admin/coaches — all coaches with stats
app.get('/api/admin/coaches', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('coaches')
      .select('id, first_name, last_name, email, phone, team_name, state, location, age_group, image_url, active, created_at')
      .order('created_at', { ascending: false });
    if (error) throw error;

    // Get tryout registration counts per coach
    const { data: regCounts } = await supabase
      .from('tryout_registrations')
      .select('coach_id');

    const countMap = {};
    (regCounts || []).forEach(r => { countMap[r.coach_id] = (countMap[r.coach_id] || 0) + 1; });

    const coaches = data.map(c => ({
      id: c.id,
      firstName: c.first_name,
      lastName: c.last_name,
      email: c.email,
      phone: c.phone,
      teamName: c.team_name,
      state: c.state,
      location: c.location,
      ageGroup: c.age_group,
      image: c.image_url || '',
      active: c.active !== false, // default true if null
      createdAt: c.created_at,
      registrationCount: countMap[c.id] || 0,
    }));
    res.json({ coaches });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/admin/coaches/:id — full coach detail
app.get('/api/admin/coaches/:id', requireAdmin, async (req, res) => {
  try {
    const { data: c, error } = await supabase
      .from('coaches')
      .select('*')
      .eq('id', req.params.id)
      .single();
    if (error) throw error;

    const { data: tryouts } = await supabase.from('tryouts').select('*').eq('coach_id', c.id);
    const { data: regs }    = await supabase.from('tryout_registrations').select('*').eq('coach_id', c.id).order('created_at', { ascending: false });
    const { data: roster }  = await supabase.from('players').select('*').eq('coach_id', c.id);
    const { data: schedule } = await supabase.from('schedule').select('*').eq('coach_id', c.id).order('date_sort');

    res.json({
      coach: {
        id: c.id, firstName: c.first_name, lastName: c.last_name,
        email: c.email, phone: c.phone, teamName: c.team_name,
        state: c.state, location: c.location, ageGroup: c.age_group,
        image: c.image_url || '', bio: c.bio || '',
        emailPublic: c.email_public || '', phonePublic: c.phone_public || '',
        assistant1: c.assistant1 || {}, assistant2: c.assistant2 || {},
        active: c.active !== false, createdAt: c.created_at,
      },
      tryouts: tryouts || [],
      registrations: regs || [],
      roster: roster || [],
      schedule: schedule || [],
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/admin/coaches/:id/toggle-active
app.put('/api/admin/coaches/:id/toggle-active', requireAdmin, async (req, res) => {
  try {
    const { active } = req.body;
    const { error } = await supabase
      .from('coaches')
      .update({ active })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: active ? 'Coach activated' : 'Coach deactivated', active });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PUT /api/admin/coaches/:id/edit
app.put('/api/admin/coaches/:id/edit', requireAdmin, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, teamName, state, location, ageGroup } = req.body;
    const { error } = await supabase.from('coaches').update({
      first_name: firstName, last_name: lastName, email,
      phone, team_name: teamName, state, location, age_group: ageGroup,
    }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Coach updated' });
  } catch (err) {
    res.status(500).json({ message: err.message });
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
      .select('id, first_name, last_name, team_name, state, location, age_group, image_url, active')
      .or('active.is.null,active.eq.true');
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


// POST /api/teams/:id/tryout-registrations — public, saves tryout registration
app.post('/api/teams/:id/tryout-registrations', async (req, res) => {
  try {
    const { completedBy, name, address, city, state, zip, cell, email,
            playerName, age, dob, hw, pos1, pos2, tryoutDate } = req.body;
    if (!name || !playerName) return res.status(400).json({ message: 'Name and player name are required' });
    const { data, error } = await supabase
      .from('tryout_registrations')
      .insert([{
        coach_id: req.params.id,
        completed_by: completedBy||'',
        name, address: address||'', city: city||'', state: state||'', zip: zip||'',
        cell: cell||'', email: email||'',
        player_name: playerName, age: age||'', dob: dob||'', hw: hw||'',
        pos1: pos1||'', pos2: pos2||'',
        tryout_date: tryoutDate||''
      }])
      .select()
      .single();
    if (error) throw error;

    // Upsert contact in GHL and include result in response for debugging
    const ghlResult = await upsertGHLContact({ completedBy, name, address, city, state, zip, cell, email,
                       playerName, age, dob, hw, pos1, pos2, tryoutDate });

    res.status(201).json({
      message: 'Registration submitted',
      registration: data,
      ghl: ghlResult
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/coach/tryout-registrations — protected, coach sees their registrations
app.get('/api/coach/tryout-registrations', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('tryout_registrations')
      .select('*')
      .eq('coach_id', req.coachId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ registrations: data });
  } catch (err) {
    res.status(500).json({ message: err.message });
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


// ── SCHEDULE ROUTES ──────────────────────────────────────────────────────────

// GET /api/teams/:id/schedule — public, fetch team schedule
app.get('/api/teams/:id/schedule', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('schedule')
      .select('*')
      .eq('coach_id', req.params.id)
      .order('date_sort', { ascending: true });
    if (error) throw error;
    res.json({ schedule: (data || []).map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/coach/schedule — protected, coach fetches own schedule
app.get('/api/coach/schedule', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('schedule')
      .select('*')
      .eq('coach_id', req.coachId)
      .order('date_sort', { ascending: true });
    if (error) throw error;
    res.json({ schedule: (data || []).map(normalizeGame) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/coach/schedule — add a game
app.post('/api/coach/schedule', requireAuth, async (req, res) => {
  try {
    const { date, event, city, state } = req.body;
    if (!date || !event) return res.status(400).json({ message: 'Date and event are required' });
    const { data, error } = await supabase
      .from('schedule')
      .insert([{ coach_id: req.coachId, date, event, city: city||'', state: state||'', date_sort: date }])
      .select()
      .single();
    if (error) throw error;
    res.status(201).json({ message: 'Game added', game: normalizeGame(data) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// PUT /api/coach/schedule/:gameId — edit a game
app.put('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    const { date, event, city, state } = req.body;
    if (!date || !event) return res.status(400).json({ message: 'Date and event are required' });
    const { data, error } = await supabase
      .from('schedule')
      .update({ date, event, city: city||'', state: state||'', date_sort: date })
      .eq('id', req.params.gameId)
      .eq('coach_id', req.coachId)
      .select()
      .single();
    if (error) throw error;
    res.json({ message: 'Game updated', game: normalizeGame(data) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// DELETE /api/coach/schedule/:gameId — delete a game
app.delete('/api/coach/schedule/:gameId', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase
      .from('schedule')
      .delete()
      .eq('id', req.params.gameId)
      .eq('coach_id', req.coachId);
    if (error) throw error;
    res.json({ message: 'Game deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

function normalizeGame(g) {
  return {
    _id:    g.id,
    date:   g.date   || '',
    event:  g.event  || '',
    city:   g.city   || '',
    state:  g.state  || '',
  };
}

module.exports = app;
module.exports.default = app;
