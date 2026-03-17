const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const webpush = require('web-push');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'truckers-secret-change-in-prod';

const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || 'BHVdKqGZZ1I41uIkANugsUNe467gYtRxHHrUKHczJHui9ubroAlAZ6JrWzB_ssPEwW7j7YgiG9sl5oYIskAe9y8';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '2jl6T3jjGLDk_nZh0tWP4UVPF9PHO60UO_03NfALN3k';
webpush.setVapidDetails('mailto:admin@truckers.app', VAPID_PUBLIC, VAPID_PRIVATE);

const TEAMLEADERS = (process.env.TEAMLEADER || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// ── Supabase ──────────────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://uoxpkwmpakaybimnclwo.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVveHBrd21wYWtheWJpbW5jbHdvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM3NzM2MTAsImV4cCI6MjA4OTM0OTYxMH0.XK_iWervEfka3lgHiy-kBbxsd_yZ4qUT0Lu4xeCYLlI';

const SB = {
  headers: {
    'Content-Type': 'application/json',
    'apikey': SUPABASE_KEY,
    'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Prefer': 'return=representation'
  },
  async get(table, params = '') {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}${params}`, { headers: this.headers });
    if (!r.ok) throw new Error(`SB GET ${table}: ${r.status} ${await r.text()}`);
    return r.json();
  },
  async post(table, body, upsert = false) {
    const h = { ...this.headers };
    if (upsert) h['Prefer'] = 'resolution=merge-duplicates,return=representation';
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
      method: 'POST', headers: h, body: JSON.stringify(body)
    });
    if (!r.ok) throw new Error(`SB POST ${table}: ${r.status} ${await r.text()}`);
    return r.json();
  },
  async patch(table, params, body) {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}${params}`, {
      method: 'PATCH', headers: this.headers, body: JSON.stringify(body)
    });
    if (!r.ok) throw new Error(`SB PATCH ${table}: ${r.status} ${await r.text()}`);
    return r.json();
  },
  async del(table, params) {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}${params}`, {
      method: 'DELETE', headers: this.headers
    });
    if (!r.ok) throw new Error(`SB DELETE ${table}: ${r.status} ${await r.text()}`);
    return r.json();
  }
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Ej inloggad' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user.isLeader = TEAMLEADERS.includes(req.user.username.toLowerCase());
    next();
  } catch { res.status(401).json({ error: 'Ogiltig token' }); }
}

// ── Push helpers ──────────────────────────────────────────────────────────────
async function pushToUser(username, payload) {
  try {
    const subs = await SB.get('push_subscriptions', `?username=eq.${encodeURIComponent(username)}`);
    subs.forEach(sub => webpush.sendNotification(
      { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
      JSON.stringify(payload)
    ).catch(async e => {
      if ([404,410].includes(e.statusCode)) await SB.del('push_subscriptions', `?endpoint=eq.${encodeURIComponent(sub.endpoint)}`).catch(()=>{});
    }));
  } catch(e) { console.error('pushToUser:', e.message); }
}

async function pushToAll(payload, exclude) {
  try {
    const param = exclude ? `?username=neq.${encodeURIComponent(exclude)}` : '';
    const subs = await SB.get('push_subscriptions', param);
    subs.forEach(sub => webpush.sendNotification(
      { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
      JSON.stringify(payload)
    ).catch(async e => {
      if ([404,410].includes(e.statusCode)) await SB.del('push_subscriptions', `?endpoint=eq.${encodeURIComponent(sub.endpoint)}`).catch(()=>{});
    }));
  } catch(e) { console.error('pushToAll:', e.message); }
}

// ── Push ──────────────────────────────────────────────────────────────────────
app.get('/api/push/vapid-public-key', (req, res) => res.json({ key: VAPID_PUBLIC }));

app.post('/api/push/subscribe', requireAuth, async (req, res) => {
  const { endpoint, keys } = req.body;
  if (!endpoint || !keys?.p256dh || !keys?.auth) return res.status(400).json({ error: 'Ogiltig prenumeration' });
  try {
    await SB.post('push_subscriptions', { username: req.user.username, endpoint, p256dh: keys.p256dh, auth: keys.auth }, true);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/push/unsubscribe', requireAuth, async (req, res) => {
  const { endpoint } = req.body;
  try {
    await SB.del('push_subscriptions', `?username=eq.${encodeURIComponent(req.user.username)}&endpoint=eq.${encodeURIComponent(endpoint)}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 2 || password.length < 4)
    return res.status(400).json({ error: 'Ogiltigt användarnamn eller lösenord' });
  try {
    const existing = await SB.get('users', `?username=eq.${encodeURIComponent(username.trim())}`);
    if (existing.length) return res.status(409).json({ error: 'Användarnamnet är redan taget' });
    const hash = bcrypt.hashSync(password, 10);
    await SB.post('users', { username: username.trim(), password: hash });
    const token = jwt.sign({ username: username.trim() }, JWT_SECRET, { expiresIn: '30d' });
    const isLeader = TEAMLEADERS.includes(username.trim().toLowerCase());
    res.json({ token, username: username.trim(), isLeader });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const users = await SB.get('users', `?username=eq.${encodeURIComponent(req.body.username?.trim())}`);
    const user = users[0];
    if (!user || !bcrypt.compareSync(req.body.password, user.password))
      return res.status(401).json({ error: 'Fel användarnamn eller lösenord' });
    const isLeader = TEAMLEADERS.includes(user.username.toLowerCase());
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: user.username, isLeader });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users', requireAuth, async (req, res) => {
  try {
    const users = await SB.get('users', '?select=username&order=username');
    res.json(users.map(u => ({ username: u.username, isLeader: TEAMLEADERS.includes(u.username.toLowerCase()) })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:username', requireAuth, async (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  if (req.params.username === req.user.username) return res.status(400).json({ error: 'Kan inte ta bort dig själv' });
  try {
    await SB.del('users', `?username=eq.${encodeURIComponent(req.params.username)}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Status ────────────────────────────────────────────────────────────────────
app.get('/api/status/:omrade/:day', requireAuth, async (req, res) => {
  try {
    const rows = await SB.get('status', `?omrade=eq.${req.params.omrade}&day=eq.${encodeURIComponent(req.params.day)}&state=neq.none`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/status', requireAuth, async (req, res) => {
  const { omrade, day, idx, state } = req.body;
  if (!['none','pagaende','done'].includes(state)) return res.status(400).json({ error: 'Ogiltigt state' });
  const by_user = state === 'none' ? null : req.user.username;
  try {
    // Use on_conflict to specify the unique columns for upsert
    const h = { ...SB.headers, 'Prefer': 'resolution=merge-duplicates,return=representation' };
    const r = await fetch(`${SUPABASE_URL}/rest/v1/status?on_conflict=omrade,day,idx`, {
      method: 'POST', headers: h,
      body: JSON.stringify({ omrade: parseInt(omrade), day, idx: parseInt(idx), state, by_user, updated: new Date().toISOString() })
    });
    if (!r.ok) throw new Error(`status upsert: ${r.status} ${await r.text()}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Assignments ───────────────────────────────────────────────────────────────
app.post('/api/assign', requireAuth, async (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  const { omrade, day, idx, title, to_user } = req.body;
  if (!to_user || !title) return res.status(400).json({ error: 'Saknar fält' });
  try {
    await SB.del('assignments', `?omrade=eq.${omrade}&day=eq.${encodeURIComponent(day)}&idx=eq.${idx}&state=eq.pending`);
    await SB.post('assignments', { omrade: parseInt(omrade), day, idx: parseInt(idx), title, from_user: req.user.username, to_user, state: 'pending' });
    await SB.post('status', { omrade: parseInt(omrade), day, idx: parseInt(idx), state: 'assigned', by_user: req.user.username, assigned_to: to_user, updated: new Date().toISOString() }, true);
    pushToUser(to_user, { title: `📋 Tilldelad uppgift`, body: `"${title}" – från ${req.user.username}`, tag: 'assignment', url: '/?tab=schema' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/assignments/pending', requireAuth, async (req, res) => {
  try {
    const rows = await SB.get('assignments', `?to_user=eq.${encodeURIComponent(req.user.username)}&state=eq.pending&order=created.desc`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/assignments/:id/respond', requireAuth, async (req, res) => {
  try {
    const [assignment] = await SB.get('assignments', `?id=eq.${req.params.id}`);
    if (!assignment) return res.status(404).json({ error: 'Hittades inte' });
    if (assignment.to_user !== req.user.username) return res.status(403).json({ error: 'Inte din förfrågan' });
    if (req.body.accept) {
      await SB.patch('assignments', `?id=eq.${assignment.id}`, { state: 'accepted' });
      await SB.post('status', { omrade: assignment.omrade, day: assignment.day, idx: assignment.idx, state: 'pagaende', by_user: req.user.username, assigned_to: req.user.username, updated: new Date().toISOString() }, true);
    } else {
      await SB.patch('assignments', `?id=eq.${assignment.id}`, { state: 'declined' });
      await SB.post('status', { omrade: assignment.omrade, day: assignment.day, idx: assignment.idx, state: 'none', by_user: null, assigned_to: null, updated: new Date().toISOString() }, true);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Report ────────────────────────────────────────────────────────────────────
app.get('/api/report/:day', requireAuth, async (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  const day = req.params.day;
  try {
    const users = await SB.get('users', '?select=username&order=username');
    const presence = await SB.get('presence', '');
    const presMap = {};
    presence.forEach(p => presMap[p.username] = p.status);
    const presenceList = users.map(u => ({ username: u.username, status: presMap[u.username] || 'på plats' }));
    const omr1 = await SB.get('status', `?omrade=eq.1&day=eq.${encodeURIComponent(day)}&state=neq.none&order=idx`);
    const omr2 = await SB.get('status', `?omrade=eq.2&day=eq.${encodeURIComponent(day)}&state=neq.none&order=idx`);
    res.json({ day, presence: presenceList, omrade1: omr1, omrade2: omr2 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Chat ──────────────────────────────────────────────────────────────────────
app.get('/api/chat', requireAuth, async (req, res) => {
  const since = parseInt(req.query.since) || 0;
  try {
    const rows = await SB.get('chat', `?id=gt.${since}&order=id.asc&limit=100`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/chat', requireAuth, async (req, res) => {
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'Tomt meddelande' });
  if (message.length > 500) return res.status(400).json({ error: 'För långt' });
  try {
    const result = await SB.post('chat', { username: req.user.username, message: message.trim() });
    pushToAll({ title: `💬 ${req.user.username}`, body: message.trim().substring(0,100), tag: 'chat', url: '/?tab=chatt' }, req.user.username);
    res.json({ ok: true, id: result[0]?.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/chat/:id', requireAuth, async (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  try {
    await SB.del('chat', `?id=eq.${req.params.id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Presence ──────────────────────────────────────────────────────────────────
app.get('/api/presence', requireAuth, async (req, res) => {
  try {
    const users = await SB.get('users', '?select=username,last_seen&order=username');
    const presence = await SB.get('presence', '');
    const presMap = {};
    presence.forEach(p => presMap[p.username] = p.status);
    res.json(users.map(u => ({ username: u.username, status: presMap[u.username] || 'på plats', last_seen: u.last_seen || null })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/presence', requireAuth, async (req, res) => {
  const { username, status } = req.body;
  if (username !== req.user.username && !req.user.isLeader) return res.status(403).json({ error: 'Ej tillåtet' });
  if (!['på plats','sjuk','ledigt'].includes(status)) return res.status(400).json({ error: 'Ogiltig status' });
  try {
    const ph = { ...SB.headers, 'Prefer': 'resolution=merge-duplicates,return=representation' };
    const pr = await fetch(`${SUPABASE_URL}/rest/v1/presence?on_conflict=username`, {
      method: 'POST', headers: ph,
      body: JSON.stringify({ username, status, updated: new Date().toISOString() })
    });
    if (!pr.ok) throw new Error(`presence upsert: ${pr.status} ${await pr.text()}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/heartbeat', requireAuth, async (req, res) => {
  try {
    await SB.patch('users', `?username=eq.${encodeURIComponent(req.user.username)}`, { last_seen: new Date().toISOString() });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Notes ─────────────────────────────────────────────────────────────────────
app.get('/api/notes/:omrade/:day', requireAuth, async (req, res) => {
  try {
    const rows = await SB.get('notes', `?omrade=eq.${req.params.omrade}&day=eq.${encodeURIComponent(req.params.day)}&select=idx,note,by_user,updated`);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notes', requireAuth, async (req, res) => {
  const { omrade, day, idx, note } = req.body;
  if (typeof note !== 'string') return res.status(400).json({ error: 'Saknar note' });
  const trimmed = note.trim().substring(0, 300);
  try {
    if (!trimmed) {
      await SB.del('notes', `?omrade=eq.${omrade}&day=eq.${encodeURIComponent(day)}&idx=eq.${idx}`);
    } else {
      const nh = { ...SB.headers, 'Prefer': 'resolution=merge-duplicates,return=representation' };
      const nr = await fetch(`${SUPABASE_URL}/rest/v1/notes?on_conflict=omrade,day,idx`, {
        method: 'POST', headers: nh,
        body: JSON.stringify({ omrade: parseInt(omrade), day, idx: parseInt(idx), note: trimmed, by_user: req.user.username, updated: new Date().toISOString() })
      });
      if (!nr.ok) throw new Error(`notes upsert: ${nr.status} ${await nr.text()}`);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`🚛 Karolinska Truckers på port ${PORT} – Supabase`));
