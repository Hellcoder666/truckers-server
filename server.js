const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const webpush = require('web-push');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'truckers-secret-change-in-prod';

// VAPID keys — genererade en gång, sätt som env vars på Render
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || 'BHVdKqGZZ1I41uIkANugsUNe467gYtRxHHrUKHczJHui9ubroAlAZ6JrWzB_ssPEwW7j7YgiG9sl5oYIskAe9y8';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '2jl6T3jjGLDk_nZh0tWP4UVPF9PHO60UO_03NfALN3k';
webpush.setVapidDetails('mailto:admin@truckers.app', VAPID_PUBLIC, VAPID_PRIVATE);

// Teamleader: sätt via Railway Variables: TEAMLEADER=Anders
// Flera: TEAMLEADER=Anders,Maria
const TEAMLEADERS = (process.env.TEAMLEADER || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database(path.join(__dirname, 'truckers.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    password  TEXT NOT NULL,
    created   TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS status (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    omrade      INTEGER NOT NULL,
    day         TEXT NOT NULL,
    idx         INTEGER NOT NULL,
    state       TEXT NOT NULL DEFAULT 'none',
    by_user     TEXT,
    assigned_to TEXT,
    updated     TEXT DEFAULT (datetime('now')),
    UNIQUE(omrade, day, idx)
  );
  CREATE TABLE IF NOT EXISTS assignments (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    omrade    INTEGER NOT NULL,
    day       TEXT NOT NULL,
    idx       INTEGER NOT NULL,
    title     TEXT NOT NULL,
    from_user TEXT NOT NULL,
    to_user   TEXT NOT NULL,
    state     TEXT NOT NULL DEFAULT 'pending',
    created   TEXT DEFAULT (datetime('now'))
  );
`);
try { db.exec(`ALTER TABLE status ADD COLUMN assigned_to TEXT`); } catch {}
db.exec(`
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL,
    endpoint  TEXT NOT NULL UNIQUE,
    p256dh    TEXT NOT NULL,
    auth      TEXT NOT NULL,
    created   TEXT DEFAULT (datetime('now'))
  );
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS notes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    omrade   INTEGER NOT NULL,
    day      TEXT NOT NULL,
    idx      INTEGER NOT NULL,
    note     TEXT NOT NULL,
    by_user  TEXT NOT NULL,
    updated  TEXT DEFAULT (datetime('now')),
    UNIQUE(omrade, day, idx)
  );
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS presence (
    username  TEXT PRIMARY KEY,
    status    TEXT NOT NULL DEFAULT 'på plats',
    updated   TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS chat (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL,
    message   TEXT NOT NULL,
    created   TEXT DEFAULT (datetime('now'))
  );
`);
try { db.exec(`ALTER TABLE users ADD COLUMN last_seen TEXT`); } catch {}

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
function sendPushToUser(username, payload) {
  const subs = db.prepare('SELECT * FROM push_subscriptions WHERE username=?').all(username);
  subs.forEach(sub => {
    webpush.sendNotification(
      { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
      JSON.stringify(payload)
    ).catch(err => {
      // Remove expired/invalid subscriptions
      if (err.statusCode === 404 || err.statusCode === 410) {
        db.prepare('DELETE FROM push_subscriptions WHERE endpoint=?').run(sub.endpoint);
      }
    });
  });
}

function sendPushToAll(payload, excludeUsername) {
  const subs = db.prepare('SELECT * FROM push_subscriptions WHERE username != ?').all(excludeUsername || '');
  subs.forEach(sub => {
    webpush.sendNotification(
      { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
      JSON.stringify(payload)
    ).catch(err => {
      if (err.statusCode === 404 || err.statusCode === 410) {
        db.prepare('DELETE FROM push_subscriptions WHERE endpoint=?').run(sub.endpoint);
      }
    });
  });
}

// ── Push subscription endpoints ───────────────────────────────────────────────
app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ key: VAPID_PUBLIC });
});

app.post('/api/push/subscribe', requireAuth, (req, res) => {
  const { endpoint, keys } = req.body;
  if (!endpoint || !keys?.p256dh || !keys?.auth) return res.status(400).json({ error: 'Ogiltig prenumeration' });
  db.prepare(`
    INSERT INTO push_subscriptions (username, endpoint, p256dh, auth)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(endpoint) DO UPDATE SET username=excluded.username, p256dh=excluded.p256dh, auth=excluded.auth
  `).run(req.user.username, endpoint, keys.p256dh, keys.auth);
  res.json({ ok: true });
});

app.post('/api/push/unsubscribe', requireAuth, (req, res) => {
  const { endpoint } = req.body;
  db.prepare('DELETE FROM push_subscriptions WHERE username=? AND endpoint=?').run(req.user.username, endpoint);
  res.json({ ok: true });
});

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 2 || password.length < 4)
    return res.status(400).json({ error: 'Ogiltigt användarnamn eller lösenord (min 2 resp 4 tecken)' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username.trim(), hash);
    const isLeader = TEAMLEADERS.includes(username.trim().toLowerCase());
    const token = jwt.sign({ username: username.trim() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: username.trim(), isLeader });
  } catch (e) {
    res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500)
      .json({ error: e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'Användarnamnet är redan taget' : 'Serverfel' });
  }
});

app.post('/api/login', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(req.body.username?.trim());
  if (!user || !bcrypt.compareSync(req.body.password, user.password))
    return res.status(401).json({ error: 'Fel användarnamn eller lösenord' });
  const isLeader = TEAMLEADERS.includes(user.username.toLowerCase());
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username, isLeader });
});

app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT username FROM users ORDER BY username ASC').all();
  res.json(users.map(u => ({ username: u.username, isLeader: TEAMLEADERS.includes(u.username.toLowerCase()) })));
});

app.delete('/api/users/:username', requireAuth, (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  const target = req.params.username;
  if (target === req.user.username) return res.status(400).json({ error: 'Du kan inte ta bort ditt eget konto' });
  const user = db.prepare('SELECT id FROM users WHERE username=?').get(target);
  if (!user) return res.status(404).json({ error: 'Användaren finns inte' });
  db.prepare('DELETE FROM users WHERE username=?').run(target);
  db.prepare('DELETE FROM presence WHERE username=?').run(target);
  res.json({ ok: true });
});

// ── Status ────────────────────────────────────────────────────────────────────
app.get('/api/status/:omrade/:day', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT idx, state, by_user, assigned_to, updated FROM status WHERE omrade=? AND day=?'
  ).all(parseInt(req.params.omrade), req.params.day);
  res.json(rows);
});

app.post('/api/status', requireAuth, (req, res) => {
  const { omrade, day, idx, state } = req.body;
  if (!['none','pagaende','done'].includes(state)) return res.status(400).json({ error: 'Ogiltigt state' });
  const by_user = state === 'none' ? null : req.user.username;
  db.prepare(`
    INSERT INTO status (omrade, day, idx, state, by_user, updated)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(omrade, day, idx) DO UPDATE SET
      state=excluded.state, by_user=excluded.by_user,
      assigned_to=CASE WHEN excluded.state='none' THEN NULL ELSE assigned_to END,
      updated=excluded.updated
  `).run(parseInt(omrade), day, parseInt(idx), state, by_user);
  res.json({ ok: true });
});

// ── Assignments ───────────────────────────────────────────────────────────────
app.post('/api/assign', requireAuth, (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  const { omrade, day, idx, title, to_user } = req.body;
  if (!to_user || !title) return res.status(400).json({ error: 'Saknar fält' });

  db.prepare(`DELETE FROM assignments WHERE omrade=? AND day=? AND idx=? AND state='pending'`)
    .run(parseInt(omrade), day, parseInt(idx));

  db.prepare(`INSERT INTO assignments (omrade,day,idx,title,from_user,to_user,state) VALUES (?,?,?,?,?,?,'pending')`)
    .run(parseInt(omrade), day, parseInt(idx), title, req.user.username, to_user);

  db.prepare(`
    INSERT INTO status (omrade,day,idx,state,by_user,assigned_to,updated)
    VALUES (?,?,?,'assigned',?,?,datetime('now'))
    ON CONFLICT(omrade,day,idx) DO UPDATE SET
      state='assigned', by_user=excluded.by_user,
      assigned_to=excluded.assigned_to, updated=excluded.updated
  `).run(parseInt(omrade), day, parseInt(idx), req.user.username, to_user);

  // Push to the assigned user
  const isLeaderSender = req.user.isLeader;
  sendPushToUser(to_user, {
    title: isLeaderSender ? `📋 Tilldelad uppgift` : `🙋 Förfrågan om hjälp`,
    body: `"${title}" – från ${req.user.username}`,
    tag: 'assignment',
    url: '/?tab=schema'
  });

  res.json({ ok: true });
});

app.get('/api/assignments/pending', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM assignments WHERE to_user=? AND state='pending' ORDER BY created DESC`)
    .all(req.user.username);
  res.json(rows);
});

app.post('/api/assignments/:id/respond', requireAuth, (req, res) => {
  const assignment = db.prepare('SELECT * FROM assignments WHERE id=?').get(parseInt(req.params.id));
  if (!assignment) return res.status(404).json({ error: 'Hittades inte' });
  if (assignment.to_user !== req.user.username) return res.status(403).json({ error: 'Inte din förfrågan' });

  if (req.body.accept) {
    db.prepare(`UPDATE assignments SET state='accepted' WHERE id=?`).run(assignment.id);
    db.prepare(`
      INSERT INTO status (omrade,day,idx,state,by_user,assigned_to,updated)
      VALUES (?,?,?,'pagaende',?,?,datetime('now'))
      ON CONFLICT(omrade,day,idx) DO UPDATE SET
        state='pagaende', by_user=excluded.by_user,
        assigned_to=excluded.assigned_to, updated=excluded.updated
    `).run(assignment.omrade, assignment.day, assignment.idx, req.user.username, req.user.username);
  } else {
    db.prepare(`UPDATE assignments SET state='declined' WHERE id=?`).run(assignment.id);
    db.prepare(`
      INSERT INTO status (omrade,day,idx,state,by_user,assigned_to,updated)
      VALUES (?,?,?,'none',NULL,NULL,datetime('now'))
      ON CONFLICT(omrade,day,idx) DO UPDATE SET
        state='none', by_user=NULL, assigned_to=NULL, updated=excluded.updated
    `).run(assignment.omrade, assignment.day, assignment.idx);
  }
  res.json({ ok: true });
});

// ── Daily Report ──────────────────────────────────────────────────────────────
app.get('/api/report/:day', requireAuth, (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  const day = req.params.day;

  // Presence
  const users = db.prepare(`SELECT username FROM users ORDER BY username`).all();
  const presMap = {};
  db.prepare(`SELECT username, status FROM presence`).all()
    .forEach(r => presMap[r.username] = r.status);
  const presence = users.map(u => ({
    username: u.username,
    status: presMap[u.username] || 'på plats'
  }));

  // Status for both areas
  const omr1 = db.prepare(`SELECT idx, state, by_user, updated FROM status WHERE omrade=1 AND day=? AND state!='none' ORDER BY idx`).all(day);
  const omr2 = db.prepare(`SELECT idx, state, by_user, updated FROM status WHERE omrade=2 AND day=? AND state!='none' ORDER BY idx`).all(day);

  res.json({ day, presence, omrade1: omr1, omrade2: omr2 });
});
// ── Chat ──────────────────────────────────────────────────────────────────────
app.get('/api/chat', requireAuth, (req, res) => {
  const since = req.query.since || 0;
  const rows = db.prepare(`SELECT id, username, message, created FROM chat WHERE id > ? ORDER BY id ASC LIMIT 100`).all(parseInt(since));
  res.json(rows);
});

app.post('/api/chat', requireAuth, (req, res) => {
  const { message } = req.body;
  if (!message || message.trim().length === 0) return res.status(400).json({ error: 'Tomt meddelande' });
  if (message.length > 500) return res.status(400).json({ error: 'För långt' });
  const result = db.prepare(`INSERT INTO chat (username, message) VALUES (?, ?)`).run(req.user.username, message.trim());
  // Push to everyone except sender
  sendPushToAll({
    title: `💬 ${req.user.username}`,
    body: message.trim().substring(0, 100),
    tag: 'chat',
    url: '/?tab=chatt'
  }, req.user.username);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.delete('/api/chat/:id', requireAuth, (req, res) => {
  if (!req.user.isLeader) return res.status(403).json({ error: 'Endast teamleader' });
  db.prepare(`DELETE FROM chat WHERE id=?`).run(parseInt(req.params.id));
  res.json({ ok: true });
});

app.get('/api/presence', requireAuth, (req, res) => {
  const users = db.prepare(`SELECT username, last_seen FROM users ORDER BY username`).all();
  const presMap = {};
  db.prepare(`SELECT username, status FROM presence`).all()
    .forEach(r => presMap[r.username] = r.status);
  const result = users.map(u => ({
    username: u.username,
    status: presMap[u.username] || 'på plats',
    last_seen: u.last_seen || null
  }));
  res.json(result);
});

// ── Heartbeat ─────────────────────────────────────────────────────────────────
app.post('/api/heartbeat', requireAuth, (req, res) => {
  db.prepare(`UPDATE users SET last_seen=datetime('now') WHERE username=?`).run(req.user.username);
  res.json({ ok: true });
});

app.post('/api/presence', requireAuth, (req, res) => {
  const { username, status } = req.body;
  // Only self or leader can update
  if (username !== req.user.username && !req.user.isLeader)
    return res.status(403).json({ error: 'Ej tillåtet' });
  const allowed = ['på plats', 'sjuk', 'ledigt'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Ogiltig status' });
  db.prepare(`INSERT INTO presence (username, status, updated) VALUES (?,?,datetime('now'))
    ON CONFLICT(username) DO UPDATE SET status=excluded.status, updated=excluded.updated`)
    .run(username, status);
  res.json({ ok: true });
});

// ── Notes ─────────────────────────────────────────────────────────────────────
app.get('/api/notes/:omrade/:day', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT idx, note, by_user, updated FROM notes WHERE omrade=? AND day=?'
  ).all(parseInt(req.params.omrade), req.params.day);
  res.json(rows);
});

app.post('/api/notes', requireAuth, (req, res) => {
  const { omrade, day, idx, note } = req.body;
  if (typeof note !== 'string') return res.status(400).json({ error: 'Saknar note' });
  const trimmed = note.trim().substring(0, 300);
  if (trimmed.length === 0) {
    db.prepare(`DELETE FROM notes WHERE omrade=? AND day=? AND idx=?`)
      .run(parseInt(omrade), day, parseInt(idx));
  } else {
    db.prepare(`
      INSERT INTO notes (omrade, day, idx, note, by_user, updated)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(omrade, day, idx) DO UPDATE SET
        note=excluded.note, by_user=excluded.by_user, updated=excluded.updated
    `).run(parseInt(omrade), day, parseInt(idx), trimmed, req.user.username);
  }
  res.json({ ok: true });
});

app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`🚛 Karolinska Truckers körs på port ${PORT}`));
