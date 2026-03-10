const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'truckers-secret-change-in-prod';

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

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Ej inloggad' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user.isLeader = TEAMLEADERS.includes(req.user.username.toLowerCase());
    next();
  } catch { res.status(401).json({ error: 'Ogiltig token' }); }
}

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

app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`🚛 Karolinska Truckers körs på port ${PORT}`));
