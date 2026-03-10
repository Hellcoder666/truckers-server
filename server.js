const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'truckers-secret-change-in-prod';

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Databas ─────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'truckers.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    password  TEXT NOT NULL,
    created   TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS status (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    omrade    INTEGER NOT NULL,
    day       TEXT NOT NULL,
    idx       INTEGER NOT NULL,
    state     TEXT NOT NULL DEFAULT 'none',  -- 'none' | 'pagaende' | 'done'
    by_user   TEXT,
    updated   TEXT DEFAULT (datetime('now')),
    UNIQUE(omrade, day, idx)
  );
`);

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Ej inloggad' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Ogiltig token' });
  }
}

// ─── Auth endpoints ───────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 2 || password.length < 4) {
    return res.status(400).json({ error: 'Ogiltigt användarnamn eller lösenord (min 2 resp 4 tecken)' });
  }
  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    stmt.run(username.trim(), hash);
    const token = jwt.sign({ username: username.trim() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: username.trim() });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      res.status(409).json({ error: 'Användarnamnet är redan taget' });
    } else {
      res.status(500).json({ error: 'Serverfel' });
    }
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username?.trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Fel användarnamn eller lösenord' });
  }
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

// ─── Status endpoints ─────────────────────────────────────────────────────────
// GET all statuses for a given omrade + day
app.get('/api/status/:omrade/:day', requireAuth, (req, res) => {
  const { omrade, day } = req.params;
  const rows = db.prepare(
    'SELECT idx, state, by_user, updated FROM status WHERE omrade=? AND day=?'
  ).all(parseInt(omrade), day);
  res.json(rows);
});

// POST update a single item status
app.post('/api/status', requireAuth, (req, res) => {
  const { omrade, day, idx, state } = req.body;
  const by_user = state === 'none' ? null : req.user.username;

  const validStates = ['none', 'pagaende', 'done'];
  if (!validStates.includes(state)) {
    return res.status(400).json({ error: 'Ogiltigt state' });
  }

  db.prepare(`
    INSERT INTO status (omrade, day, idx, state, by_user, updated)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(omrade, day, idx) DO UPDATE SET
      state=excluded.state,
      by_user=excluded.by_user,
      updated=excluded.updated
  `).run(parseInt(omrade), day, parseInt(idx), state, by_user);

  res.json({ ok: true });
});

// GET all users (för admin-ändamål, kräver auth)
app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id, username, created FROM users ORDER BY created DESC').all();
  res.json(users);
});

// ─── Fallback: serve index.html ───────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`🚛 Karolinska Truckers körs på port ${PORT}`));
