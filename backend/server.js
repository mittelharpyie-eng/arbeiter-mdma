import express from 'express';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;

// ---- DB ----
const db = new Database(path.join(__dirname, 'database.sqlite'));
db.pragma('journal_mode = WAL');

// create tables
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TEXT DEFAULT (datetime('now'))
  )
`).run();

// ensure master
function ensureMaster() {
  const masterPass = process.env.MASTER_PASSWORD || 'admin123';
  const has = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
  if (!has) {
    const hash = bcrypt.hashSync(masterPass, 10);
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run('admin', hash, 'admin');
    console.log('✅ Master-User "admin" angelegt.');
  }
}
ensureMaster();

// ---- middleware ----
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 // 1h
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Zu viele Login-Versuche. Bitte später erneut versuchen.' }
});
app.use('/api/login', loginLimiter);

// static
app.use(express.static(path.join(__dirname, '../frontend')));

// ---- auth helpers ----
function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ success: false, error: 'Nicht eingeloggt' });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ success: false, error: 'Nicht eingeloggt' });
    if (req.session.user.role !== role) return res.status(403).json({ success: false, error: 'Zugriff verweigert' });
    next();
  };
}

// ---- auth routes ----
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ success: false, error: 'Benutzer nicht gefunden' });
  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ success: false, error: 'Falsches Passwort' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ success: true, user: req.session.user });
});
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});
app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// ---- admin user management ----
app.get('/api/admin/users', requireRole('admin'), (req, res) => {
  const rows = db.prepare('SELECT id, username, role, created_at FROM users ORDER BY id ASC').all();
  res.json({ users: rows });
});

app.post('/api/admin/users', requireRole('admin'), (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ success: false, error: 'username, password, role erforderlich' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run(username, hash, role);
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ success: false, error: 'Benutzername bereits vergeben?' });
  }
});

app.patch('/api/admin/users/:id', requireRole('admin'), (req, res) => {
  const id = Number(req.params.id);
  const { role, password } = req.body;
  if (!Number.isInteger(id)) return res.status(400).json({ success: false, error: 'Ungültige ID' });

  if (role) {
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  }
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, id);
  }
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', requireRole('admin'), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ success: false, error: 'Ungültige ID' });
  // Admin sich selbst löschen verhindern
  if (req.session.user.id === id) return res.status(400).json({ success: false, error: 'Eigener Account kann nicht gelöscht werden' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ success: true });
});

// ---- gate pages by role (optional hard gates for direct access) ----
app.get('/admin.html', (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/login.html');
  next();
});

// ---- start ----
app.listen(PORT, () => {
  console.log(`🚀 Server läuft auf http://localhost:${PORT}`);
});
