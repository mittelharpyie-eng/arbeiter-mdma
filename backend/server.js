import express from 'express';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import bcrypt from "bcryptjs";
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Zu viele Login-Versuche. Bitte später erneut versuchen.' }
});

// Open DB (file: backend/database.sqlite)
const db = await open({
  filename: path.join(__dirname, 'database.sqlite'),
  driver: sqlite3.Database
});

// Create tables if missing
await db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  passwordHash TEXT,
  role TEXT,
  createdAt TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS akten (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  vorname TEXT,
  geburtstag TEXT,
  zugehoerigkeit TEXT,
  arbeiterVon TEXT,
  passwort TEXT,
  bild TEXT,
  notizen TEXT,
  createdAt TEXT DEFAULT (datetime('now'))
);
`);

// Ensure master user exists (creates only if missing)
async function ensureMasterUser() {
  const master = await db.get('SELECT * FROM users WHERE username = ?', ['master']);
  if (!master) {
    if (!process.env.MASTER_PASSWORD) {
      console.warn('WARN: MASTER_PASSWORD not set in .env — run reset_master.js to set a password.');
      return;
    }
    const hash = await bcrypt.hash(process.env.MASTER_PASSWORD, 12);
    await db.run('INSERT INTO users (username, passwordHash, role) VALUES (?, ?, ?)', ['master', hash, 'master']);
    console.log('Master user created: username=master');
  } else {
    console.log('Master user already exists');
  }
}
await ensureMasterUser();

// Auth helpers
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Nicht eingeloggt' });
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) return res.status(401).json({ error: 'Nicht eingeloggt' });
    if (req.session.user.role !== role) return res.status(403).json({ error: 'Kein Zugriff' });
    next();
  };
}

// Login
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Fehlende Felder' });
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  if (!user) return res.status(401).json({ error: 'Ungültige Zugangsdaten' });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Ungültige Zugangsdaten' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ success: true, role: user.role, username: user.username });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Who am I
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// Accounts (master)
app.get('/api/accounts', requireRole('master'), async (_req, res) => {
  const rows = await db.all('SELECT id, username, role, createdAt FROM users ORDER BY id DESC');
  res.json({ accounts: rows });
});
app.post('/api/accounts', requireRole('master'), async (req, res) => {
  const { username, password, role } = req.body;
  const allowed = ['master', 'search', 'entry', 'worker'];
  if (!username || !password || !role || !allowed.includes(role)) return res.status(400).json({ error: 'Ungültige Eingabe' });
  const exists = await db.get('SELECT 1 FROM users WHERE username = ?', [username]);
  if (exists) return res.status(409).json({ error: 'Benutzer existiert bereits' });
  const passwordHash = await bcrypt.hash(password, 12);
  await db.run('INSERT INTO users (username, passwordHash, role) VALUES (?,?,?)', [username, passwordHash, role]);
  res.json({ success: true });
});
app.delete('/api/accounts/:id', requireRole('master'), async (req, res) => {
  const { id } = req.params;
  await db.run('DELETE FROM users WHERE id = ? AND username != "master"', [id]);
  res.json({ success: true });
});

// Akten
app.post('/api/akten', requireAuth, async (req, res) => {
  const role = req.session.user.role;
  if (!['entry', 'master', 'worker'].includes(role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  const { name, vorname, geburtstag, zugehoerigkeit, arbeiterVon, passwort, bild, notizen } = req.body;
  if (!name || !vorname || !geburtstag) return res.status(400).json({ error: 'Name, Vorname und Geburtstag sind Pflicht' });
  await db.run(`INSERT INTO akten (name, vorname, geburtstag, zugehoerigkeit, arbeiterVon, passwort, bild, notizen) VALUES (?,?,?,?,?,?,?,?)`,
    [name, vorname, geburtstag, zugehoerigkeit||'', arbeiterVon||'', passwort||'', bild||'', notizen||'']);
  res.json({ success: true });
});

app.get('/api/akten/uebersicht', requireRole('master'), async (_req, res) => {
  const akten = await db.all('SELECT id, name, vorname, geburtstag, zugehoerigkeit, arbeiterVon, passwort, notizen, createdAt FROM akten ORDER BY id DESC');
  res.json({ akten });
});

app.post('/api/akten/suche', requireAuth, async (req, res) => {
  const { name, vorname, geburtstag, aktePasswort } = req.body;
  if (!name || !vorname || !geburtstag) return res.status(400).json({ error: 'Alle Felder ausfüllen' });
  const akte = await db.get('SELECT * FROM akten WHERE name=? AND vorname=? AND geburtstag=?', [name, vorname, geburtstag]);
  if (!akte) return res.status(404).json({ error: 'Keine Akte gefunden' });
  if (akte.passwort && akte.passwort !== aktePasswort) return res.status(403).json({ error: 'Falsches Akten-Passwort' });
  res.json({ akte });
});

app.post('/api/akten/:id/updateNotizen', requireRole('master'), async (req, res) => {
  const { id } = req.params;
  const { notizen } = req.body;
  await db.run('UPDATE akten SET notizen=? WHERE id=?', [notizen, id]);
  res.json({ success: true });
});

// Serve frontend (static files)
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

app.listen(PORT, () => console.log(`Server läuft auf http://localhost:${PORT}`));
