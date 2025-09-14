// backend/server.js
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const db = new Database('./database.sqlite3');

// Tabellen erstellen, falls nicht vorhanden
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )
`).run();

// Master-Admin erzeugen, falls noch keiner existiert
function ensureMaster() {
  const exists = db.prepare(`SELECT COUNT(*) AS count FROM users WHERE username = 'admin'`).get();
  if (exists.count === 0) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.prepare(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`)
      .run('admin', hashedPassword, 'admin');
    console.log('✅ Master-User "admin" wurde erstellt. Passwort: admin123');
  }
}
ensureMaster();

// Authentifizierung
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (user && bcrypt.compareSync(password, user.password)) {
    res.json({ success: true, role: user.role });
  } else {
    res.status(401).json({ success: false, message: 'Ungültige Anmeldedaten' });
  }
});

// Benutzerliste (Admin-only)
app.get('/api/users', (req, res) => {
  const users = db.prepare('SELECT id, username, role FROM users').all();
  res.json(users);
});

// Benutzer erstellen
app.post('/api/users', (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)')
      .run(username, hashedPassword, role || 'user');
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// 🆕 Route für `/` → zeigt index.html im Frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(port, () => {
  console.log(`🚀 Server läuft auf http://localhost:${port}`);
});
