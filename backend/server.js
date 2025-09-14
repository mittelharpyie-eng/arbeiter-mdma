import express from 'express';
import cors from 'cors';
import sqlite from 'better-sqlite3';

const app = express();
const db = sqlite('database.db');

app.use(cors());
app.use(express.json());

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )
`).run();

function ensureMaster() {
  const existing = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
  if (!existing) {
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run('admin', 'admin123', 'admin');
    console.log('✅ Master-User "admin" wurde erstellt. Passwort: admin123');
  }
}

ensureMaster();

app.get('/', (req, res) => {
  res.send('API läuft');
});

app.listen(10000, () => {
  console.log('🚀 Server läuft auf http://localhost:10000');
});
