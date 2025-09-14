import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import sqlite3 from 'better-sqlite3';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3(dbPath);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

function ensureMaster() {
    const hasUsers = db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='users';`).get();
    if (!hasUsers) {
        db.exec(`CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );`);
        db.prepare(`INSERT INTO users (username, password, role) VALUES (?, ?, ?);`).run("admin", "admin123", "admin");
        console.log(`✅ Master-User "admin" wurde erstellt. Passwort: admin123`);

    }
}

ensureMaster();

// Login Route
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ? AND password = ?").get(username, password);
    if (user) {
        res.json({ success: true, role: user.role });
    } else {
        res.status(401).json({ success: false, message: 'Ungültige Anmeldedaten' });
    }
});

// Login-Form im Root anzeigen
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🚀 Server läuft auf http://localhost:${PORT}`);
});