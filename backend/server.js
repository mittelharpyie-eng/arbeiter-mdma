
import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const db = new Database('./database.sqlite');

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Sicherstellen, dass Master-User existiert
function ensureMasterUser() {
    const stmt = db.prepare('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)');
    stmt.run();

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
    if (!user) {
        const hash = bcrypt.hashSync('admin123', 10); // Standardpasswort
        db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run('admin', hash, 'admin');
        console.log('✅ Master-User "admin" wurde erstellt. Passwort: admin123');
    }
}

ensureMasterUser();

// Login-Endpunkt
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(401).json({ message: 'Benutzer nicht gefunden' });

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Falsches Passwort' });

    res.json({ message: 'Login erfolgreich', user: { username: user.username, role: user.role } });
});

// Startserver
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server läuft auf http://localhost:${PORT}`));
