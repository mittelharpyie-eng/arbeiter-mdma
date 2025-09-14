import express from 'express';
import fs from 'fs';
import path from 'path';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, '../frontend')));

const USERS_FILE = path.join(__dirname, '../data/users.json');
if (!fs.existsSync(USERS_FILE)) {
    fs.mkdirSync(path.join(__dirname, '../data'), { recursive: true });
    fs.writeFileSync(USERS_FILE, JSON.stringify([{
        username: 'admin',
        password: 'admin123',
        role: 'admin'
    }], null, 2));
}

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        const token = jwt.sign({ username: user.username, role: user.role }, 'secret', { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true }).json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.get('/', (req, res) => res.redirect('/login.html'));

app.listen(PORT, () => console.log(`🚀 Server läuft auf http://localhost:${PORT}`));