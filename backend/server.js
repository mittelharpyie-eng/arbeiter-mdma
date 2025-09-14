
import express from 'express';
import fs from 'fs';
import path from 'path';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET = 'supersecret';

const usersPath = path.join(__dirname, '../data/users.json');
const recordsPath = path.join(__dirname, '../data/records.json');

app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../frontend')));

// Multer für PNG Uploads
const upload = multer({ dest: path.join(__dirname, '../uploads') });

// Initialdaten sicherstellen
if (!fs.existsSync(usersPath)) fs.writeFileSync(usersPath, '[]');
if (!fs.existsSync(recordsPath)) fs.writeFileSync(recordsPath, '[]');

// Master-User erzeugen (admin/admin123)
const users = JSON.parse(fs.readFileSync(usersPath));
if (!users.find(u => u.username === 'admin')) {
  users.push({ username: 'admin', password: 'admin123', role: 'admin' });
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  console.log('✅ Master-User "admin" wurde erstellt. Passwort: admin123');
}

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const users = JSON.parse(fs.readFileSync(usersPath));
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ username: user.username, role: user.role }, SECRET, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true }).json({ message: 'Logged in' });
});

// Auth Middleware
function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (e) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// Benutzerliste (Admin)
app.get('/api/users', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const users = JSON.parse(fs.readFileSync(usersPath));
  res.json(users);
});

// Neue Benutzer anlegen (Admin)
app.post('/api/users', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  const users = JSON.parse(fs.readFileSync(usersPath));
  users.push(req.body);
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2));
  res.json({ message: 'User created' });
});

// Akten speichern (Entry-Rolle)
app.post('/api/records', authenticate, (req, res) => {
  if (req.user.role !== 'entry') return res.status(403).json({ message: 'Forbidden' });
  const records = JSON.parse(fs.readFileSync(recordsPath));
  records.push(req.body);
  fs.writeFileSync(recordsPath, JSON.stringify(records, null, 2));
  res.json({ message: 'Record saved' });
});

// Akten suchen (Search-Rolle)
app.get('/api/records', authenticate, (req, res) => {
  if (req.user.role !== 'search') return res.status(403).json({ message: 'Forbidden' });
  const records = JSON.parse(fs.readFileSync(recordsPath));
  res.json(records);
});

// PNG Upload
app.post('/api/upload', authenticate, upload.single('image'), (req, res) => {
  res.json({ filename: req.file.filename });
});

// Weiterleitung Root → Login
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

app.listen(PORT, () => {
  console.log(`🚀 Server läuft auf http://localhost:${PORT}`);
});
