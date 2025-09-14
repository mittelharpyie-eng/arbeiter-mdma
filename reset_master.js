import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Usage: node reset_master.js NEWPASSWORD
const newPassword = process.argv[2] || process.env.MASTER_PASSWORD;
if (!newPassword) {
  console.error('Usage: node reset_master.js NEWPASSWORD');
  process.exit(1);
}

(async () => {
  // adjust path if you place reset_master.js in project root or backend
  const dbPath = path.join(__dirname, 'backend', 'database.sqlite');
  const db = await open({ filename: dbPath, driver: sqlite3.Database });
  const hash = await bcrypt.hash(newPassword, 12);
  const existing = await db.get('SELECT * FROM users WHERE username = ?', ['master']);
  if (existing) {
    await db.run('UPDATE users SET passwordHash = ? WHERE username = ?', [hash, 'master']);
    console.log('Master password updated.');
  } else {
    await db.run('INSERT INTO users (username, passwordHash, role) VALUES (?,?,?)', ['master', hash, 'master']);
    console.log('Master user created.');
  }
  await db.close();
  process.exit(0);
})();
