const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

require('dotenv').config();

const PORT = process.env.AUTH_PORT || 4001;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'auth.db');
const JWT_SECRET = process.env.JWT_SECRET || 'replace-with-secure-secret';
const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

const db = new sqlite3.Database(DB_FILE);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function initializeDatabase() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  const admin = await get('SELECT * FROM users WHERE email = ?', ['admin@example.com']);
  if (!admin) {
    const passwordHash = bcrypt.hashSync('Admin123!', 10);
    await run(
      'INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
      ['admin@example.com', passwordHash, 'super_admin', new Date().toISOString()]
    );
    console.log('Created default super_admin user: admin@example.com / Admin123!');
  }
}

function signAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}

async function createRefreshToken(userId, sessionId) {
  const token = crypto.randomBytes(48).toString('hex');
  const expiresAt = Date.now() + parseDuration(REFRESH_TOKEN_EXPIRES_IN);
  await run(
    'INSERT INTO refresh_tokens (token, user_id, session_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
    [token, userId, sessionId, expiresAt, new Date().toISOString()]
  );
  return token;
}

function parseDuration(value) {
  if (typeof value === 'number') return value;
  const match = /^([0-9]+)([smhd])$/.exec(value);
  if (!match) return 0;
  const amount = Number(match[1]);
  const unit = match[2];
  switch (unit) {
    case 's': return amount * 1000;
    case 'm': return amount * 60 * 1000;
    case 'h': return amount * 60 * 60 * 1000;
    case 'd': return amount * 24 * 60 * 60 * 1000;
    default: return 0;
  }
}

async function findUserByEmail(email) {
  return get('SELECT * FROM users WHERE email = ?', [email]);
}

async function findRefreshToken(token) {
  return get('SELECT * FROM refresh_tokens WHERE token = ?', [token]);
}

async function deleteRefreshToken(token) {
  return run('DELETE FROM refresh_tokens WHERE token = ?', [token]);
}

async function deleteRefreshTokensBySession(sessionId) {
  return run('DELETE FROM refresh_tokens WHERE session_id = ?', [sessionId]);
}

const app = express();
app.use(cors());
app.use(express.json());

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const user = await findUserByEmail(email.toLowerCase());
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const sessionId = crypto.randomUUID();
    const accessToken = signAccessToken({ userId: user.id, email: user.email, role: user.role, sessionId });
    const refreshToken = await createRefreshToken(user.id, sessionId);

    return res.json({
      user: { id: user.id, email: user.email, role: user.role },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Could not sign in.' });
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required.' });
  }

  try {
    const stored = await findRefreshToken(refreshToken);
    if (!stored || stored.expires_at < Date.now()) {
      return res.status(401).json({ message: 'Refresh token is invalid or expired.' });
    }

    const user = await get('SELECT * FROM users WHERE id = ?', [stored.user_id]);
    if (!user) {
      await deleteRefreshToken(refreshToken);
      return res.status(401).json({ message: 'Invalid refresh session.' });
    }

    await deleteRefreshToken(refreshToken);
    const newRefreshToken = await createRefreshToken(user.id, stored.session_id);
    const accessToken = signAccessToken({ userId: user.id, email: user.email, role: user.role, sessionId: stored.session_id });

    return res.json({
      user: { id: user.id, email: user.email, role: user.role },
      accessToken,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Could not refresh the session.' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required.' });
  }

  try {
    await deleteRefreshToken(refreshToken);
    return res.json({ message: 'Logged out successfully.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Could not log out.' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Auth service listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to initialize auth service database:', error);
    process.exit(1);
  });
