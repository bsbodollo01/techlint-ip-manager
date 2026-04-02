const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const fs = require('fs');
const path = require('path');
const net = require('net');
require('dotenv').config();

const PORT = process.env.IP_PORT || 4002;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'ip.db');
const JWT_SECRET = process.env.JWT_SECRET || 'replace-with-secure-secret';
const AUDIT_SECRET = process.env.AUDIT_SECRET || 'replace-with-audit-secret';

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
  await run(`CREATE TABLE IF NOT EXISTS ip_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    label TEXT NOT NULL,
    comment TEXT,
    owner_user_id INTEGER NOT NULL,
    owner_email TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_user_id INTEGER,
    actor_email TEXT,
    session_id TEXT,
    target_type TEXT NOT NULL,
    target_id INTEGER,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing authorization header.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

function isSuperAdmin(req) {
  return req.user && req.user.role === 'super_admin';
}

function validateIp(ip) {
  return net.isIP(ip) !== 0;
}

async function createAudit(event) {
  const { eventType, actorUserId, actorEmail, sessionId, targetType, targetId, details } = event;
  return run(
    'INSERT INTO audit_logs (event_type, actor_user_id, actor_email, session_id, target_type, target_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [eventType, actorUserId || null, actorEmail || null, sessionId || null, targetType, targetId || null, details, new Date().toISOString()]
  );
}

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

app.post('/api/ips', verifyToken, async (req, res) => {
  const { ip, label, comment } = req.body || {};
  if (!ip || !label) {
    return res.status(400).json({ message: 'IP address and label are required.' });
  }
  if (!validateIp(ip)) {
    return res.status(400).json({ message: 'Invalid IP address.' });
  }

  try {
    const result = await run(
      'INSERT INTO ip_records (ip, label, comment, owner_user_id, owner_email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [ip, label, comment || '', req.user.userId, req.user.email, new Date().toISOString(), new Date().toISOString()]
    );

    const recordId = result.lastID;
    await createAudit({
      eventType: 'IP_CREATED',
      actorUserId: req.user.userId,
      actorEmail: req.user.email,
      sessionId: req.user.sessionId,
      targetType: 'IP',
      targetId: recordId,
      details: `Created IP ${ip} with label ${label}`,
    });

    const record = await get('SELECT * FROM ip_records WHERE id = ?', [recordId]);
    res.status(201).json(record);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Could not create IP record.' });
  }
});

app.get('/api/ips', verifyToken, async (req, res) => {
  try {
    const records = await all('SELECT * FROM ip_records ORDER BY created_at DESC', []);
    res.json(records);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Could not load IP records.' });
  }
});

app.patch('/api/ips/:id', verifyToken, async (req, res) => {
  const { label } = req.body || {};
  const id = Number(req.params.id);
  if (!label || !id) {
    return res.status(400).json({ message: 'Label and valid ID are required.' });
  }

  try {
    const record = await get('SELECT * FROM ip_records WHERE id = ?', [id]);
    if (!record) {
      return res.status(404).json({ message: 'IP record not found.' });
    }

    if (record.owner_user_id !== req.user.userId && !isSuperAdmin(req)) {
      return res.status(403).json({ message: 'Not allowed to edit this IP record.' });
    }

    await run('UPDATE ip_records SET label = ?, updated_at = ? WHERE id = ?', [label, new Date().toISOString(), id]);
    await createAudit({
      eventType: 'IP_UPDATED',
      actorUserId: req.user.userId,
      actorEmail: req.user.email,
      sessionId: req.user.sessionId,
      targetType: 'IP',
      targetId: id,
      details: `Updated label to ${label}`,
    });

    const updatedRecord = await get('SELECT * FROM ip_records WHERE id = ?', [id]);
    res.json(updatedRecord);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Could not update IP record.' });
  }
});

app.delete('/api/ips/:id', verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!id) {
    return res.status(400).json({ message: 'Valid ID is required.' });
  }

  if (!isSuperAdmin(req)) {
    return res.status(403).json({ message: 'Only super admins can delete IP records.' });
  }

  try {
    const record = await get('SELECT * FROM ip_records WHERE id = ?', [id]);
    if (!record) {
      return res.status(404).json({ message: 'IP record not found.' });
    }

    await run('DELETE FROM ip_records WHERE id = ?', [id]);
    await createAudit({
      eventType: 'IP_DELETED',
      actorUserId: req.user.userId,
      actorEmail: req.user.email,
      sessionId: req.user.sessionId,
      targetType: 'IP',
      targetId: id,
      details: `Deleted IP ${record.ip}`,
    });

    res.json({ message: 'IP record deleted.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Could not delete IP record.' });
  }
});

app.get('/api/audit', verifyToken, async (req, res) => {
  if (!isSuperAdmin(req)) {
    return res.status(403).json({ message: 'Super admin role required.' });
  }

  try {
    const logs = await all('SELECT * FROM audit_logs ORDER BY created_at DESC', []);
    res.json(logs);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Could not load audit logs.' });
  }
});

app.post('/api/audit/events', async (req, res) => {
  const auditSecret = req.headers['x-audit-secret'];
  if (auditSecret !== AUDIT_SECRET) {
    return res.status(403).json({ message: 'Audit secret is required.' });
  }

  const event = req.body || {};
  if (!event.eventType || !event.targetType || !event.details) {
    return res.status(400).json({ message: 'Invalid audit event payload.' });
  }

  try {
    await createAudit(event);
    res.status(201).json({ message: 'Audit event recorded.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Could not record audit event.' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`IP service listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to initialize IP service database:', error);
    process.exit(1);
  });
