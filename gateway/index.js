const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fetch = global.fetch;
const path = require('path');
require('dotenv').config();

const PORT = process.env.GATEWAY_PORT || 4000;
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://auth:4001';
const IP_SERVICE_URL = process.env.IP_SERVICE_URL || 'http://ip:4002';
const AUDIT_SECRET = process.env.AUDIT_SECRET || 'replace-with-audit-secret';
const JWT_SECRET = process.env.JWT_SECRET || 'replace-with-secure-secret';

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

function parseBearerToken(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return null;
  const [scheme, token] = headerValue.split(' ');
  return scheme === 'Bearer' ? token : null;
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

async function forwardRequest(target, req, res, extraHeaders = {}) {
  const url = `${target}${req.originalUrl}`;
  const init = {
    method: req.method,
    headers: {
      'Content-Type': 'application/json',
      ...extraHeaders,
      ...req.headers,
    },
    body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body),
  };

  delete init.headers.host;
  delete init.headers.origin;

  const response = await fetch(url, init);
  const body = await response.text();
  res.status(response.status);
  try {
    res.json(JSON.parse(body));
  } catch {
    res.send(body);
  }
}

async function sendAuditEvent(event) {
  try {
    await fetch(`${IP_SERVICE_URL}/api/audit/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-audit-secret': AUDIT_SECRET,
      },
      body: JSON.stringify(event),
    });
  } catch (error) {
    console.error('Failed to send audit event:', error);
  }
}

app.post('/api/auth/login', async (req, res) => {
  const response = await fetch(`${AUTH_SERVICE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req.body),
  });

  const payload = await response.json();
  if (!response.ok) {
    return res.status(response.status).json(payload);
  }

  const token = parseBearerToken(`Bearer ${payload.accessToken}`);
  const claims = verifyToken(token);
  if (claims) {
    await sendAuditEvent({
      eventType: 'LOGIN',
      actorUserId: claims.userId,
      actorEmail: claims.email,
      sessionId: claims.sessionId,
      targetType: 'USER',
      targetId: claims.userId,
      details: 'User logged in',
    });
  }

  res.json(payload);
});

app.post('/api/auth/refresh', async (req, res) => {
  await forwardRequest(AUTH_SERVICE_URL, req, res);
});

app.post('/api/auth/logout', async (req, res) => {
  const response = await fetch(`${AUTH_SERVICE_URL}/api/auth/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req.body),
  });

  const payload = await response.json();
  if (!response.ok) {
    return res.status(response.status).json(payload);
  }

  const token = parseBearerToken(req.headers.authorization);
  const claims = verifyToken(token);
  await sendAuditEvent({
    eventType: 'LOGOUT',
    actorUserId: claims?.userId || null,
    actorEmail: claims?.email || null,
    sessionId: claims?.sessionId || null,
    targetType: 'USER',
    targetId: claims?.userId || null,
    details: 'User logged out',
  });

  return res.json(payload);
});

app.use('/api/ips', async (req, res) => {
  const token = parseBearerToken(req.headers.authorization);
  if (!token) {
    return res.status(401).json({ message: 'Authorization token required.' });
  }

  const claims = verifyToken(token);
  if (!claims) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }

  await forwardRequest(IP_SERVICE_URL, req, res, {
    Authorization: `Bearer ${token}`,
  });
});

app.use('/api/audit', async (req, res) => {
  const token = parseBearerToken(req.headers.authorization);
  if (!token) {
    return res.status(401).json({ message: 'Authorization token required.' });
  }

  const claims = verifyToken(token);
  if (!claims) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }

  if (claims.role !== 'super_admin') {
    return res.status(403).json({ message: 'Super admin role required.' });
  }

  await forwardRequest(IP_SERVICE_URL, req, res, {
    Authorization: `Bearer ${token}`,
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Gateway listening on port ${PORT}`);
});
