const assert = require('node:assert');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

test('should hash and verify a password', () => {
  const password = 'TestPassword123!';
  const hash = bcrypt.hashSync(password, 10);
  assert.ok(bcrypt.compareSync(password, hash));
});

test('should sign and verify a JWT payload', () => {
  const secret = 'test-secret';
  const payload = { userId: 1, email: 'user@example.com', role: 'regular' };
  const token = jwt.sign(payload, secret, { expiresIn: '1h' });
  const decoded = jwt.verify(token, secret);
  assert.strictEqual(decoded.email, payload.email);
  assert.strictEqual(decoded.role, payload.role);
});
