const assert = require('node:assert');
const net = require('node:net');

describe('IP validation', () => {
  it('should recognize valid IPv4 addresses', () => {
    assert.strictEqual(net.isIP('192.168.1.1'), 4);
  });

  it('should recognize valid IPv6 addresses', () => {
    assert.strictEqual(net.isIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), 6);
  });

  it('should reject invalid IP addresses', () => {
    assert.strictEqual(net.isIP('not-an-ip'), 0);
  });
});
