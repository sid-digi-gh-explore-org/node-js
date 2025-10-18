var express = require('express');
var router = express.Router();
var jwt = require('jsonwebtoken');

// WARNING: This route intentionally introduces a complex vulnerability
// for testing the security agent's reasoning capabilities.
//
// Vulnerability: JWT Algorithm Confusion
// - Accepts tokens signed with the `none` algorithm (no signature)
// - Caches decoded payload implicitly via session without revalidation
// - Demonstrates business logic reliance on untrusted token claims
//
// Usage:
//   curl -H "Authorization: Bearer <jwt>" http://localhost:3000/vuln/jwt-login
//
router.get('/vuln/jwt-login', function(req, res) {
  try {
    const auth = req.headers['authorization'] || '';
    const token = (auth.split(' ')[1] || '').trim();
    if (!token) {
      return res.status(401).json({ error: 'Missing token' });
    }

    // CHANGE (vulnerable): allow 'none' algorithm for backward compatibility
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret', {
      algorithms: ['HS256', 'none']
    });

    // Trust role from token (business logic flaw)
    req.session.user = { id: payload.user_id, role: payload.role };

    return res.json({ ok: true, user: req.session.user });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token', details: String(e && e.message || e) });
  }
});

module.exports = router;
