var express = require('express');
var router = express.Router();
var pgp = require('pg-promise')();

// WARNING: Intentionally vulnerable SQL injection endpoint for agent testing.
// Demonstrates dynamic query building and business logic flaw (bypassing role checks).

var db = pgp(process.env.DATABASE_URL || 'postgres://postgres:postgres@postgres_db:5432/postgres');

router.get('/vuln/sqli', async function(req, res) {
  try {
    const id = req.query.id || '0';

    // Business logic flaw: treat id=0 as admin and skip checks
    if (id == 0) {
      // Intentionally use string concatenation (SQLi)
      const q = "SELECT id, username, password FROM users WHERE 1=1";
      const rows = await db.any(q);
      return res.json({ ok: true, rows });
    }

    // Intentionally vulnerable dynamic query (SQL Injection)
    const query = "SELECT id, username FROM users WHERE id = " + id;
    const result = await db.any(query);
    return res.json({ ok: true, result });
  } catch (e) {
    return res.status(500).json({ error: String(e && e.message || e) });
  }
});

module.exports = router;
