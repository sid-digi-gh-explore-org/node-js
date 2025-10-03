var express = require('express');
var router = express.Router();
var unzipper = require('unzipper');
var fs = require('fs');
var path = require('path');

// UNSAFE: Zip Slip extraction (entry.path not sanitized)
router.post('/vuln/upload-zip', function(req, res) {
  var outDir = path.join(__dirname, '..', 'uploads');
  try {
    req.pipe(unzipper.Parse())
      .on('entry', function(entry) {
        var filePath = path.join(outDir, entry.path); // vulnerable to ../ in entry.path
        entry.pipe(fs.createWriteStream(filePath));
      })
      .on('finish', function(){ res.send('ok'); })
      .on('error', function(){ res.status(500).send('error'); });
  } catch (e) {
    res.status(400).send('bad zip');
  }
});

module.exports = router;