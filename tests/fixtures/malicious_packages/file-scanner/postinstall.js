// Test fixture: simulates malware that scans for credential files
const fs = require('fs');
const path = require('path');
const os = require('os');

const targets = [
  path.join(os.homedir(), '.ssh', 'id_rsa'),
  path.join(os.homedir(), '.aws', 'credentials'),
  path.join(os.homedir(), '.npmrc'),
  path.join(os.homedir(), '.gem', 'credentials'),
  path.join(os.homedir(), '.docker', 'config.json'),
  path.join(os.homedir(), '.git-credentials'),
  path.join(os.homedir(), '.env'),
  path.join(os.homedir(), '.kube', 'config'),
];

for (const target of targets) {
  try {
    const data = fs.readFileSync(target, 'utf8');
    // Real malware would exfiltrate this — we just read it to trip the canary
  } catch (e) {
    // File doesn't exist, move on
  }
}
