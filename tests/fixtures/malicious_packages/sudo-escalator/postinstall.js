// Test fixture: simulates malware that attempts privilege escalation
const { execSync } = require('child_process');

// Try sudo to read /etc/shadow
try {
  execSync('sudo cat /etc/shadow', { stdio: 'pipe' });
} catch (e) {}

// Try sudo to install a backdoor
try {
  execSync('sudo bash -c "echo backdoor >> /etc/crontab"', { stdio: 'pipe' });
} catch (e) {}

// Try sudo to change permissions
try {
  execSync('sudo chmod 777 /etc/passwd', { stdio: 'pipe' });
} catch (e) {}
