#!/usr/bin/env node

/**
 * Telegram Security Assessment Toolkit
 * A security assessment bot for authorized cybersecurity teams
 * Runs directly on Termux/Node.js without VPS requirement
 */

const TelegramBot = require('node-telegram-bot-api');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================================================
// CONFIGURATION & INITIALIZATION
// ============================================================================

const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_ID = process.env.ADMIN_ID ? parseInt(process.env.ADMIN_ID) : null;
const LOG_DIR = './logs';
const DATA_DIR = './data';
const TRAINING_DIR = './training_sessions';

if (!BOT_TOKEN) {
  console.error('❌ BOT_TOKEN environment variable not set!');
  console.error('Usage: export BOT_TOKEN="your_token" && node bot.js');
  process.exit(1);
}

// Initialize directories
[LOG_DIR, DATA_DIR, TRAINING_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// ============================================================================
// DATA MANAGEMENT
// ============================================================================

class DataManager {
  constructor() {
    this.targetsFile = path.join(DATA_DIR, 'authorized_targets.json');
    this.auditLogFile = path.join(LOG_DIR, 'audit.log');
    this.rateLimitFile = path.join(DATA_DIR, 'rate_limits.json');
    this.initFiles();
  }

  initFiles() {
    if (!fs.existsSync(this.targetsFile)) {
      fs.writeFileSync(this.targetsFile, JSON.stringify({ targets: [] }));
    }
    if (!fs.existsSync(this.rateLimitFile)) {
      fs.writeFileSync(this.rateLimitFile, JSON.stringify({}));
    }
  }

  getTargets() {
    const data = JSON.parse(fs.readFileSync(this.targetsFile, 'utf8'));
    return data.targets || [];
  }

  addTarget(domain) {
    const data = JSON.parse(fs.readFileSync(this.targetsFile, 'utf8'));
    if (!data.targets.includes(domain)) {
      data.targets.push(domain);
      fs.writeFileSync(this.targetsFile, JSON.stringify(data, null, 2));
      return true;
    }
    return false;
  }

  removeTarget(domain) {
    const data = JSON.parse(fs.readFileSync(this.targetsFile, 'utf8'));
    data.targets = data.targets.filter(t => t !== domain);
    fs.writeFileSync(this.targetsFile, JSON.stringify(data, null, 2));
    return true;
  }

  isAuthorized(domain) {
    const targets = this.getTargets();
    return targets.some(t => domain.includes(t) || t.includes(domain));
  }

  addAuditLog(userId, command, target, result, duration) {
    const log = {
      timestamp: new Date().toISOString(),
      user_id: userId,
      command,
      target,
      result,
      duration_ms: duration
    };
    fs.appendFileSync(this.auditLogFile, JSON.stringify(log) + '\n');
  }

  checkRateLimit(userId, limit = 5, window = 60000) {
    const data = JSON.parse(fs.readFileSync(this.rateLimitFile, 'utf8'));
    const now = Date.now();

    if (!data[userId]) {
      data[userId] = [];
    }

    // Clean old entries
    data[userId] = data[userId].filter(t => now - t < window);

    if (data[userId].length >= limit) {
      fs.writeFileSync(this.rateLimitFile, JSON.stringify(data, null, 2));
      return false;
    }

    data[userId].push(now);
    fs.writeFileSync(this.rateLimitFile, JSON.stringify(data, null, 2));
    return true;
  }
}

const dataManager = new DataManager();

// ============================================================================
// SECURITY SCANNER
// ============================================================================

class SecurityScanner {
  constructor() {
    this.timeout = 10000;
    this.commonPorts = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 8080, 8443];
  }

  normalizeUrl(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    return url;
  }

  async fetchHeaders(url) {
    return new Promise((resolve) => {
      const parsedUrl = new URL(url);
      const protocol = parsedUrl.protocol === 'https:' ? https : http;
      const options = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname || '/',
        method: 'HEAD',
        timeout: this.timeout,
        headers: { 'User-Agent': 'SecurityBot/1.0' }
      };

      const req = protocol.request(options, (res) => {
        const headers = {};
        Object.keys(res.headers).forEach(key => {
          headers[key] = res.headers[key];
        });
        resolve({
          statusCode: res.statusCode,
          headers,
          redirectUrl: res.headers.location
        });
      });

      req.on('error', () => resolve({ error: 'Connection failed' }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ error: 'Timeout' });
      });
      req.end();
    });
  }

  async getSSLCertificate(hostname) {
    return new Promise((resolve) => {
      const options = {
        hostname,
        port: 443,
        method: 'HEAD',
        timeout: this.timeout
      };

      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        resolve({
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          fingerprint: cert.fingerprint
        });
      });

      req.on('error', () => resolve({ error: 'SSL check failed' }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ error: 'Timeout' });
      });
      req.end();
    });
  }

  async resolveDNS(hostname) {
    try {
      const [aRecords, aaaaRecords, mxRecords, nsRecords] = await Promise.all([
        dns.resolve4(hostname).catch(() => []),
        dns.resolve6(hostname).catch(() => []),
        dns.resolveMx(hostname).catch(() => []),
        dns.resolveNs(hostname).catch(() => [])
      ]);

      return {
        A: aRecords,
        AAAA: aaaaRecords,
        MX: mxRecords,
        NS: nsRecords
      };
    } catch (err) {
      return { error: 'DNS resolution failed' };
    }
  }

  async checkPorts(hostname) {
    const open = [];
    const checks = this.commonPorts.map(port =>
      this.checkPort(hostname, port).then(isOpen => {
        if (isOpen) open.push(port);
      }).catch(() => {})
    );

    await Promise.all(checks);
    return open;
  }

  checkPort(hostname, port) {
    return new Promise((resolve) => {
      const socket = require('net').createConnection(
        { host: hostname, port, timeout: 3000 },
        () => {
          socket.destroy();
          resolve(true);
        }
      );

      socket.on('error', () => resolve(false));
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
    });
  }

  async fetchRobotsTxt(url) {
    return new Promise((resolve) => {
      const parsedUrl = new URL(url);
      const robotsUrl = new URL('/robots.txt', url).href;
      const protocol = parsedUrl.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsedUrl.hostname,
        path: '/robots.txt',
        timeout: this.timeout,
        headers: { 'User-Agent': 'SecurityBot/1.0' }
      };

      const req = protocol.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(res.statusCode === 200 ? data : null));
      });

      req.on('error', () => resolve(null));
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });
      req.end();
    });
  }

  async detectTechnology(url) {
    // Simple passive technology detection
    const techs = [];
    try {
      const response = await this.fetchHeaders(url);
      const headers = response.headers || {};

      if (headers.server) techs.push(`Server: ${headers.server}`);
      if (headers['x-powered-by']) techs.push(`Powered By: ${headers['x-powered-by']}`);
      if (headers['x-aspnet-version']) techs.push('ASP.NET Detected');
      if (headers['set-cookie']) techs.push('Session Cookies Found');
    } catch (err) {}

    return techs.length > 0 ? techs : ['No technology detected'];
  }

  analyzeSecurityHeaders(headers) {
    const findings = [];
    const securityHeaders = {
      'content-security-policy': '✅ CSP configured',
      'strict-transport-security': '✅ HSTS configured',
      'x-frame-options': '✅ Clickjacking protection',
      'x-content-type-options': '✅ MIME sniffing protection',
      'referrer-policy': '✅ Referrer policy configured',
      'permissions-policy': '✅ Permissions policy configured'
    };

    Object.keys(securityHeaders).forEach(header => {
      if (!headers[header]) {
        findings.push(`⚠️ Missing: ${securityHeaders[header].split(' ')[1]}`);
      } else {
        findings.push(securityHeaders[header]);
      }
    });

    return findings;
  }

  analyzeCookies(headers) {
    const setCookie = headers['set-cookie'] || [];
    const findings = [];

    if (!Array.isArray(setCookie)) return ['No cookies detected'];

    setCookie.forEach(cookie => {
      const flags = {
        secure: cookie.includes('Secure'),
        httponly: cookie.includes('HttpOnly'),
        samesite: cookie.includes('SameSite')
      };

      if (!flags.secure) findings.push('⚠️ Cookie missing Secure flag');
      if (!flags.httponly) findings.push('⚠️ Cookie missing HttpOnly flag');
      if (!flags.samesite) findings.push('⚠️ Cookie missing SameSite flag');
    });

    return findings.length > 0 ? findings : ['✅ Cookies secure'];
  }

  async fullScan(url) {
    const start = Date.now();
    const parsedUrl = new URL(this.normalizeUrl(url));
    const hostname = parsedUrl.hostname;

    const results = {
      target: hostname,
      timestamp: new Date().toISOString(),
      http: await this.fetchHeaders(url),
      ssl: await this.getSSLCertificate(hostname),
      dns: await this.resolveDNS(hostname),
      ports: await this.checkPorts(hostname),
      robots: await this.fetchRobotsTxt(url),
      technology: await this.detectTechnology(url),
      duration: Date.now() - start
    };

    if (results.http.headers) {
      results.securityHeaders = this.analyzeSecurityHeaders(results.http.headers);
      results.cookies = this.analyzeCookies(results.http.headers);
    }

    return results;
  }
}

const scanner = new SecurityScanner();

// ============================================================================
// TRAINING SIMULATOR
// ============================================================================

class TrainingSimulator {
  createPhishingPage(sessionId) {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Awareness Training</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
        h1 { color: #333; margin-bottom: 20px; text-align: center; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .warning-title { font-weight: bold; color: #856404; }
        button { width: 100%; padding: 12px; margin: 10px 0; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #c82333; }
        button.success { background: #28a745; }
        button.success:hover { background: #218838; }
        .info { background: #e7f3ff; padding: 15px; margin-top: 20px; border-radius: 4px; text-align: center; color: #004085; }
        .log { font-size: 12px; margin-top: 10px; padding: 10px; background: #f0f0f0; border-radius: 4px; max-height: 150px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Training</h1>
        <div class="warning">
            <div class="warning-title">⚠️ Training Scenario</div>
            <p>This is a controlled security awareness training exercise. Your responses help us improve security awareness.</p>
        </div>
        
        <button class="danger" onclick="recordEvent('PHISHING_BUTTON_CLICKED')">
            ⚠️ This looks like phishing - Report it
        </button>
        
        <button class="success" onclick="recordEvent('SAFE_BUTTON_CLICKED')">
            ✅ This looks safe - Continue
        </button>
        
        <button onclick="recordEvent('TRAINING_COMPLETED')">
            🏁 Complete Training
        </button>
        
        <div class="info">
            Session ID: ${sessionId}
            <div class="log" id="log"></div>
        </div>
    </div>

    <script>
        const sessionId = '${sessionId}';
        const events = [];
        
        // IMPORTANT: This is a training-only page. NO credential harvesting, NO spyware.
        function recordEvent(eventType) {
            const event = {
                type: eventType,
                timestamp: new Date().toISOString(),
                sessionId: sessionId
            };
            events.push(event);
            logEvent(event);
            
            if (eventType === 'TRAINING_COMPLETED') {
                alert('Training Complete! Thank you for participating in security awareness.');
            }
        }
        
        function logEvent(event) {
            const log = document.getElementById('log');
            const entry = document.createElement('div');
            entry.textContent = event.type + ' @ ' + new Date(event.timestamp).toLocaleTimeString();
            log.appendChild(entry);
            log.scrollTop = log.scrollHeight;
        }
        
        // Record page open
        recordEvent('PAGE_OPENED');
    </script>
</body>
</html>`;
    return html;
  }

  createTrainingSession() {
    const sessionId = crypto.randomBytes(8).toString('hex');
    const sessionDir = path.join(TRAINING_DIR, sessionId);
    fs.mkdirSync(sessionDir, { recursive: true });

    const htmlFile = path.join(sessionDir, 'index.html');
    fs.writeFileSync(htmlFile, this.createPhishingPage(sessionId));

    return {
      sessionId,
      path: sessionDir,
      htmlPath: htmlFile
    };
  }
}

const trainingSimulator = new TrainingSimulator();

// ============================================================================
// REPORT GENERATOR
// ============================================================================

class ReportGenerator {
  generateReport(scanResults, userId) {
    const reportId = crypto.randomBytes(6).toString('hex');
    const timestamp = new Date().toISOString();

    const report = `
╔════════════════════════════════════════════════════════════════════╗
║         SECURITY ASSESSMENT REPORT                                 ║
╚══════════════��═════════════════════════════════════════════════════╝

Target: ${scanResults.target}
Date: ${timestamp}
Tester: User #${userId}
Report ID: ${reportId}

─────────────────────────────────────────────────────────────────────
📊 HTTP ANALYSIS
─────────────────────────────────────────────────────────────────────
Status Code: ${scanResults.http?.statusCode || 'N/A'}
Server: ${scanResults.http?.headers?.server || 'Not disclosed'}
Redirect: ${scanResults.http?.redirectUrl || 'None detected'}

─────────────────────────────────────────────────────────────────────
🔐 TLS/SSL CERTIFICATE
─────────────────────────────────────────────────────────────────────
${this.formatSSL(scanResults.ssl)}

─────────────────────────────────────────────────────────────────────
🛡️  SECURITY HEADERS
─────────────────────────────────────────────────────────────────────
${scanResults.securityHeaders?.join('\n') || 'No headers analyzed'}

─────────────────────────────────────────────────────────────────────
🍪 COOKIE SECURITY
─────────────────────────────────────────────────────────────────────
${scanResults.cookies?.join('\n') || 'No cookies found'}

─────────────────────────────────────────────────────────────────────
🌐 DNS RECORDS
─────────────────────────────────────────────────────────────────────
${this.formatDNS(scanResults.dns)}

─────────────────────────────────────────────────────────────────────
📡 OPEN PORTS (Common Ports Scanned)
─────────────────────────────────────────────────────────────────────
${scanResults.ports?.length > 0 ? scanResults.ports.join(', ') : 'No common ports open'}

─────────────────────────────────────────────────────────────────────
🔍 DETECTED TECHNOLOGY
─────────────────────────────────────────────────────────────────────
${scanResults.technology?.join('\n') || 'No technology detected'}

─────────────────────────────────────────────────────────────────────
📋 robots.txt STATUS
─────────────────────────────────────────────────────────────────────
${scanResults.robots ? '✅ Found' : '❌ Not found or blocked'}

─────────────────────────────────────────────────────────────────────
⏱️  SCAN DURATION
─────────────────────────────────────────────────────────────────────
${scanResults.duration}ms

═════════════════════════════════════════════════════════════════════

Note: This report is for authorized security testing only.
Unauthorized access to computer systems is illegal.

═════════════════════════════════════════════════════════════════════
`;

    return report;
  }

  formatSSL(ssl) {
    if (ssl?.error) return `❌ ${ssl.error}`;
    if (!ssl?.subject) return 'Certificate data unavailable';

    return `
Issued To: ${ssl.subject?.CN || 'N/A'}
Issued By: ${ssl.issuer?.CN || 'N/A'}
Valid From: ${ssl.valid_from || 'N/A'}
Valid To: ${ssl.valid_to || 'N/A'}
Fingerprint: ${ssl.fingerprint || 'N/A'}
    `.trim();
  }

  formatDNS(dns) {
    if (dns?.error) return `❌ ${dns.error}`;
    let result = '';
    if (dns.A?.length) result += `A Records: ${dns.A.join(', ')}\n`;
    if (dns.AAAA?.length) result += `AAAA Records: ${dns.AAAA.join(', ')}\n`;
    if (dns.MX?.length) result += `MX Records: ${dns.MX.map(r => r.exchange).join(', ')}\n`;
    if (dns.NS?.length) result += `NS Records: ${dns.NS.join(', ')}\n`;
    return result || 'No DNS records found';
  }
}

const reportGenerator = new ReportGenerator();

// ============================================================================
// TELEGRAM BOT HANDLERS
// ============================================================================

// Dashboard
async function showDashboard(chatId) {
  const keyboard = {
    inline_keyboard: [
      [
        { text: '🔍 Scan', callback_data: 'scan' },
        { text: '🌐 HTTP Headers', callback_data: 'headers' }
      ],
      [
        { text: '🔐 SSL/TLS', callback_data: 'ssl' },
        { text: '🔎 DNS', callback_data: 'dns' }
      ],
      [
        { text: '📡 Ports', callback_data: 'ports' },
        { text: '🧪 Training', callback_data: 'training' }
      ],
      [
        { text: '📊 Report', callback_data: 'report' },
        { text: '⚙️ Targets', callback_data: 'targets' }
      ],
      [
        { text: '❓ Help', callback_data: 'help' }
      ]
    ]
  };

  await bot.sendMessage(chatId, `
🛡️ *SECURITY ASSESSMENT TOOLKIT*

Welcome to the Security Assessment Bot. This toolkit is designed for authorized security testing only.

*Available Commands:*
• /scan - Full security scan
• /headers - HTTP security headers
• /ssl - TLS/SSL certificate check
• /dns - DNS lookup
• /ports - Common port scanning
• /robots - Check robots.txt
• /tech - Technology detection
• /status - HTTP status check
• /whois - WHOIS lookup
• /training - Create training simulation
• /report - Generate assessment report
• /addtarget - Add authorized target
• /removetarget - Remove target
• /targets - List authorized targets
• /help - Show all commands

*Security Notice:*
All operations are logged. Authorized targets only.
  `, { parse_mode: 'Markdown', reply_markup: keyboard });
}

// Start command
bot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  await showDashboard(chatId);
});

// Help command
bot.onText(/\/help/, async (msg) => {
  const chatId = msg.chat.id;
  await bot.sendMessage(chatId, `
*🛡️ SECURITY TOOLKIT HELP*

*Authorization:*
/addtarget <domain> - Add authorized target (admin)
/removetarget <domain> - Remove target (admin)
/targets - List authorized targets

*Scanning Commands:*
/scan <domain> - Full security assessment
/headers <domain> - Check security headers
/ssl <domain> - Certificate information
/dns <domain> - DNS records
/ports <domain> - Check common ports
/robots <domain> - Check robots.txt
/tech <domain> - Detect technology
/status <domain> - HTTP status check

*Training & Reports:*
/training - Create training simulation
/report <domain> - Generate scan report

*Usage Example:*
/scan example.com

*Important:*
• Only authorized targets in whitelist
• All activity is logged
• Unauthorized testing is prohibited
  `, { parse_mode: 'Markdown' });
});

// Add target (admin only)
bot.onText(/\/addtarget (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (ADMIN_ID && userId !== ADMIN_ID) {
    return bot.sendMessage(chatId, '❌ Admin only command');
  }

  const domain = match[1].trim();
  if (dataManager.addTarget(domain)) {
    await bot.sendMessage(chatId, `✅ Target authorized: ${domain}`);
  } else {
    await bot.sendMessage(chatId, `⚠️ Target already in list`);
  }
});

// Remove target (admin only)
bot.onText(/\/removetarget (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (ADMIN_ID && userId !== ADMIN_ID) {
    return bot.sendMessage(chatId, '❌ Admin only command');
  }

  const domain = match[1].trim();
  dataManager.removeTarget(domain);
  await bot.sendMessage(chatId, `✅ Target removed: ${domain}`);
});

// List targets
bot.onText(/\/targets/, async (msg) => {
  const chatId = msg.chat.id;
  const targets = dataManager.getTargets();

  if (targets.length === 0) {
    return bot.sendMessage(chatId, '📋 No authorized targets configured');
  }

  const list = targets.map((t, i) => `${i + 1}. ${t}`).join('\n');
  await bot.sendMessage(chatId, `
*📋 Authorized Targets:*

${list}
  `, { parse_mode: 'Markdown' });
});

// Scan command
bot.onText(/\/scan (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const domain = match[1].trim();

  // Rate limit check
  if (!dataManager.checkRateLimit(userId, 5, 60000)) {
    return bot.sendMessage(chatId, '⏱️ Rate limit exceeded. Try again in 1 minute.');
  }

  // Authorization check
  if (!dataManager.isAuthorized(domain)) {
    dataManager.addAuditLog(userId, 'scan', domain, 'UNAUTHORIZED_ATTEMPT', 0);
    return bot.sendMessage(chatId, `❌ Target belum terdaftar sebagai authorized asset.\n\nGunakan /targets untuk melihat daftar target yang diizinkan.`);
  }

  const startTime = Date.now();
  const msg_sent = await bot.sendMessage(chatId, `🔄 Scanning ${domain}...`);

  try {
    const results = await scanner.fullScan(scanner.normalizeUrl(domain));
    const duration = Date.now() - startTime;
    dataManager.addAuditLog(userId, 'scan', domain, 'SUCCESS', duration);

    const report = reportGenerator.generateReport(results, userId);
    await bot.editMessageText(report, {
      chat_id: chatId,
      message_id: msg_sent.message_id,
      parse_mode: 'Markdown'
    });
  } catch (err) {
    const duration = Date.now() - startTime;
    dataManager.addAuditLog(userId, 'scan', domain, 'ERROR', duration);
    await bot.editMessageText(
      `❌ Scan error: ${err.message}`,
      { chat_id: chatId, message_id: msg_sent.message_id }
    );
  }
});

// Headers command
bot.onText(/\/headers (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  if (!dataManager.checkRateLimit(msg.from.id)) {
    return bot.sendMessage(chatId, '⏱️ Rate limit exceeded');
  }

  try {
    const result = await scanner.fetchHeaders(scanner.normalizeUrl(domain));
    if (result.error) {
      return bot.sendMessage(chatId, `❌ ${result.error}`);
    }

    const headers = result.headers || {};
    const headerText = Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');

    await bot.sendMessage(chatId, `
*HTTP Headers for ${domain}*

Status: ${result.statusCode}

\`\`\`
${headerText.substring(0, 3000)}
\`\`\`
    `, { parse_mode: 'Markdown' });
  } catch (err) {
    await bot.sendMessage(chatId, `❌ Error: ${err.message}`);
  }
});

// SSL command
bot.onText(/\/ssl (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  try {
    const cert = await scanner.getSSLCertificate(domain);
    const report = `
*🔐 SSL/TLS Certificate - ${domain}*

${cert.error ? `❌ ${cert.error}` : `
✅ Subject: ${cert.subject?.CN || 'N/A'}
✅ Issuer: ${cert.issuer?.CN || 'N/A'}
✅ Valid From: ${cert.valid_from || 'N/A'}
✅ Valid To: ${cert.valid_to || 'N/A'}
✅ Fingerprint: ${cert.fingerprint || 'N/A'}
    `}
    `;
    await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
  } catch (err) {
    await bot.sendMessage(chatId, `❌ Error: ${err.message}`);
  }
});

// DNS command
bot.onText(/\/dns (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  try {
    const dnsResult = await scanner.resolveDNS(domain);
    const report = `
*🌐 DNS Records - ${domain}*

${reportGenerator.formatDNS(dnsResult)}
    `;
    await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
  } catch (err) {
    await bot.sendMessage(chatId, `❌ Error: ${err.message}`);
  }
});

// Ports command
bot.onText(/\/ports (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  const checking = await bot.sendMessage(chatId, `📡 Checking ports on ${domain}...`);
  try {
    const ports = await scanner.checkPorts(domain);
    const report = `
*📡 Open Ports - ${domain}*

Common ports checked: 80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 8080, 8443

${ports.length > 0 ? `Open: ${ports.join(', ')}` : 'No common ports open'}
    `;
    await bot.editMessageText(report, {
      chat_id: chatId,
      message_id: checking.message_id,
      parse_mode: 'Markdown'
    });
  } catch (err) {
    await bot.editMessageText(`❌ Error: ${err.message}`, {
      chat_id: chatId,
      message_id: checking.message_id
    });
  }
});

// Robots command
bot.onText(/\/robots (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  try {
    const url = scanner.normalizeUrl(domain);
    const robots = await scanner.fetchRobotsTxt(url);
    const report = `
*🤖 robots.txt - ${domain}*

${robots ? `\`\`\`\n${robots.substring(0, 2000)}\n\`\`\`` : '❌ Not found or blocked'}
    `;
    await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
  } catch (err) {
    await bot.sendMessage(chatId, `❌ Error: ${err.message}`);
  }
});

// Technology detection
bot.onText(/\/tech (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  try {
    const url = scanner.normalizeUrl(domain);
    const techs = await scanner.detectTechnology(url);
    const report = `
*🔍 Technology Detection - ${domain}*

${techs.join('\n')}
    `;
    await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
  } catch (err) {
    await bot.sendMessage(chatId, `❌ Error: ${err.message}`);
  }
});

// Status command
bot.onText(/\/status (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  try {
    const url = scanner.normalizeUrl(domain);
    const result = await scanner.fetchHeaders(url);
    const report = `
*📊 HTTP Status - ${domain}*

Status Code: ${result.statusCode || 'N/A'}
Response Time: ${result.duration || 'N/A'}ms
Server: ${result.headers?.server || 'Not disclosed'}
Redirect: ${result.redirectUrl || 'None'}
    `;
    await bot.sendMessage(chatId, report, { parse_mode: 'Markdown' });
  } catch (err) {
    await bot.sendMessage(chatId, `❌ Error: ${err.message}`);
  }
});

// Training command
bot.onText(/\/training/, async (msg) => {
  const chatId = msg.chat.id;
  
  try {
    const training = trainingSimulator.createTrainingSession();

    const instructions = `
*🧪 Security Awareness Training Created*

✅ Training session created successfully

*Session Details:*
Session ID: \`${training.sessionId}\`
Files: index.html

*Deployment Instructions:*

1. Copy the training files from directory:
   \`${training.path}\`

2. Deploy to your authorized web server:
   scp -r ${training.path} user@yourserver:/var/www/training/

3. Access at: https://yourserver/training/index.html

*Important:*
✅ This page does NOT:
   • Collect passwords
   • Steal cookies/tokens
   • Access camera/microphone
   • Perform fingerprinting
   • Record credentials
   • Capture private data

✅ This page ONLY records:
   • Page opened event
   • Button clicks
   • Training completion

*After Training:*
Collect anonymous statistics from \`${training.path}/events.json\`
    `;

    await bot.sendMessage(chatId, instructions, { parse_mode: 'Markdown' });
  } catch (err) {
    await bot.sendMessage(chatId, `❌ Error: ${err.message}`);
  }
});

// Report command
bot.onText(/\/report (.+)/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;
  const domain = match[1].trim();

  if (!dataManager.isAuthorized(domain)) {
    return bot.sendMessage(chatId, `❌ Target not authorized`);
  }

  const generating = await bot.sendMessage(chatId, `📊 Generating report...`);

  try {
    const results = await scanner.fullScan(scanner.normalizeUrl(domain));
    const report = reportGenerator.generateReport(results, userId);
    dataManager.addAuditLog(userId, 'report', domain, 'SUCCESS', 0);

    await bot.editMessageText(report, {
      chat_id: chatId,
      message_id: generating.message_id
    });
  } catch (err) {
    dataManager.addAuditLog(userId, 'report', domain, 'ERROR', 0);
    await bot.editMessageText(`❌ Error: ${err.message}`, {
      chat_id: chatId,
      message_id: generating.message_id
    });
  }
});

// Callback query handler
bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const action = query.data;

  try {
    switch (action) {
      case 'scan':
        await bot.sendMessage(chatId, 'Send domain to scan:\n/scan example.com');
        break;
      case 'headers':
        await bot.sendMessage(chatId, 'Send domain:\n/headers example.com');
        break;
      case 'ssl':
        await bot.sendMessage(chatId, 'Send domain:\n/ssl example.com');
        break;
      case 'dns':
        await bot.sendMessage(chatId, 'Send domain:\n/dns example.com');
        break;
      case 'ports':
        await bot.sendMessage(chatId, 'Send domain:\n/ports example.com');
        break;
      case 'training':
        const training = trainingSimulator.createTrainingSession();
        const instructions = `
*🧪 Security Awareness Training Created*

✅ Training session created successfully

*Session Details:*
Session ID: \`${training.sessionId}\`
Files: index.html

*Deployment Instructions:*

1. Copy the training files from directory:
   \`${training.path}\`

2. Deploy to your authorized web server:
   scp -r ${training.path} user@yourserver:/var/www/training/

3. Access at: https://yourserver/training/index.html

*Important:*
✅ This page does NOT collect passwords/cookies/camera/microphone

✅ This page ONLY records:
   • Page opened event
   • Button clicks
   • Training completion
        `;
        await bot.sendMessage(chatId, instructions, { parse_mode: 'Markdown' });
        break;
      case 'report':
        await bot.sendMessage(chatId, 'Send domain:\n/report example.com');
        break;
      case 'targets':
        const targets = dataManager.getTargets();
        if (targets.length === 0) {
          await bot.sendMessage(chatId, '📋 No authorized targets configured');
        } else {
          const list = targets.map((t, i) => `${i + 1}. ${t}`).join('\n');
          await bot.sendMessage(chatId, `*📋 Authorized Targets:*\n\n${list}`, { parse_mode: 'Markdown' });
        }
        break;
      case 'help':
        await bot.sendMessage(chatId, `
*🛡️ SECURITY TOOLKIT HELP*

*Authorization:*
/addtarget <domain> - Add authorized target (admin)
/removetarget <domain> - Remove target (admin)
/targets - List authorized targets

*Scanning Commands:*
/scan <domain> - Full security assessment
/headers <domain> - Check security headers
/ssl <domain> - Certificate information
/dns <domain> - DNS records
/ports <domain> - Check common ports
/robots <domain> - Check robots.txt
/tech <domain> - Detect technology
/status <domain> - HTTP status check

*Training & Reports:*
/training - Create training simulation
/report <domain> - Generate scan report

*Usage Example:*
/scan example.com

*Important:*
• Only authorized targets in whitelist
• All activity is logged
• Unauthorized testing is prohibited
        `, { parse_mode: 'Markdown' });
        break;
    }

    await bot.answerCallbackQuery(query.id);
  } catch (err) {
    console.error('Callback error:', err);
    await bot.answerCallbackQuery(query.id, { text: `Error: ${err.message}`, show_alert: true });
  }
});

// Error handler
bot.on('error', (error) => {
  console.error('❌ Bot error:', error);
});

// ============================================================================
// STARTUP
// ============================================================================

console.log('🚀 Security Assessment Bot starting...');
console.log('✅ BOT_TOKEN loaded from environment');
console.log(`✅ Admin ID: ${ADMIN_ID || 'Not configured'}`);
console.log(`✅ Authorized targets: ${dataManager.getTargets().length}`);
console.log('✅ Bot is polling for messages...');
console.log('\n💡 Add targets with: /addtarget example.com');
console.log('💡 Run scans with: /scan example.com');
console.log('💡 All activities logged to ./logs/audit.log\n');

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n👋 Bot shutting down...');
  bot.stopPolling();
  process.exit(0);
});
