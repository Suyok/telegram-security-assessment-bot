# Telegram Security Assessment Toolkit

A comprehensive security assessment bot for authorized cybersecurity teams running on Node.js without VPS requirement.

## 🛡️ Features

- **Full Security Scanning**: HTTP headers, SSL/TLS certificates, DNS records, port scanning
- **Technology Detection**: Passive web technology identification
- **Whitelist Authorization**: Admin-controlled target authorization system
- **Security Awareness Training**: Safe phishing simulation for employee training
- **Detailed Reports**: Professional security assessment reports
- **Rate Limiting**: Built-in protection against abuse
- **Audit Logging**: Complete audit trail of all operations
- **Runs on Termux**: No VPS required, works on Android via Termux

## 📋 Prerequisites

- Node.js 14+
- npm
- Telegram Bot Token (from @BotFather)
- Termux or any Linux/macOS environment

## ⚡ Quick Setup

### 1. Install on Termux

```bash
pkg update && pkg upgrade
pkg install nodejs git
git clone https://github.com/Suyok/telegram-security-assessment-bot.git
cd telegram-security-assessment-bot
npm install
```

### 2. Create .env file

```bash
cp .env.example .env
nano .env
```

### 3. Run the Bot

```bash
npm start
```

## 🎮 Commands

### Admin Commands
```
/addtarget <domain>      - Add authorized target
/removetarget <domain>   - Remove target from whitelist
/targets                 - List all authorized targets
```

### Scanning Commands
```
/start                   - Show dashboard
/scan <domain>           - Full security assessment
/headers <domain>        - Check HTTP security headers
/ssl <domain>            - TLS/SSL certificate information
/dns <domain>            - DNS records lookup
/ports <domain>          - Common port scanning
/robots <domain>         - Check robots.txt
/tech <domain>           - Technology detection
/status <domain>         - HTTP status and response info
```

### Training & Reports
```
/training                - Create security awareness training
/report <domain>         - Generate assessment report
/help                    - Show all commands
```

## 📊 Full Scan Checks

Each scan performs:
- ✅ HTTP/HTTPS availability and status codes
- ✅ TLS certificate validation and expiry
- ✅ Security headers analysis
- ✅ Cookie security flags
- ✅ DNS records (A, AAAA, MX, NS)
- ✅ Common port availability
- ✅ robots.txt detection
- ✅ Basic technology detection
- ✅ Server banner information

## 🔐 Security Features

- **Authorization System**: Whitelist-based target authorization
- **Rate Limiting**: 5 requests per minute per user
- **Audit Logging**: Complete audit trail
- **Safe Training**: No credential capture, no spyware
- **Data Protection**: No sensitive data in logs

## 📁 Directory Structure

```
telegram-security-assessment-bot/
├── bot.js                      # Main bot file
├── package.json                # Dependencies
├── .env.example                # Example configuration
├── README.md                   # This file
├── data/                       # Data storage
├── logs/                       # Audit logs
└── training_sessions/          # Training simulations
```

## 📝 Legal Notice

This tool is for authorized security assessments only.
**Unauthorized access to computer systems is ILLEGAL.**

Always obtain written permission before testing any target.

---

**Stay secure, test responsibly!** 🛡️