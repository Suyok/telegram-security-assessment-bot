# Telegram Security Assessment Bot - Setup Guide for Termux

## 🚀 Quick Start (5 minutes)

### Step 1: Install on Termux

```bash
# Update packages
pkg update && pkg upgrade

# Install Node.js
pkg install nodejs git

# Clone and setup
git clone https://github.com/Suyok/telegram-security-assessment-bot.git
cd telegram-security-assessment-bot

# Run setup script
bash setup.sh
```

### Step 2: Configure Bot Token

1. Open Telegram and message **@BotFather**
2. Send `/newbot`
3. Follow the prompts to create your bot
4. Copy the token (looks like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### Step 3: Get Your Admin ID

1. Install **@userinfobot** on Telegram
2. Send `/start` message
3. Copy your user ID

### Step 4: Configure Environment

```bash
# Edit .env file
nano .env
```

Add your values:
```
BOT_TOKEN=paste_your_token_here
ADMIN_ID=paste_your_id_here
```

Save: `Ctrl+X` → `Y` → `Enter`

### Step 5: Run the Bot

```bash
npm start
```

You should see:
```
🚀 Security Assessment Bot starting...
✅ BOT_TOKEN loaded from environment
✅ Admin ID: your_id
✅ Authorized targets: 0
✅ Bot is polling for messages...
```

## ✅ Your Bot is Running!

Open Telegram and search for your bot name, then:

1. Send `/start` to see the dashboard
2. Send `/help` for all commands
3. Add targets with `/addtarget example.com`
4. Run scans with `/scan example.com`

## 📋 Common Tasks

### Add a Target

```
/addtarget google.com
```

### Scan a Website

```
/scan google.com
```

### Check Security Headers

```
/headers google.com
```

### View All Targets

```
/targets
```

### Get Full Report

```
/report google.com
```

## 🔧 Troubleshooting

### Bot not responding

1. Check if bot is running: Look for "✅ Bot is polling" message
2. Restart: Press `Ctrl+C` and run `npm start` again
3. Check token: Make sure BOT_TOKEN in .env is correct

### "Rate limit exceeded"

Wait 1 minute and try again. This is normal protection against abuse.

### "Target not authorized"

Add the target first: `/addtarget example.com`

### npm install fails

```bash
npm install --legacy-peer-deps
```

## 📁 Important Files

```
data/authorized_targets.json  - Your whitelist of targets
logs/audit.log               - Log of all scans
.env                         - Your configuration (keep secret!)
```

## 🔐 Security Reminders

✅ Always use authorized targets only
✅ Keep your BOT_TOKEN secret
✅ Only admin can add/remove targets
✅ All activities are logged
✅ Never share your .env file

## 🆘 Need Help?

1. Check the README.md file
2. Review logs: `cat logs/audit.log`
3. Verify .env settings: `cat .env`
4. Check authorized targets: `cat data/authorized_targets.json`

## 📚 Full Command List

**Admin Only:**
- `/addtarget <domain>` - Add to whitelist
- `/removetarget <domain>` - Remove from whitelist
- `/targets` - List all targets

**Scanning:**
- `/scan <domain>` - Full assessment
- `/headers <domain>` - Security headers
- `/ssl <domain>` - Certificate info
- `/dns <domain>` - DNS records
- `/ports <domain>` - Port scan
- `/robots <domain>` - Check robots.txt
- `/tech <domain>` - Technology detection
- `/status <domain>` - HTTP status

**Reports:**
- `/report <domain>` - Full report
- `/training` - Create awareness training
- `/help` - Show commands
- `/start` - Dashboard

---

**Your bot is ready to secure! 🛡️**