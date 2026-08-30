#!/bin/bash

# Setup script for Telegram Security Assessment Bot on Termux

echo "🛡️ Telegram Security Assessment Bot - Setup"
echo "=============================================="
echo ""

# Check if node is installed
if ! command -v node &> /dev/null; then
    echo "📦 Installing Node.js..."
    pkg update
    pkg install nodejs
else
    echo "✅ Node.js already installed: $(node -v)"
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "📦 Installing npm..."
    pkg install npm
else
    echo "✅ npm already installed: $(npm -v)"
fi

echo ""
echo "📥 Installing dependencies..."
npm install

echo ""
echo "📝 Creating .env file..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ .env file created. Please edit it with your BOT_TOKEN and ADMIN_ID:"
    echo "   nano .env"
else
    echo "⚠️  .env file already exists"
fi

echo ""
echo "✨ Setup complete!"
echo ""
echo "📌 Next steps:"
echo "1. Edit .env file: nano .env"
echo "2. Add your BOT_TOKEN and ADMIN_ID"
echo "3. Run: npm start"
echo ""
echo "💡 Get your BOT_TOKEN from @BotFather on Telegram"
echo "💡 Get your ADMIN_ID from @userinfobot on Telegram"
echo ""