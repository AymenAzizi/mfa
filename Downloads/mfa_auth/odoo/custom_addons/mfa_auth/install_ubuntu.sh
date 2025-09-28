#!/bin/bash

# MFA Module Installation Script for Ubuntu/Odoo 17
# This script will install the MFA module perfectly

echo "🚀 Installing MFA Authentication System for Odoo 17..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install pyotp qrcode cryptography

# Set proper permissions
echo "🔐 Setting permissions..."
chown -R odoo:odoo /odoo/custom_addons/mfa_auth
chmod -R 755 /odoo/custom_addons/mfa_auth

# Clear Python cache
echo "🧹 Clearing Python cache..."
find /odoo/custom_addons/mfa_auth -name "*.pyc" -delete
find /odoo/custom_addons/mfa_auth -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Restart Odoo
echo "🔄 Restarting Odoo..."
systemctl restart odoo

# Wait for Odoo to start
echo "⏳ Waiting for Odoo to start..."
sleep 10

# Check if Odoo is running
if systemctl is-active --quiet odoo; then
    echo "✅ Odoo is running successfully!"
    echo "🌐 Access Odoo at: http://localhost:8069"
    echo "📝 Go to Apps and install the 'MFA Authentication System' module"
    echo ""
    echo "🎯 Module Features:"
    echo "   • TOTP Authentication with Google Authenticator"
    echo "   • QR Code generation for easy setup"
    echo "   • Security logging and compliance"
    echo "   • Backup codes for emergency access"
    echo "   • Account lockout after failed attempts"
    echo ""
    echo "🚀 The module is now ready to use!"
else
    echo "❌ Odoo failed to start. Check logs:"
    echo "sudo journalctl -u odoo -f"
fi
