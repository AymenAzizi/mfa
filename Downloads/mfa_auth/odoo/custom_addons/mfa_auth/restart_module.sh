#!/bin/bash

# MFA Module Restart Script for Odoo 17
# This script will restart Odoo and upgrade the MFA module

echo "🔄 Restarting MFA Module for Odoo 17..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Stop Odoo
echo "⏹️ Stopping Odoo..."
systemctl stop odoo

# Clear Python cache
echo "🧹 Clearing Python cache..."
find /odoo/custom_addons/mfa_auth -name "*.pyc" -delete
find /odoo/custom_addons/mfa_auth -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Set proper permissions
echo "🔐 Setting permissions..."
chown -R odoo:odoo /odoo/custom_addons/mfa_auth
chmod -R 755 /odoo/custom_addons/mfa_auth

# Start Odoo
echo "▶️ Starting Odoo..."
systemctl start odoo

# Wait a moment for Odoo to start
sleep 5

# Check if Odoo is running
if systemctl is-active --quiet odoo; then
    echo "✅ Odoo is running successfully!"
    echo "🌐 Access Odoo at: http://localhost:8069"
    echo "📝 Go to Apps and upgrade the MFA module"
else
    echo "❌ Odoo failed to start. Check logs:"
    echo "sudo journalctl -u odoo -f"
fi
