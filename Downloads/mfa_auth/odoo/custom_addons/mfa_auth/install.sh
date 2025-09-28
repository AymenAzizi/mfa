#!/bin/bash

# MFA Module Installation Script for Odoo 17
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

# Restart Odoo
echo "🔄 Restarting Odoo..."
systemctl restart odoo

echo "✅ MFA Module installation complete!"
echo "🎯 Now go to Odoo Apps and install the 'MFA Authentication System' module"
echo "🌐 Access Odoo at: http://localhost:8069"
