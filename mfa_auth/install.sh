#!/bin/bash

# MFA Authentication Module Installation Script
# For Odoo 17 on Ubuntu

echo "🔐 MFA Authentication Module Installation Script"
echo "================================================"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "❌ Please do not run this script as root"
    exit 1
fi

# Check if Odoo is installed
if ! command -v odoo &> /dev/null; then
    echo "❌ Odoo not found. Please install Odoo 17 first."
    exit 1
fi

# Get Odoo addons directory
ODOO_ADDONS_DIR="/opt/odoo/addons"
if [ ! -d "$ODOO_ADDONS_DIR" ]; then
    ODOO_ADDONS_DIR="/usr/lib/python3/dist-packages/odoo/addons"
fi

if [ ! -d "$ODOO_ADDONS_DIR" ]; then
    echo "❌ Odoo addons directory not found. Please specify the correct path."
    read -p "Enter Odoo addons directory path: " ODOO_ADDONS_DIR
fi

# Create custom addons directory if it doesn't exist
CUSTOM_ADDONS_DIR="$(dirname "$ODOO_ADDONS_DIR")/custom_addons"
if [ ! -d "$CUSTOM_ADDONS_DIR" ]; then
    echo "📁 Creating custom addons directory: $CUSTOM_ADDONS_DIR"
    sudo mkdir -p "$CUSTOM_ADDONS_DIR"
    sudo chown -R odoo:odoo "$CUSTOM_ADDONS_DIR"
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
sudo pip3 install pyotp qrcode cryptography

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Python dependencies"
    exit 1
fi

# Copy module to addons directory
echo "📋 Copying module to addons directory..."
sudo cp -r "$(pwd)" "$CUSTOM_ADDONS_DIR/mfa_auth"
sudo chown -R odoo:odoo "$CUSTOM_ADDONS_DIR/mfa_auth"
sudo chmod -R 755 "$CUSTOM_ADDONS_DIR/mfa_auth"

if [ $? -ne 0 ]; then
    echo "❌ Failed to copy module"
    exit 1
fi

# Restart Odoo service
echo "🔄 Restarting Odoo service..."
sudo systemctl restart odoo

if [ $? -ne 0 ]; then
    echo "⚠️  Failed to restart Odoo service. Please restart manually."
fi

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Go to your Odoo instance"
echo "2. Navigate to Apps menu"
echo "3. Search for 'MFA Authentication System'"
echo "4. Click Install"
echo "5. Configure MFA for your users"
echo ""
echo "📖 For detailed usage instructions, see the README.md file"
echo ""
echo "🔐 MFA Authentication Module is ready to use!"