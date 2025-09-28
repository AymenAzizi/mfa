#!/bin/bash

# MFA Authentication Module Installation Script for Odoo 17
# This script helps install the MFA module and its dependencies

set -e

echo "🚀 MFA Authentication Module Installation Script"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root. Consider running as odoo user for production."
fi

# Step 1: Install Python dependencies
print_status "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install pyotp qrcode[pil] cryptography

if [ $? -eq 0 ]; then
    print_success "Python dependencies installed successfully"
else
    print_error "Failed to install Python dependencies"
    exit 1
fi

# Step 2: Check Odoo installation
print_status "Checking for Odoo installation..."

ODOO_PATHS=(
    "/opt/odoo"
    "/usr/lib/python3/dist-packages/odoo"
    "/odoo"
    "$HOME/odoo"
)

ODOO_ADDONS_PATH=""
for path in "${ODOO_PATHS[@]}"; do
    if [ -d "$path/addons" ]; then
        ODOO_ADDONS_PATH="$path/addons"
        break
    fi
    if [ -d "$path/custom_addons" ]; then
        ODOO_ADDONS_PATH="$path/custom_addons"
        break
    fi
done

if [ -z "$ODOO_ADDONS_PATH" ]; then
    print_warning "Could not automatically detect Odoo addons path."
    read -p "Please enter your Odoo addons path: " ODOO_ADDONS_PATH
    
    if [ ! -d "$ODOO_ADDONS_PATH" ]; then
        print_error "Directory does not exist: $ODOO_ADDONS_PATH"
        exit 1
    fi
fi

print_success "Using Odoo addons path: $ODOO_ADDONS_PATH"

# Step 3: Copy module files
print_status "Copying MFA module to Odoo addons directory..."

if [ -d "$ODOO_ADDONS_PATH/mfa_auth" ]; then
    print_warning "MFA module already exists. Backing up..."
    mv "$ODOO_ADDONS_PATH/mfa_auth" "$ODOO_ADDONS_PATH/mfa_auth.backup.$(date +%Y%m%d_%H%M%S)"
fi

cp -r "$(dirname "$0")" "$ODOO_ADDONS_PATH/mfa_auth"

# Set proper permissions
if [ -w "$ODOO_ADDONS_PATH" ]; then
    chmod -R 755 "$ODOO_ADDONS_PATH/mfa_auth"
    print_success "Module files copied successfully"
else
    print_error "No write permission to $ODOO_ADDONS_PATH"
    print_status "You may need to run: sudo cp -r $(dirname "$0") $ODOO_ADDONS_PATH/mfa_auth"
    print_status "And: sudo chmod -R 755 $ODOO_ADDONS_PATH/mfa_auth"
fi

# Step 4: Check Odoo configuration
print_status "Checking Odoo configuration..."

ODOO_CONF_PATHS=(
    "/etc/odoo/odoo.conf"
    "/etc/odoo.conf"
    "/opt/odoo/odoo.conf"
    "$HOME/.odoorc"
)

ODOO_CONF=""
for conf_path in "${ODOO_CONF_PATHS[@]}"; do
    if [ -f "$conf_path" ]; then
        ODOO_CONF="$conf_path"
        break
    fi
done

if [ -n "$ODOO_CONF" ]; then
    print_success "Found Odoo configuration: $ODOO_CONF"
    
    # Check if addons_path includes our directory
    if grep -q "$ODOO_ADDONS_PATH" "$ODOO_CONF"; then
        print_success "Addons path is correctly configured"
    else
        print_warning "You may need to add $ODOO_ADDONS_PATH to addons_path in $ODOO_CONF"
    fi
else
    print_warning "Could not find Odoo configuration file"
fi

# Step 5: Restart Odoo (optional)
print_status "Installation completed!"
echo
echo "📋 Next Steps:"
echo "1. Restart your Odoo service:"
echo "   sudo systemctl restart odoo"
echo "   # or"
echo "   sudo service odoo restart"
echo
echo "2. Go to Odoo Apps menu and install 'MFA Authentication System'"
echo
echo "3. Configure MFA for users in Settings > Users & Companies > Users"
echo
echo "🔒 Security Notes:"
echo "- Test MFA functionality in a development environment first"
echo "- Ensure you have backup access before enabling MFA"
echo "- Review the README.md file for detailed usage instructions"
echo

read -p "Would you like to restart Odoo now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Attempting to restart Odoo..."
    
    if systemctl is-active --quiet odoo; then
        sudo systemctl restart odoo
        print_success "Odoo restarted successfully"
    elif service odoo status >/dev/null 2>&1; then
        sudo service odoo restart
        print_success "Odoo restarted successfully"
    else
        print_warning "Could not detect Odoo service. Please restart manually."
    fi
fi

print_success "MFA Authentication module installation completed!"