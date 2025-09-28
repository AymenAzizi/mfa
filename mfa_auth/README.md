# MFA Authentication System for Odoo 17

A comprehensive Multi-Factor Authentication (MFA) module for Odoo 17 that provides TOTP-based authentication with compliance features for ISMS and privacy regulations.

## 🎯 Features

- **TOTP Authentication**: Time-based One-Time Password using Google Authenticator
- **QR Code Setup**: Easy setup with QR code scanning
- **Backup Codes**: Emergency access codes for device loss scenarios
- **Security Logging**: Complete audit trail for compliance
- **Account Lockout**: Protection against brute force attacks
- **Per-user Configuration**: Flexible MFA enforcement
- **Group-based Requirements**: Force MFA for specific user groups
- **Clean UI**: Modern and user-friendly interface

## 🔒 Security & Compliance

- **ISO 27001** compliant audit logging
- **GDPR** compliant data handling
- **ANSSI** recommendations compliance
- Secure secret storage with encryption
- Session timeout management
- Failed attempt tracking and lockout

## 📦 Installation

### Prerequisites

Install required Python packages:

```bash
pip3 install pyotp qrcode cryptography pillow
```

### Module Installation

1. **Copy the module** to your Odoo addons directory:
```bash
cp -r mfa_auth /path/to/odoo/addons/
chown -R odoo:odoo /path/to/odoo/addons/mfa_auth
```

2. **Restart Odoo** service:
```bash
sudo systemctl restart odoo
```

3. **Install the module** through Odoo Apps interface:
   - Go to Apps menu
   - Search for "MFA Authentication System"
   - Click Install

## 🚀 Usage

### For Users

#### Enabling MFA

1. Go to **Settings > Users & Companies > Users**
2. Open your user record
3. Navigate to **Multi-Factor Authentication** tab
4. Click **Setup MFA**
5. Scan the QR code with your authenticator app
6. Enter the verification code to complete setup
7. Save your backup codes in a secure location

#### Login with MFA

1. Enter your username and password as usual
2. You'll be redirected to the MFA verification page
3. Enter the 6-digit code from your authenticator app
4. Or use a backup code if needed

#### Disabling MFA

1. Go to your user settings
2. Navigate to **Multi-Factor Authentication** tab
3. Click **Disable MFA**
4. Enter your password to confirm
5. Confirm you understand the security implications

### For Administrators

#### Forcing MFA for User Groups

1. Go to **Settings > Users & Companies > Groups**
2. Create or edit a group
3. Add users who should be required to use MFA
4. Assign the **MFA Required** group to these users

#### Viewing Audit Logs

1. Go to **Settings > MFA Security > MFA Audit Logs**
2. Review all MFA-related activities
3. Filter by user, action, or date range

## 🛠️ Technical Details

### Module Structure

```
mfa_auth/
├── __init__.py
├── __manifest__.py
├── models/
│   ├── __init__.py
│   ├── mfa_user.py          # User model extension
│   ├── mfa_log.py           # Audit logging
│   └── mfa_wizard.py        # Setup/disable wizards
├── controllers/
│   ├── __init__.py
│   └── mfa_controller.py    # Web routes for MFA
├── views/
│   ├── mfa_settings.xml     # User interface views
│   ├── mfa_templates.xml    # Web templates
│   └── mfa_wizard_views.xml # Wizard forms
├── security/
│   ├── ir.model.access.csv  # Access permissions
│   └── mfa_security.xml     # Security groups and rules
├── data/
│   └── mfa_demo_data.xml    # Demo data
└── static/src/css/
    └── mfa.css              # Styling
```

### Key Models

- **res.users**: Extended with MFA fields and methods
- **mfa.log**: Audit log for all MFA activities
- **mfa.setup.wizard**: Wizard for MFA setup
- **mfa.disable.wizard**: Wizard for MFA disable

### Security Features

- **Account Lockout**: 5 failed attempts locks account for 15 minutes
- **Backup Codes**: 10 single-use backup codes generated
- **Session Management**: Proper session handling during MFA flow
- **Audit Logging**: All actions logged with IP and user agent

## 🔧 Configuration

### Environment Variables

No special environment variables required.

### Dependencies

- `pyotp`: For TOTP generation and verification
- `qrcode`: For QR code generation
- `cryptography`: For secure operations
- `pillow`: For image processing

## 🧪 Testing

### Manual Testing

1. **Install Test**: Verify module installs without errors
2. **Setup Test**: Enable MFA for a test user
3. **Login Test**: Test login flow with MFA enabled
4. **Backup Code Test**: Test backup code functionality
5. **Lockout Test**: Test account lockout after failed attempts
6. **Disable Test**: Test MFA disable functionality

### Expected Behavior

- ✅ Module installs without JavaScript errors
- ✅ QR codes generate correctly
- ✅ TOTP verification works with authenticator apps
- ✅ Backup codes work for emergency access
- ✅ Account lockout prevents brute force attacks
- ✅ Audit logs capture all activities

## ⚠️ Important Notes

### Odoo 17 Compatibility

This module is specifically designed for Odoo 17 and includes:

- **No JavaScript assets** in manifest (prevents minification errors)
- **Odoo 17 XML syntax** (no deprecated `attrs` usage)
- **Proper field access** with all required permissions
- **No `_check_credentials` override** (prevents authentication errors)

### Security Considerations

- Store backup codes securely
- Regularly review audit logs
- Consider network security for MFA pages
- Test thoroughly before production deployment

## 📝 License

LGPL-3 - See LICENSE file for details.

## 🤝 Contributing

This is a university project. Contributions should follow academic guidelines.

## 📞 Support

For issues related to this university project, please contact the project team.

---

**Version**: 17.0.1.0.0  
**Odoo Version**: 17.0  
**License**: LGPL-3