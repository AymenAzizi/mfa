# MFA Authentication Module for Odoo 17

A comprehensive Multi-Factor Authentication (MFA) module for Odoo 17 that provides TOTP (Time-based One-Time Password) authentication with Google Authenticator integration.

## 🎯 Features

### Core Authentication Features
- **TOTP Authentication**: Time-based One-Time Password using Google Authenticator
- **QR Code Generation**: Easy setup with QR code scanning
- **Backup Codes**: Emergency access codes for account recovery
- **Secure Storage**: Encrypted secret storage

### Security & Compliance
- **ISO 27001 Compliant Logging**: Complete audit trail of all MFA actions
- **GDPR Compliant**: Proper data handling and user privacy
- **ANSSI Recommendations**: Follows French cybersecurity guidelines
- **Account Lockout**: Protection against brute force attacks
- **Session Management**: Secure session handling

### User Management
- **Per-user MFA**: Individual MFA settings for each user
- **Group-based Enforcement**: Force MFA for specific user groups
- **Administrative Control**: Global MFA settings and user management
- **Security Dashboard**: Comprehensive audit logging

## 🚀 Installation

### Prerequisites
- Odoo 17.0 or later
- Python 3.8 or later
- Required Python packages: `pyotp`, `qrcode`, `cryptography`

### Installation Steps

1. **Install Python Dependencies**
   ```bash
   sudo pip3 install pyotp qrcode cryptography
   ```

2. **Copy Module to Odoo Addons Directory**
   ```bash
   sudo cp -r /path/to/mfa_auth /odoo/custom_addons/
   sudo chown -R odoo:odoo /odoo/custom_addons/mfa_auth
   sudo chmod -R 755 /odoo/custom_addons/mfa_auth
   ```

3. **Restart Odoo Service**
   ```bash
   sudo systemctl restart odoo
   ```

4. **Install Module in Odoo**
   - Go to Apps menu
   - Search for "MFA Authentication System"
   - Click Install

## 📖 Usage Guide

### For Users

#### Setting Up MFA
1. Go to your user profile (Settings → Users & Companies → Users)
2. Click on the "Multi-Factor Authentication" tab
3. Click "Setup MFA"
4. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)
5. Enter the 6-digit verification code
6. Save your backup codes in a secure location

#### Logging In with MFA
1. Enter your username and password as usual
2. If MFA is enabled, you'll be redirected to the MFA verification page
3. Enter the 6-digit code from your authenticator app
4. Or use a backup code if you can't access your authenticator

### For Administrators

#### Managing User MFA
1. Go to Settings → Users & Companies → Users
2. Select a user and go to the "Multi-Factor Authentication" tab
3. View MFA status and settings
4. Force MFA for specific users by adding them to the "MFA Required" group

#### Viewing Audit Logs
1. Go to Settings → MFA Audit Log
2. View all MFA-related activities
3. Filter by user, action type, or date range
4. Export logs for compliance reporting

#### Security Groups
- **MFA Required**: Users in this group must use MFA
- **MFA Administrator**: Can manage MFA settings for all users

## 🔧 Configuration

### Global Settings
The module automatically integrates with Odoo's authentication system. No additional configuration is required for basic functionality.

### Advanced Configuration
- **Session Timeout**: Configure in Odoo's session settings
- **Account Lockout**: Automatically locks accounts after 5 failed attempts for 15 minutes
- **Backup Codes**: 10 codes generated per user, single-use only

## 🛡️ Security Features

### Authentication Security
- **TOTP Algorithm**: RFC 6238 compliant time-based tokens
- **Secret Encryption**: TOTP secrets are stored securely
- **Time Synchronization**: 30-second window for token validation
- **Backup Code Protection**: Single-use backup codes

### Audit & Compliance
- **Complete Logging**: All MFA actions are logged with timestamps
- **IP Tracking**: IP addresses recorded for security monitoring
- **User Agent Logging**: Browser/device information captured
- **Failed Attempt Tracking**: Monitoring of suspicious activity

### Data Protection
- **GDPR Compliance**: User data handling follows privacy regulations
- **Secure Storage**: Sensitive data encrypted at rest
- **Access Controls**: Proper permission management
- **Data Retention**: Configurable log retention policies

## 🧪 Testing

### Test Scenarios
1. **Module Installation**: Verify no errors during installation
2. **MFA Setup**: Test QR code generation and verification
3. **Authentication Flow**: Test login with MFA enabled
4. **Backup Codes**: Test backup code usage
5. **Account Lockout**: Test failed attempt handling
6. **Audit Logging**: Verify all actions are logged

### Demo Data
The module includes demo data for testing:
- Demo user with MFA enabled
- Sample audit log entries
- Test backup codes

## 🚨 Troubleshooting

### Common Issues

#### Module Installation Errors
- **Missing Dependencies**: Ensure all Python packages are installed
- **Permission Issues**: Check file ownership and permissions
- **JavaScript Errors**: Module doesn't include JavaScript assets to avoid minification issues

#### Authentication Issues
- **Time Synchronization**: Ensure server and client time are synchronized
- **QR Code Not Working**: Try manual secret entry in authenticator app
- **Backup Codes Not Working**: Ensure codes are entered exactly as shown

#### Performance Issues
- **Slow Login**: Check server resources and database performance
- **Memory Usage**: Monitor Odoo server memory consumption
- **Database Size**: Audit logs may grow large over time

### Error Prevention
This module has been designed to avoid common Odoo 17 issues:
- ✅ No `_check_credentials` method override
- ✅ No JavaScript assets in manifest
- ✅ Proper Odoo 17 XML syntax
- ✅ Complete field access rules
- ✅ Proper error handling

## 📋 Requirements

### System Requirements
- Odoo 17.0+
- Python 3.8+
- PostgreSQL 12+
- Ubuntu 20.04+ (recommended)

### Python Dependencies
- `pyotp>=2.8.0`: TOTP implementation
- `qrcode>=7.3.1`: QR code generation
- `cryptography>=3.4.8`: Encryption support

## 📄 License

This module is licensed under LGPL-3. See the LICENSE file for details.

## 🤝 Contributing

This is a university project module. For contributions or issues, please contact the development team.

## 📞 Support

For technical support or questions:
- Check the troubleshooting section above
- Review Odoo 17 documentation
- Contact your system administrator

## 🔄 Version History

- **17.0.1.0.0**: Initial release
  - TOTP authentication
  - QR code generation
  - Backup codes
  - Audit logging
  - Security compliance features

---

**Note**: This module has been specifically designed for Odoo 17 and follows all best practices to avoid common implementation errors. It provides a clean, reliable MFA solution for production use.