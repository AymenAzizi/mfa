{
    'name': 'MFA Authentication System',
    'version': '17.0.1.0.0',
    'category': 'Authentication',
    'summary': 'Multi-Factor Authentication for Odoo 17',
    'description': """
        MFA Authentication System for Odoo 17
        =====================================
        
        Features:
        * TOTP (Time-based One-Time Password) authentication
        * Google Authenticator integration
        * Security logging and compliance tracking
        * Per-user MFA enforcement
        * Simple and reliable implementation
        
        Security & Compliance:
        * ISO 27001 compliant logging
        * GDPR compliant data handling
        * Secure secret storage with encryption
        * ANSSI recommendations compliance
    """,
    'author': 'University Project Team',
    'website': 'https://github.com/university/mfa-auth-odoo',
    'license': 'LGPL-3',
    'depends': [
        'base',
        'web',
    ],
    'external_dependencies': {
        'python': ['pyotp', 'qrcode', 'cryptography'],
    },
    'data': [
        'security/ir.model.access.csv',
        'security/mfa_security.xml',
        'views/mfa_settings.xml',
        'views/mfa_templates.xml',
    ],
    'installable': True,
    'auto_install': False,
    'application': False,
    'sequence': 100,
}