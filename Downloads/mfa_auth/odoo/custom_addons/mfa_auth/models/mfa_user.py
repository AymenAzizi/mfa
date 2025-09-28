# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import pyotp
import qrcode
import base64
from io import BytesIO


class ResUsers(models.Model):
    _inherit = 'res.users'

    # MFA Fields
    mfa_enabled = fields.Boolean(
        string='MFA Enabled',
        default=False,
        help='Enable Multi-Factor Authentication for this user'
    )
    
    totp_secret = fields.Char(
        string='TOTP Secret',
        help='Encrypted TOTP secret for Google Authenticator',
        groups='base.group_user'
    )
    
    totp_backup_codes = fields.Text(
        string='Backup Codes',
        help='Encrypted backup codes for emergency access',
        groups='base.group_user'
    )
    
    last_mfa_success = fields.Datetime(
        string='Last MFA Success',
        readonly=True,
        help='Last successful MFA verification'
    )
    
    mfa_attempts = fields.Integer(
        string='Failed MFA Attempts',
        default=0,
        help='Number of consecutive failed MFA attempts'
    )
    
    mfa_locked_until = fields.Datetime(
        string='MFA Locked Until',
        readonly=True,
        help='Account locked until this time due to failed attempts'
    )

    def action_setup_mfa(self):
        """Setup MFA for user"""
        if self.mfa_enabled:
            raise ValidationError(_('MFA is already enabled for this user'))
        
        # Generate secret
        secret = pyotp.random_base32()
        self.totp_secret = secret
        
        # Generate backup codes
        import secrets
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        self.totp_backup_codes = '\n'.join(backup_codes)
        
        return {
            'type': 'ir.actions.act_window',
            'name': 'Setup MFA',
            'res_model': 'mfa.setup.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_user_id': self.id}
        }

    def action_disable_mfa(self):
        """Disable MFA for user"""
        self.mfa_enabled = False
        self.totp_secret = False
        self.totp_backup_codes = False
        self.mfa_attempts = 0
        self.mfa_locked_until = False
        return True

    def action_reset_mfa_attempts(self):
        """Reset failed MFA attempts"""
        self.mfa_attempts = 0
        self.mfa_locked_until = False
        return True

    def verify_totp_code(self, code):
        """Verify TOTP code"""
        if not self.totp_secret:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code)

    def get_qr_code(self):
        """Get QR code for setup"""
        if not self.totp_secret:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=self.login,
            issuer_name='Odoo ERP'
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return img_str