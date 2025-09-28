from odoo import models, fields, api
from odoo.exceptions import ValidationError
import pyotp
import qrcode
import base64
from io import BytesIO
import logging

_logger = logging.getLogger(__name__)

class ResUsers(models.Model):
    _inherit = 'res.users'
    
    # MFA Fields
    mfa_enabled = fields.Boolean('MFA Enabled', default=False)
    totp_secret = fields.Char('TOTP Secret', groups='base.group_user')
    totp_backup_codes = fields.Text('Backup Codes', groups='base.group_user')
    mfa_verified = fields.Boolean('MFA Verified', default=False)
    force_mfa = fields.Boolean('Force MFA', compute='_compute_force_mfa', store=True)
    mfa_failed_attempts = fields.Integer('Failed MFA Attempts', default=0)
    mfa_locked_until = fields.Datetime('MFA Locked Until')
    
    @api.depends('groups_id')
    def _compute_force_mfa(self):
        for user in self:
            user.force_mfa = user.has_group('mfa_auth.group_mfa_required')
    
    def generate_totp_secret(self):
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_qr_code(self):
        """Generate QR code for TOTP setup"""
        if not self.totp_secret:
            self.totp_secret = self.generate_totp_secret()
        
        totp = pyotp.TOTP(self.totp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=self.login,
            issuer_name="Odoo MFA"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code = base64.b64encode(buffer.getvalue()).decode()
        
        return qr_code
    
    def verify_totp(self, token):
        """Verify TOTP token"""
        if not self.totp_secret:
            return False
        
        # Check if account is locked
        if self.mfa_locked_until and fields.Datetime.now() < self.mfa_locked_until:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        is_valid = totp.verify(token, valid_window=1)
        
        if is_valid:
            # Reset failed attempts on successful verification
            self.mfa_failed_attempts = 0
            self.mfa_locked_until = False
        else:
            # Increment failed attempts
            self.mfa_failed_attempts += 1
            # Lock account after 5 failed attempts for 15 minutes
            if self.mfa_failed_attempts >= 5:
                self.mfa_locked_until = fields.Datetime.now() + fields.timedelta(minutes=15)
        
        return is_valid
    
    def verify_backup_code(self, code):
        """Verify backup code"""
        if not self.totp_backup_codes:
            return False
        
        backup_codes = self.totp_backup_codes.split('\n')
        if code.strip() in backup_codes:
            # Remove used backup code
            backup_codes.remove(code.strip())
            self.totp_backup_codes = '\n'.join(backup_codes)
            return True
        return False
    
    def generate_backup_codes(self):
        """Generate backup codes"""
        import secrets
        codes = []
        for _ in range(10):
            codes.append(secrets.token_hex(4).upper())
        self.totp_backup_codes = '\n'.join(codes)
        return codes
    
    def action_setup_mfa(self):
        """Open MFA setup wizard"""
        return {
            'type': 'ir.actions.act_window',
            'name': 'Setup MFA',
            'res_model': 'mfa.setup.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_user_id': self.id},
        }
    
    def action_disable_mfa(self):
        """Disable MFA for user"""
        self.mfa_enabled = False
        self.totp_secret = False
        self.totp_backup_codes = False
        self.mfa_verified = False
        self.mfa_failed_attempts = 0
        self.mfa_locked_until = False
        
        # Log MFA disable action
        self.env['mfa.log'].create({
            'user_id': self.id,
            'action': 'disable',
            'description': 'MFA disabled by user',
        })
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'MFA Disabled',
                'message': 'Multi-factor authentication has been disabled for your account.',
                'type': 'success',
            }
        }
    
    def is_mfa_required(self):
        """Check if MFA is required for this user"""
        return self.mfa_enabled or self.force_mfa