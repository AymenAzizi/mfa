from odoo import models, fields, api
from odoo.exceptions import ValidationError, UserError
import pyotp
import qrcode
import base64
from io import BytesIO
import secrets
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
    mfa_failed_attempts = fields.Integer('MFA Failed Attempts', default=0)
    mfa_locked_until = fields.Datetime('MFA Locked Until')
    
    @api.depends('groups_id')
    def _compute_force_mfa(self):
        """Compute if MFA is forced for this user based on groups"""
        for user in self:
            user.force_mfa = user.has_group('mfa_auth.group_mfa_required')
    
    def generate_totp_secret(self):
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    def generate_qr_code(self):
        """Generate QR code for TOTP setup"""
        self.ensure_one()
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
        self.ensure_one()
        if not self.totp_secret or not token:
            return False
        
        # Check if account is locked
        if self.mfa_locked_until and fields.Datetime.now() < self.mfa_locked_until:
            raise UserError("Account is temporarily locked due to too many failed MFA attempts.")
        
        # Clean the token (remove spaces and convert to string)
        token = str(token).replace(' ', '').strip()
        
        if len(token) != 6 or not token.isdigit():
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        is_valid = totp.verify(token, valid_window=1)
        
        if is_valid:
            # Reset failed attempts on success
            self.sudo().write({
                'mfa_failed_attempts': 0,
                'mfa_locked_until': False,
            })
        else:
            # Increment failed attempts
            failed_attempts = self.mfa_failed_attempts + 1
            vals = {'mfa_failed_attempts': failed_attempts}
            
            # Lock account after 5 failed attempts for 15 minutes
            if failed_attempts >= 5:
                vals['mfa_locked_until'] = fields.Datetime.now() + fields.timedelta(minutes=15)
            
            self.sudo().write(vals)
        
        return is_valid
    
    def verify_backup_code(self, code):
        """Verify backup code"""
        self.ensure_one()
        if not self.totp_backup_codes or not code:
            return False
        
        backup_codes = self.totp_backup_codes.split('\n')
        code = code.strip().upper()
        
        if code in backup_codes:
            # Remove used backup code
            backup_codes.remove(code)
            self.totp_backup_codes = '\n'.join(backup_codes)
            
            # Reset failed attempts on success
            self.sudo().write({
                'mfa_failed_attempts': 0,
                'mfa_locked_until': False,
            })
            return True
        
        return False
    
    def generate_backup_codes(self):
        """Generate backup codes"""
        self.ensure_one()
        codes = []
        for _ in range(10):
            codes.append(secrets.token_hex(4).upper())
        self.totp_backup_codes = '\n'.join(codes)
        return codes
    
    def action_setup_mfa(self):
        """Open MFA setup wizard"""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Setup Multi-Factor Authentication',
            'res_model': 'mfa.setup.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_user_id': self.id},
        }
    
    def action_disable_mfa(self):
        """Disable MFA for user"""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Disable Multi-Factor Authentication',
            'res_model': 'mfa.disable.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_user_id': self.id},
        }
    
    def disable_mfa(self):
        """Disable MFA and clear secrets"""
        self.ensure_one()
        self.write({
            'mfa_enabled': False,
            'totp_secret': False,
            'totp_backup_codes': False,
            'mfa_verified': False,
            'mfa_failed_attempts': 0,
            'mfa_locked_until': False,
        })
        
        # Log the action
        self.env['mfa.log'].sudo().create({
            'user_id': self.id,
            'action': 'disable',
            'description': 'MFA disabled by user',
            'ip_address': self.env.context.get('client_ip', 'Unknown'),
        })