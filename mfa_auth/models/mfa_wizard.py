from odoo import models, fields, api
from odoo.exceptions import ValidationError

class MfaSetupWizard(models.TransientModel):
    _name = 'mfa.setup.wizard'
    _description = 'MFA Setup Wizard'
    
    user_id = fields.Many2one('res.users', 'User', required=True)
    qr_code = fields.Binary('QR Code', readonly=True)
    totp_secret = fields.Char('TOTP Secret', readonly=True)
    verification_code = fields.Char('Verification Code')
    backup_codes = fields.Text('Backup Codes', readonly=True)
    show_success = fields.Boolean('Show Success', default=False)
    
    @api.model
    def default_get(self, fields_list):
        res = super().default_get(fields_list)
        if 'user_id' in fields_list:
            res['user_id'] = self.env.user.id
        return res
    
    @api.model
    def create(self, vals):
        wizard = super().create(vals)
        if wizard.user_id:
            wizard.qr_code = wizard.user_id.generate_qr_code()
            wizard.totp_secret = wizard.user_id.totp_secret
        return wizard
    
    def action_verify_and_enable(self):
        """Verify TOTP and enable MFA"""
        if not self.verification_code:
            raise ValidationError('Please enter a verification code')
        
        if not self.user_id.verify_totp(self.verification_code):
            raise ValidationError('Invalid verification code')
        
        # Enable MFA
        self.user_id.mfa_enabled = True
        
        # Generate backup codes
        backup_codes = self.user_id.generate_backup_codes()
        self.backup_codes = '\n'.join(backup_codes)
        self.show_success = True
        
        # Log MFA setup
        self.env['mfa.log'].create({
            'user_id': self.user_id.id,
            'action': 'setup',
            'description': 'MFA enabled successfully',
        })
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'mfa.setup.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
            'context': {'show_success': True},
        }
    
    def action_close(self):
        """Close wizard"""
        return {'type': 'ir.actions.act_window_close'}