# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError


class MFASetupWizard(models.TransientModel):
    _name = 'mfa.setup.wizard'
    _description = 'MFA Setup Wizard'

    user_id = fields.Many2one(
        'res.users',
        string='User',
        required=True,
        default=lambda self: self.env.user
    )
    
    qr_code = fields.Char(
        string='QR Code',
        readonly=True,
        help='QR code for authenticator app setup'
    )
    
    backup_codes = fields.Text(
        string='Backup Codes',
        readonly=True,
        help='Emergency backup codes'
    )

    @api.model
    def default_get(self, fields_list):
        """Set default values"""
        res = super().default_get(fields_list)
        if 'user_id' in fields_list and not res.get('user_id'):
            res['user_id'] = self.env.user.id
        return res

    @api.model
    def create(self, vals):
        """Create wizard and generate QR code"""
        wizard = super().create(vals)
        if wizard.user_id and wizard.user_id.totp_secret:
            wizard.qr_code = wizard.user_id.get_qr_code()
            wizard.backup_codes = wizard.user_id.totp_backup_codes
        return wizard

    def action_enable_mfa(self):
        """Enable MFA for user"""
        if not self.user_id:
            raise UserError(_('No user selected'))
        
        self.user_id.mfa_enabled = True
        return {
            'type': 'ir.actions.client',
            'tag': 'reload',
        }