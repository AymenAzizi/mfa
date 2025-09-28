# -*- coding: utf-8 -*-

from odoo import models, fields, api
from datetime import datetime


class MFALog(models.Model):
    _name = 'mfa.log'
    _description = 'MFA Log'
    _order = 'create_date desc'

    user_id = fields.Many2one(
        'res.users',
        string='User',
        required=True
    )
    
    action = fields.Selection([
        ('login', 'Login'),
        ('setup', 'MFA Setup'),
        ('disable', 'MFA Disabled'),
        ('verify', 'MFA Verification'),
        ('failed', 'Failed Attempt'),
    ], string='Action', required=True)
    
    ip_address = fields.Char(
        string='IP Address',
        help='IP address of the user'
    )
    
    user_agent = fields.Text(
        string='User Agent',
        help='Browser user agent'
    )
    
    success = fields.Boolean(
        string='Success',
        default=True,
        help='Whether the action was successful'
    )
    
    notes = fields.Text(
        string='Notes',
        help='Additional information'
    )