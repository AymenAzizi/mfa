from odoo import models, fields, api

class MfaLog(models.Model):
    _name = 'mfa.log'
    _description = 'MFA Audit Log'
    _order = 'create_date desc'
    _rec_name = 'description'
    
    user_id = fields.Many2one('res.users', 'User', required=True)
    action = fields.Selection([
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('setup', 'Setup'),
        ('disable', 'Disabled'),
        ('backup_used', 'Backup Code Used'),
    ], 'Action', required=True)
    description = fields.Text('Description')
    ip_address = fields.Char('IP Address')
    user_agent = fields.Text('User Agent')
    create_date = fields.Datetime('Date', default=fields.Datetime.now)
    
    @api.model
    def create_log(self, user_id, action, description, ip_address=None, user_agent=None):
        """Create audit log entry"""
        return self.create({
            'user_id': user_id,
            'action': action,
            'description': description,
            'ip_address': ip_address,
            'user_agent': user_agent,
        })