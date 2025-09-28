from odoo import models, fields, api


class MfaLog(models.Model):
    _name = 'mfa.log'
    _description = 'MFA Audit Log'
    _order = 'create_date desc'
    _rec_name = 'description'
    
    user_id = fields.Many2one('res.users', 'User', required=True, ondelete='cascade')
    action = fields.Selection([
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('setup', 'Setup'),
        ('disable', 'Disabled'),
        ('locked', 'Account Locked'),
    ], 'Action', required=True)
    description = fields.Text('Description', required=True)
    ip_address = fields.Char('IP Address')
    user_agent = fields.Text('User Agent')
    create_date = fields.Datetime('Date', default=fields.Datetime.now, readonly=True)
    
    def name_get(self):
        """Custom name_get to display meaningful names"""
        result = []
        for record in self:
            name = f"{record.user_id.name} - {record.action} - {record.create_date}"
            result.append((record.id, name))
        return result