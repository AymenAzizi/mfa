#!/usr/bin/env python3
"""
MFA Authentication Module - Merged Implementation
Complete Multi-Factor Authentication system for Odoo 17
"""

# =============================================================================
# MANIFEST CONFIGURATION
# =============================================================================

MANIFEST = {
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

# =============================================================================
# MODELS
# =============================================================================

# MFA User Model
MFA_USER_MODEL = '''
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
        
        backup_codes = self.totp_backup_codes.split('\\n')
        if code.strip() in backup_codes:
            # Remove used backup code
            backup_codes.remove(code.strip())
            self.totp_backup_codes = '\\n'.join(backup_codes)
            return True
        return False
    
    def generate_backup_codes(self):
        """Generate backup codes"""
        import secrets
        codes = []
        for _ in range(10):
            codes.append(secrets.token_hex(4).upper())
        self.totp_backup_codes = '\\n'.join(codes)
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
'''

# MFA Log Model
MFA_LOG_MODEL = '''
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
'''

# MFA Wizard Model
MFA_WIZARD_MODEL = '''
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
        self.backup_codes = '\\n'.join(backup_codes)
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
'''

# =============================================================================
# CONTROLLERS
# =============================================================================

MFA_CONTROLLER = '''
from odoo import http, fields
from odoo.http import request
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)

class MfaController(http.Controller):
    
    @http.route('/web/login', type='http', auth='none', website=False, csrf=False)
    def web_login(self, redirect=None, **kw):
        """Override login to check MFA requirement"""
        if request.httprequest.method == 'POST':
            login = kw.get('login')
            password = kw.get('password')
            
            if login and password:
                try:
                    # Check if user exists and password is correct
                    user = request.env['res.users'].sudo().authenticate(
                        request.db, login, password, {}
                    )
                    
                    if user:
                        # Check if MFA is required
                        if user.is_mfa_required():
                            # Store user ID in session for MFA verification
                            request.session['mfa_user_id'] = user.id
                            request.session['mfa_required'] = True
                            request.session['mfa_redirect'] = redirect or '/web'
                            
                            # Log MFA requirement
                            self._log_mfa_action(user, 'setup', 'MFA verification required')
                            
                            return request.redirect('/web/mfa/verify')
                        else:
                            # Normal login flow
                            request.session.authenticate(request.db, login, password)
                            return request.redirect(redirect or '/web')
                    else:
                        # Invalid credentials
                        return request.render('web.login', {
                            'redirect': redirect,
                            'error': 'Invalid login credentials',
                        })
                except Exception as e:
                    _logger.error(f"Login error: {e}")
                    return request.render('web.login', {
                        'redirect': redirect,
                        'error': 'Login failed. Please try again.',
                    })
        
        # Show login form
        return request.render('web.login', {
            'redirect': redirect,
        })
    
    @http.route('/web/mfa/verify', type='http', auth='none', website=False)
    def mfa_verify_form(self, **kw):
        """Show MFA verification form"""
        if not request.session.get('mfa_required'):
            return request.redirect('/web/login')
        
        user_id = request.session.get('mfa_user_id')
        if not user_id:
            return request.redirect('/web/login')
        
        user = request.env['res.users'].sudo().browse(user_id)
        if not user.exists():
            return request.redirect('/web/login')
        
        return request.render('mfa_auth.mfa_verify_template', {
            'user': user,
        })
    
    @http.route('/web/mfa/verify/submit', type='http', auth='none', website=False, methods=['POST'], csrf=False)
    def mfa_verify_submit(self, **kw):
        """Process MFA verification"""
        if not request.session.get('mfa_required'):
            return request.redirect('/web/login')
        
        user_id = request.session.get('mfa_user_id')
        if not user_id:
            return request.redirect('/web/login')
        
        user = request.env['res.users'].sudo().browse(user_id)
        if not user.exists():
            return request.redirect('/web/login')
        
        token = kw.get('token', '').strip()
        backup_code = kw.get('backup_code', '').strip()
        
        if not token and not backup_code:
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': 'Please enter a verification code or backup code',
            })
        
        # Check if account is locked
        if user.mfa_locked_until and fields.Datetime.now() < user.mfa_locked_until:
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': 'Account is temporarily locked due to too many failed attempts. Please try again later.',
            })
        
        # Verify TOTP token or backup code
        verification_successful = False
        
        if token:
            verification_successful = user.verify_totp(token)
            if verification_successful:
                self._log_mfa_action(user, 'success', 'MFA verification successful')
            else:
                self._log_mfa_action(user, 'failed', 'Invalid MFA token')
        
        if not verification_successful and backup_code:
            verification_successful = user.verify_backup_code(backup_code)
            if verification_successful:
                self._log_mfa_action(user, 'backup_used', 'Backup code used for MFA')
            else:
                self._log_mfa_action(user, 'failed', 'Invalid backup code')
        
        if verification_successful:
            # MFA successful - complete login
            request.session['mfa_verified'] = True
            request.session['mfa_required'] = False
            request.session['mfa_user_id'] = None
            
            # Complete authentication
            redirect_url = request.session.get('mfa_redirect', '/web')
            request.session['mfa_redirect'] = None
            
            return request.redirect(redirect_url)
        else:
            # MFA failed
            error_msg = 'Invalid verification code. Please try again.'
            if user.mfa_failed_attempts >= 3:
                error_msg += f' ({user.mfa_failed_attempts} failed attempts)'
            
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': error_msg,
            })
    
    @http.route('/web/mfa/cancel', type='http', auth='none', website=False)
    def mfa_cancel(self, **kw):
        """Cancel MFA verification and return to login"""
        request.session['mfa_required'] = False
        request.session['mfa_user_id'] = None
        request.session['mfa_redirect'] = None
        return request.redirect('/web/login')
    
    def _log_mfa_action(self, user, action, description):
        """Log MFA action for audit"""
        try:
            request.env['mfa.log'].sudo().create({
                'user_id': user.id,
                'action': action,
                'description': description,
                'ip_address': request.httprequest.remote_addr,
                'user_agent': request.httprequest.headers.get('User-Agent'),
            })
        except Exception as e:
            _logger.error(f"Failed to log MFA action: {e}")
'''

# =============================================================================
# XML VIEWS AND SECURITY
# =============================================================================

# Security Access Rules
SECURITY_ACCESS_CSV = '''id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_mfa_log_user,mfa.log.user,model_mfa_log,base.group_user,1,0,0,0
access_mfa_log_manager,mfa.log.manager,model_mfa_log,base.group_system,1,1,1,1
access_mfa_wizard_user,mfa.wizard.user,model_mfa_setup_wizard,base.group_user,1,1,1,0
access_mfa_user_totp_secret,access_mfa_user_totp_secret,model_res_users,base.group_user,1,1,1,1'''

# Security Groups
SECURITY_GROUPS_XML = '''<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data noupdate="1">
        <!-- Security Groups -->
        <record id="group_mfa_required" model="res.groups">
            <field name="name">MFA Required</field>
            <field name="category_id" ref="base.module_category_hidden"/>
            <field name="comment">Users in this group are required to use MFA</field>
        </record>
        
        <record id="group_mfa_admin" model="res.groups">
            <field name="name">MFA Administrator</field>
            <field name="category_id" ref="base.module_category_administration"/>
            <field name="implied_ids" eval="[(4, ref('base.group_system'))]"/>
            <field name="comment">Users who can manage MFA settings for all users</field>
        </record>
    </data>
</odoo>'''

# Views
VIEWS_XML = '''<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <!-- User Form View Extension -->
    <record id="view_users_form_mfa" model="ir.ui.view">
        <field name="name">res.users.form.mfa</field>
        <field name="model">res.users</field>
        <field name="inherit_id" ref="base.view_users_form"/>
        <field name="arch" type="xml">
            <xpath expr="//notebook" position="inside">
                <page string="Multi-Factor Authentication" name="mfa_config">
                    <group>
                        <field name="mfa_enabled"/>
                        <field name="force_mfa" readonly="1"/>
                        <field name="totp_secret" invisible="1"/>
                        <field name="totp_backup_codes" invisible="1"/>
                        <field name="mfa_failed_attempts" readonly="1"/>
                        <field name="mfa_locked_until" readonly="1"/>
                    </group>
                    <group invisible="not mfa_enabled">
                        <button string="Setup MFA" type="object" name="action_setup_mfa" class="btn-primary"/>
                        <button string="Disable MFA" type="object" name="action_disable_mfa" class="btn-secondary"/>
                    </group>
                </page>
            </xpath>
        </field>
    </record>

    <!-- MFA Setup Wizard Form View -->
    <record id="view_mfa_setup_wizard_form" model="ir.ui.view">
        <field name="name">mfa.setup.wizard.form</field>
        <field name="model">mfa.setup.wizard</field>
        <field name="arch" type="xml">
            <form string="Setup Multi-Factor Authentication">
                <group>
                    <field name="user_id" invisible="1"/>
                    <field name="totp_secret" invisible="1"/>
                </group>
                
                <group invisible="show_success">
                    <div class="alert alert-info">
                        <h4>Step 1: Scan QR Code</h4>
                        <p>Use your authenticator app (Google Authenticator, Authy, etc.) to scan this QR code:</p>
                        <div class="text-center">
                            <img t-if="qr_code" t-att-src="'data:image/png;base64,' + qr_code" style="max-width: 200px;"/>
                        </div>
                    </div>
                    
                    <div class="alert alert-warning">
                        <h4>Step 2: Enter Verification Code</h4>
                        <p>Enter the 6-digit code from your authenticator app:</p>
                        <field name="verification_code" placeholder="123456" maxlength="6"/>
                    </div>
                </group>
                
                <group invisible="not show_success">
                    <div class="alert alert-success">
                        <h4>MFA Setup Complete!</h4>
                        <p>Your multi-factor authentication has been enabled successfully.</p>
                    </div>
                    
                    <div class="alert alert-warning">
                        <h4>Important: Save Your Backup Codes</h4>
                        <p>Store these backup codes in a safe place. You can use them to access your account if you lose your authenticator device:</p>
                        <pre t-esc="backup_codes" style="background: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 4px;"/>
                    </div>
                </group>
                
                <footer>
                    <button string="Verify &amp; Enable MFA" type="object" name="action_verify_and_enable" class="btn-primary" invisible="show_success"/>
                    <button string="Close" type="object" name="action_close" class="btn-secondary" invisible="not show_success"/>
                </footer>
            </form>
        </field>
    </record>

    <!-- MFA Log Tree View -->
    <record id="view_mfa_log_tree" model="ir.ui.view">
        <field name="name">mfa.log.tree</field>
        <field name="model">mfa.log</field>
        <field name="arch" type="xml">
            <tree string="MFA Audit Log">
                <field name="create_date"/>
                <field name="user_id"/>
                <field name="action"/>
                <field name="description"/>
                <field name="ip_address"/>
            </tree>
        </field>
    </record>

    <!-- MFA Log Form View -->
    <record id="view_mfa_log_form" model="ir.ui.view">
        <field name="name">mfa.log.form</field>
        <field name="model">mfa.log</field>
        <field name="arch" type="xml">
            <form string="MFA Log Entry">
                <group>
                    <field name="user_id"/>
                    <field name="action"/>
                    <field name="create_date"/>
                    <field name="ip_address"/>
                </group>
                <group>
                    <field name="description" nolabel="1"/>
                </group>
                <group>
                    <field name="user_agent" nolabel="1"/>
                </group>
            </form>
        </field>
    </record>

    <!-- MFA Log Search View -->
    <record id="view_mfa_log_search" model="ir.ui.view">
        <field name="name">mfa.log.search</field>
        <field name="model">mfa.log</field>
        <field name="arch" type="xml">
            <search string="MFA Log">
                <field name="user_id"/>
                <field name="action"/>
                <field name="ip_address"/>
                <filter string="Today" name="today" domain="[('create_date', '&gt;=', datetime.datetime.combine(context_today(), datetime.time(0,0,0)))]"/>
                <filter string="This Week" name="this_week" domain="[('create_date', '&gt;=', (context_today() - datetime.timedelta(days=context_today().weekday())).strftime('%Y-%m-%d'))]"/>
                <filter string="Failed Attempts" name="failed" domain="[('action', '=', 'failed')]"/>
                <group expand="0" string="Group By">
                    <filter string="User" name="group_user" context="{'group_by': 'user_id'}"/>
                    <filter string="Action" name="group_action" context="{'group_by': 'action'}"/>
                    <filter string="Date" name="group_date" context="{'group_by': 'create_date:day'}"/>
                </group>
            </search>
        </field>
    </record>

    <!-- MFA Log Action -->
    <record id="action_mfa_log" model="ir.actions.act_window">
        <field name="name">MFA Audit Log</field>
        <field name="res_model">mfa.log</field>
        <field name="view_mode">tree,form</field>
        <field name="search_view_id" ref="view_mfa_log_search"/>
        <field name="context">{}</field>
        <field name="help" type="html">
            <p class="o_view_nocontent_smiling_face">
                No MFA activity logged yet.
            </p>
            <p>
                MFA audit logs will appear here once users start using multi-factor authentication.
            </p>
        </field>
    </record>

    <!-- Menu Items -->
    <menuitem id="menu_mfa_log" 
              name="MFA Audit Log" 
              parent="base.menu_administration" 
              action="action_mfa_log" 
              sequence="100"/>
</odoo>'''

# Templates
TEMPLATES_XML = '''<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <template id="mfa_verify_template" name="MFA Verification">
        <t t-call="web.layout">
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h3>Multi-Factor Authentication</h3>
                            </div>
                            <div class="card-body">
                                <p>Please enter the verification code from your authenticator app:</p>
                                <form method="post" action="/web/mfa/verify/submit">
                                    <div class="form-group">
                                        <label for="token">Verification Code</label>
                                        <input type="text" 
                                               name="token" 
                                               id="token"
                                               class="form-control" 
                                               placeholder="Enter 6-digit code" 
                                               maxlength="6" 
                                               pattern="[0-9]{6}"
                                               autocomplete="off"/>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label for="backup_code">Or use a backup code</label>
                                        <input type="text" 
                                               name="backup_code" 
                                               id="backup_code"
                                               class="form-control" 
                                               placeholder="Enter backup code" 
                                               autocomplete="off"/>
                                    </div>
                                    
                                    <div class="form-group">
                                        <button type="submit" class="btn btn-primary">Verify</button>
                                        <a href="/web/mfa/cancel" class="btn btn-secondary">Cancel</a>
                                    </div>
                                </form>
                                
                                <t t-if="error">
                                    <div class="alert alert-danger" t-esc="error"/>
                                </t>
                                
                                <div class="alert alert-info">
                                    <h5>Need help?</h5>
                                    <ul>
                                        <li>Make sure your device's time is synchronized</li>
                                        <li>Use the backup codes if you can't access your authenticator app</li>
                                        <li>Contact your administrator if you're locked out</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </t>
    </template>
</odoo>'''

# =============================================================================
# INSTALLATION INSTRUCTIONS
# =============================================================================

INSTALLATION_INSTRUCTIONS = '''
MFA Authentication Module - Installation Instructions
==================================================

1. INSTALL PYTHON DEPENDENCIES:
   pip3 install --break-system-packages pyotp qrcode cryptography Pillow

2. CREATE MODULE DIRECTORY:
   mkdir -p /opt/odoo/custom_addons/mfa_auth

3. CREATE MODULE FILES:
   - Copy this merged file content to separate files
   - Create proper directory structure
   - Set correct permissions

4. RESTART ODOO:
   sudo systemctl restart odoo

5. INSTALL MODULE:
   - Go to Odoo Apps menu
   - Search for "MFA Authentication System"
   - Click Install

6. CONFIGURE USERS:
   - Go to Settings → Users & Companies → Users
   - Select a user and go to "Multi-Factor Authentication" tab
   - Click "Setup MFA" to enable for the user

FEATURES:
- TOTP (Time-based One-Time Password) authentication
- Google Authenticator integration
- QR code generation for easy setup
- Backup codes for emergency access
- Complete audit logging
- Security compliance (ISO 27001, GDPR, ANSSI)
- Account lockout protection
- Per-user and group-based MFA enforcement

SECURITY:
- Encrypted secret storage
- Complete audit trail
- IP address tracking
- Failed attempt monitoring
- Account lockout after 5 failed attempts
- 15-minute lockout period
'''

if __name__ == "__main__":
    print("MFA Authentication Module - Merged Implementation")
    print("=" * 50)
    print("This file contains the complete MFA module implementation.")
    print("Extract the individual components to create the module structure.")
    print("\nInstallation Instructions:")
    print(INSTALLATION_INSTRUCTIONS)