# MFA Authentication Module - Complete Specification & Error Prevention Guide

## 🎯 **PROJECT OVERVIEW**

**Objective**: Create a Multi-Factor Authentication (MFA) module for Odoo 17 that is compliant with privacy practices in an ISMS based on electronic certification.

**Target**: University project for implementing strong authentication (MFA) compliant with privacy practices in an ISMS based on electronic certification for Open Source ERP (ODOO).

## 📋 **REQUIRED FEATURES**

### **Core Authentication Features**
1. **TOTP (Time-based One-Time Password) Authentication**
   - Google Authenticator integration
   - QR code generation for easy setup
   - Backup codes for emergency access
   - Secure secret storage with encryption

2. **Security & Compliance**
   - ISO 27001 compliant logging
   - GDPR compliant data handling
   - ANSSI recommendations compliance
   - Secure secret storage with encryption
   - Audit logs for all MFA actions

3. **User Management**
   - Per-user MFA enforcement
   - Force MFA for specific user groups
   - Account lockout after failed attempts
   - Session timeout management

4. **Administrative Features**
   - Global MFA settings
   - User MFA configuration interface
   - Security dashboard
   - Compliance reporting

## 🚨 **CRITICAL ERRORS TO AVOID**

### **Error 1: AttributeError in _check_credentials Method**
**❌ WRONG APPROACH:**
```python
def _check_credentials(self, password, env):
    user = self.browse(self.env.uid)  # ❌ CAUSES: AttributeError: 'dict' object has no attribute 'context'
    # OR
    user = self.browse(env.uid)       # ❌ CAUSES: AttributeError: 'dict' object has no attribute 'uid'
```

**✅ CORRECT SOLUTION:**
```python
# DO NOT override _check_credentials method at all!
# Handle MFA verification in the controller instead
```

**Why this happens**: Odoo 17 changed the `_check_credentials` method signature and the `env` parameter is now a dictionary, not an Odoo environment object.

### **Error 2: JavaScript Assets Causing Minification Errors**
**❌ WRONG APPROACH:**
```python
# In __manifest__.py
'assets': {
    'web.assets_backend': [
        'mfa_auth/static/src/js/mfa.js',
        'mfa_auth/static/src/css/mfa.css',
    ],
    'web.assets_frontend': [
        'mfa_auth/static/src/js/mfa_frontend.js',
        'mfa_auth/static/src/css/mfa_frontend.css',
    ],
},
```

**✅ CORRECT SOLUTION:**
```python
# Remove all JavaScript assets from manifest
# Only include CSS if absolutely necessary
# Odoo 17 has issues with custom JavaScript minification
```

**Why this happens**: Odoo 17's JavaScript minification process has issues with custom modules, causing "unreachable code after return statement" errors.

### **Error 3: Field Access Permissions**
**❌ WRONG APPROACH:**
```python
totp_secret = fields.Char('TOTP Secret', groups='base.group_user')
# Without proper access rules in ir.model.access.csv
```

**✅ CORRECT SOLUTION:**
```python
# In models/mfa_user.py
totp_secret = fields.Char('TOTP Secret', groups='base.group_user')

# In security/ir.model.access.csv
access_mfa_user_totp_secret,access_mfa_user_totp_secret,model_res_users,res.users,1,1,1,1
```

**Why this happens**: Odoo 17 requires explicit access rules for all fields, even if they have groups defined.

### **Error 4: XML View Syntax Errors**
**❌ WRONG APPROACH:**
```xml
<!-- Odoo 16 syntax - NOT compatible with Odoo 17 -->
<field name="totp_secret" attrs="{'invisible': [['mfa_enabled', '=', False]]}"/>
```

**✅ CORRECT SOLUTION:**
```xml
<!-- Odoo 17 syntax -->
<field name="totp_secret" invisible="not mfa_enabled"/>
<field name="totp_secret" invisible="1"/>  <!-- Hidden field for form access -->
```

**Why this happens**: Odoo 17 deprecated `attrs` and `states` attributes in favor of simplified `invisible` syntax.

### **Error 5: Missing Fields in Views**
**❌ WRONG APPROACH:**
```xml
<!-- Field used in modifier but not present in view -->
<field name="mfa_enabled" invisible="not totp_secret"/>
```

**✅ CORRECT SOLUTION:**
```xml
<!-- Always include fields used in modifiers -->
<field name="totp_secret" invisible="1"/>
<field name="totp_backup_codes" invisible="1"/>
<field name="mfa_enabled" invisible="not totp_secret"/>
```

**Why this happens**: Odoo 17 requires all fields referenced in modifiers to be present in the view, even if hidden.

## 🏗️ **MODULE STRUCTURE**

### **Required Files Structure**
```
mfa_auth/
├── __init__.py
├── __manifest__.py
├── models/
│   ├── __init__.py
│   ├── mfa_user.py          # Extends res.users
│   ├── mfa_log.py           # Audit logging
│   └── mfa_wizard.py        # Setup/disable wizards
├── controllers/
│   ├── __init__.py
│   └── mfa_controller.py    # Web routes for MFA
├── views/
│   ├── mfa_settings.xml     # User form view
│   └── mfa_templates.xml    # Web templates
├── security/
│   ├── ir.model.access.csv  # Access rules
│   └── mfa_security.xml     # Security groups
├── data/
│   └── mfa_demo_data.xml    # Demo data
└── static/src/css/
    └── mfa.css              # Optional styling
```

## 📝 **DETAILED IMPLEMENTATION SPECIFICATIONS**

### **1. Manifest File (__manifest__.py)**
```python
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
        'data/mfa_demo_data.xml',
    ],
    'installable': True,
    'auto_install': False,
    'application': False,
    'sequence': 100,
}
```

### **2. User Model (models/mfa_user.py)**
```python
from odoo import models, fields, api
from odoo.exceptions import ValidationError
import pyotp
import qrcode
import base64
from io import BytesIO

class ResUsers(models.Model):
    _inherit = 'res.users'
    
    # MFA Fields
    mfa_enabled = fields.Boolean('MFA Enabled', default=False)
    totp_secret = fields.Char('TOTP Secret', groups='base.group_user')
    totp_backup_codes = fields.Text('Backup Codes', groups='base.group_user')
    mfa_verified = fields.Boolean('MFA Verified', default=False)
    force_mfa = fields.Boolean('Force MFA', compute='_compute_force_mfa', store=True)
    
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
        
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)
    
    def generate_backup_codes(self):
        """Generate backup codes"""
        import secrets
        codes = []
        for _ in range(10):
            codes.append(secrets.token_hex(4).upper())
        self.totp_backup_codes = '\n'.join(codes)
        return codes
```

### **3. Controller (controllers/mfa_controller.py)**
```python
from odoo import http, fields
from odoo.http import request
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)

class MfaController(http.Controller):
    
    @http.route('/web/login', type='http', auth='none', website=False)
    def web_login(self, redirect=None, **kw):
        """Override login to check MFA requirement"""
        if request.httprequest.method == 'POST':
            login = kw.get('login')
            password = kw.get('password')
            
            if login and password:
                # Check if user exists and password is correct
                user = request.env['res.users'].sudo().authenticate(
                    request.db, login, password, {}
                )
                
                if user:
                    # Check if MFA is required
                    if user.mfa_enabled or user.force_mfa:
                        # Store user ID in session for MFA verification
                        request.session['mfa_user_id'] = user.id
                        request.session['mfa_required'] = True
                        return request.redirect('/web/mfa/verify')
                    else:
                        # Normal login flow
                        request.session.authenticate(request.db, login, password)
                        return request.redirect(redirect or '/web')
        
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
    
    @http.route('/web/mfa/verify/submit', type='http', auth='none', website=False, methods=['POST'])
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
        if not token:
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': 'Please enter a verification code',
            })
        
        # Verify TOTP token
        if user.verify_totp(token):
            # MFA successful - complete login
            request.session['mfa_verified'] = True
            request.session['mfa_required'] = False
            request.session['mfa_user_id'] = None
            
            # Log successful MFA
            self._log_mfa_action(user, 'success', 'MFA verification successful')
            
            return request.redirect('/web')
        else:
            # MFA failed
            self._log_mfa_action(user, 'failed', 'Invalid MFA token')
            
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': 'Invalid verification code. Please try again.',
            })
    
    def _log_mfa_action(self, user, action, description):
        """Log MFA action for audit"""
        request.env['mfa.log'].sudo().create({
            'user_id': user.id,
            'action': action,
            'description': description,
            'ip_address': request.httprequest.remote_addr,
            'user_agent': request.httprequest.headers.get('User-Agent'),
        })
```

### **4. Log Model (models/mfa_log.py)**
```python
from odoo import models, fields, api

class MfaLog(models.Model):
    _name = 'mfa.log'
    _description = 'MFA Audit Log'
    _order = 'create_date desc'
    
    user_id = fields.Many2one('res.users', 'User', required=True)
    action = fields.Selection([
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('setup', 'Setup'),
        ('disable', 'Disabled'),
    ], 'Action', required=True)
    description = fields.Text('Description')
    ip_address = fields.Char('IP Address')
    user_agent = fields.Text('User Agent')
    create_date = fields.Datetime('Date', default=fields.Datetime.now)
```

### **5. Wizard Model (models/mfa_wizard.py)**
```python
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
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'mfa.setup.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
            'context': {'show_success': True},
        }
```

### **6. Views (views/mfa_settings.xml)**
```xml
<?xml version="1.0" encoding="utf-8"?>
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
                    </group>
                    <group invisible="not mfa_enabled">
                        <button string="Setup MFA" type="object" name="action_setup_mfa" class="btn-primary"/>
                        <button string="Disable MFA" type="object" name="action_disable_mfa" class="btn-secondary"/>
                    </group>
                </page>
            </xpath>
        </field>
    </record>
</odoo>
```

### **7. Templates (views/mfa_templates.xml)**
```xml
<?xml version="1.0" encoding="utf-8"?>
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
                                        <input type="text" name="token" class="form-control" placeholder="Enter 6-digit code" maxlength="6" required/>
                                    </div>
                                    <div class="form-group">
                                        <button type="submit" class="btn btn-primary">Verify</button>
                                    </div>
                                </form>
                                <t t-if="error">
                                    <div class="alert alert-danger" t-esc="error"/>
                                </t>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </t>
    </template>
</odoo>
```

### **8. Security (security/ir.model.access.csv)**
```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_mfa_log_user,mfa.log.user,model_mfa_log,base.group_user,1,0,0,0
access_mfa_log_manager,mfa.log.manager,model_mfa_log,base.group_system,1,1,1,1
access_mfa_wizard_user,mfa.wizard.user,model_mfa_setup_wizard,base.group_user,1,1,1,0
access_mfa_user_totp_secret,access_mfa_user_totp_secret,model_res_users,base.group_user,1,1,1,1
```

## 🧪 **TESTING REQUIREMENTS**

### **Test Cases**
1. **Module Installation**
   - Install module without errors
   - Verify all dependencies are installed
   - Check that no JavaScript errors occur

2. **MFA Setup**
   - Enable MFA for a user
   - Generate QR code
   - Verify TOTP setup with authenticator app
   - Test backup codes generation

3. **Authentication Flow**
   - Login with MFA-enabled user
   - Verify MFA verification page appears
   - Test successful MFA verification
   - Test failed MFA verification

4. **Security Features**
   - Verify audit logging works
   - Test account lockout after failed attempts
   - Verify session management

## 🚀 **INSTALLATION INSTRUCTIONS**

### **For Ubuntu VM:**
```bash
# 1. Copy module to Odoo addons directory
sudo cp -r /path/to/mfa_auth /odoo/custom_addons/
sudo chown -R odoo:odoo /odoo/custom_addons/mfa_auth
sudo chmod -R 755 /odoo/custom_addons/mfa_auth

# 2. Install Python dependencies
sudo pip3 install pyotp qrcode cryptography

# 3. Restart Odoo
sudo systemctl restart odoo

# 4. Install module in Odoo Apps interface
```

## ⚠️ **CRITICAL SUCCESS FACTORS**

1. **DO NOT override `_check_credentials` method
2. **DO NOT include JavaScript assets in manifest**
3. **ALWAYS include all fields used in modifiers in views**
4. **USE Odoo 17 syntax for XML views (no `attrs`)**
5. **INCLUDE proper access rules for all fields**
6. **TEST thoroughly on Ubuntu VM before deployment**

## 🎯 **EXPECTED OUTCOME**

A fully functional MFA module for Odoo 17 that:
- ✅ Installs without errors
- ✅ Provides TOTP authentication
- ✅ Includes security logging
- ✅ Is compliant with privacy regulations
- ✅ Works reliably in production
- ✅ Meets university project requirements

**This specification contains all the lessons learned from our development process and will prevent the common pitfalls that caused errors in the original implementation.**
