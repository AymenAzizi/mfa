from odoo import http, fields
from odoo.http import request
from odoo.exceptions import ValidationError, UserError
from odoo.addons.web.controllers.home import Home
import logging

_logger = logging.getLogger(__name__)


class MfaController(http.Controller):
    
    @http.route('/web/mfa/verify', type='http', auth='none', website=False, csrf=False)
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
        
        error = kw.get('error', '')
        success = kw.get('success', '')
        
        return request.render('mfa_auth.mfa_verify_template', {
            'user': user,
            'error': error,
            'success': success,
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
        
        verification_success = False
        
        try:
            # Try TOTP verification first
            if token:
                verification_success = user.verify_totp(token)
            
            # Try backup code if TOTP failed
            if not verification_success and backup_code:
                verification_success = user.verify_backup_code(backup_code)
            
            if verification_success:
                # MFA successful - complete login
                request.session['mfa_verified'] = True
                request.session['mfa_required'] = False
                request.session['uid'] = user.id
                request.session.authenticate(request.db, user.login, request.session.get('mfa_password', ''))
                
                # Clear temporary session data
                request.session.pop('mfa_user_id', None)
                request.session.pop('mfa_password', None)
                
                # Log successful MFA
                self._log_mfa_action(user, 'success', 'MFA verification successful')
                
                return request.redirect('/web')
            else:
                # MFA failed
                self._log_mfa_action(user, 'failed', 'Invalid MFA token or backup code')
                
                return request.render('mfa_auth.mfa_verify_template', {
                    'user': user,
                    'error': 'Invalid verification code or backup code. Please try again.',
                })
        
        except UserError as e:
            # Handle account lockout
            self._log_mfa_action(user, 'locked', str(e))
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': str(e),
            })
        except Exception as e:
            _logger.error(f"MFA verification error: {e}")
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': 'An error occurred during verification. Please try again.',
            })
    
    def _log_mfa_action(self, user, action, description):
        """Log MFA action for audit"""
        try:
            request.env['mfa.log'].sudo().create({
                'user_id': user.id,
                'action': action,
                'description': description,
                'ip_address': request.httprequest.remote_addr or 'Unknown',
                'user_agent': request.httprequest.headers.get('User-Agent', 'Unknown'),
            })
        except Exception as e:
            _logger.error(f"Failed to log MFA action: {e}")


class HomeInherit(Home):
    """Inherit Home controller to add MFA check after login"""
    
    @http.route()
    def web_login(self, redirect=None, **kw):
        """Override login to add MFA check"""
        # First, call the original login method
        response = super().web_login(redirect=redirect, **kw)
        
        # Check if login was successful and MFA is required
        if request.session.uid and request.httprequest.method == 'POST':
            user = request.env['res.users'].sudo().browse(request.session.uid)
            
            # Check if MFA is required for this user
            if user.exists() and (user.mfa_enabled or user.force_mfa):
                # Store necessary data for MFA verification
                request.session['mfa_required'] = True
                request.session['mfa_user_id'] = user.id
                request.session['mfa_password'] = kw.get('password', '')
                
                # Clear the session uid temporarily
                request.session.pop('uid', None)
                
                # Redirect to MFA verification
                return request.redirect('/web/mfa/verify')
        
        return response