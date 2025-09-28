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