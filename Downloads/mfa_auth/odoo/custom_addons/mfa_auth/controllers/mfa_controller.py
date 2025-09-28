# -*- coding: utf-8 -*-

from odoo import http, _
from odoo.http import request
from odoo.addons.web.controllers.main import Home
import pyotp


class MFAHome(Home):
    """Extended Home controller for MFA integration"""

    @http.route('/web/login', type='http', auth="none")
    def web_login(self, redirect=None, **kw):
        """Override login to handle MFA"""
        # First perform normal login
        response = super(MFAHome, self).web_login(redirect=redirect, **kw)
        
        # Check if login was successful and MFA is required
        if request.httprequest.method == 'POST' and request.session.uid:
            user = request.env['res.users'].browse(request.session.uid)
            
            # Check if MFA is required for this user
            if user.mfa_enabled and not request.session.get('mfa_verified'):
                # Redirect to MFA verification page
                return request.redirect('/web/mfa/verify_form')
        
        return response

    @http.route('/web/mfa/verify_form', type='http', auth='user', website=False)
    def mfa_verify_form(self):
        """MFA verification form"""
        user = request.env.user
        
        # Check if MFA is already verified
        if request.session.get('mfa_verified'):
            return request.redirect('/web')
        
        # Check if MFA is required
        if not user.mfa_enabled:
            return request.redirect('/web')
        
        return request.render('mfa_auth.mfa_verify_template', {
            'user': user,
        })

    @http.route('/web/mfa/verify', type='http', auth='user', methods=['POST'], website=False)
    def mfa_verify(self, **kw):
        """Verify MFA code"""
        user = request.env.user
        code = kw.get('code', '').strip()
        
        if not code:
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': 'Please enter a verification code'
            })
        
        # Verify TOTP code
        if user.verify_totp_code(code):
            # Mark MFA as verified
            request.session['mfa_verified'] = True
            
            # Log successful verification
            request.env['mfa.log'].create({
                'user_id': user.id,
                'action': 'verify',
                'ip_address': request.httprequest.environ.get('REMOTE_ADDR'),
                'user_agent': request.httprequest.environ.get('HTTP_USER_AGENT'),
                'success': True,
                'notes': 'MFA verification successful'
            })
            
            return request.redirect('/web')
        else:
            # Log failed attempt
            request.env['mfa.log'].create({
                'user_id': user.id,
                'action': 'failed',
                'ip_address': request.httprequest.environ.get('REMOTE_ADDR'),
                'user_agent': request.httprequest.environ.get('HTTP_USER_AGENT'),
                'success': False,
                'notes': 'Invalid MFA code'
            })
            
            return request.render('mfa_auth.mfa_verify_template', {
                'user': user,
                'error': 'Invalid verification code. Please try again.'
            })