# -*- coding: utf-8 -*-

import json
import logging
from datetime import timedelta
from odoo import http, fields, _
from odoo.http import request
from odoo.exceptions import AccessError, ValidationError

_logger = logging.getLogger(__name__)


class MFARestAPI(http.Controller):
    """REST API for MFA System Integration"""

    def _check_api_access(self):
        """Check API access permissions"""
        if not request.env.user.has_group('mfa_auth.group_mfa_admin'):
            raise AccessError(_('API access requires MFA Administrator privileges'))

    def _validate_api_key(self):
        """Validate API key (basic implementation)"""
        api_key = request.httprequest.headers.get('X-API-Key')
        configured_key = request.env['ir.config_parameter'].sudo().get_param('mfa_auth.api_key')
        
        if not api_key or api_key != configured_key:
            raise AccessError(_('Invalid or missing API key'))

    @http.route('/api/mfa/dashboard', type='json', auth='user', methods=['GET'])
    def get_dashboard_data(self):
        """Get MFA dashboard data"""
        try:
            self._check_api_access()
            dashboard = request.env['mfa.dashboard'].sudo()
            return {
                'success': True,
                'data': dashboard.get_dashboard_data()
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @http.route('/api/mfa/users', type='json', auth='user', methods=['GET'])
    def get_mfa_users(self):
        """Get list of users with MFA status"""
        try:
            self._check_api_access()
            users = request.env['res.users'].sudo().search([('active', '=', True)])
            
            user_data = []
            for user in users:
                user_data.append({
                    'id': user.id,
                    'name': user.name,
                    'login': user.login,
                    'email': user.email,
                    'mfa_enabled': user.mfa_enabled,
                    'mfa_method': user.mfa_method,
                    'last_mfa_success': user.last_mfa_success.isoformat() if user.last_mfa_success else None,
                    'mfa_attempts': user.mfa_attempts,
                    'force_mfa': user.force_mfa
                })
            
            return {
                'success': True,
                'data': user_data,
                'total': len(user_data)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @http.route('/api/mfa/user/<int:user_id>/enable', type='json', auth='user', methods=['POST'])
    def enable_user_mfa(self, user_id):
        """Enable MFA for a specific user"""
        try:
            self._check_api_access()
            user = request.env['res.users'].sudo().browse(user_id)
            
            if not user.exists():
                return {
                    'success': False,
                    'error': _('User not found')
                }
            
            user.write({
                'mfa_enabled': True,
                'mfa_method': 'totp'
            })
            
            # Generate TOTP secret
            secret = user.generate_totp_secret()
            qr_code = user.get_totp_qr_code()
            
            return {
                'success': True,
                'message': _('MFA enabled for user %s') % user.name,
                'data': {
                    'secret': secret,
                    'qr_code': qr_code
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @http.route('/api/mfa/user/<int:user_id>/disable', type='json', auth='user', methods=['POST'])
    def disable_user_mfa(self, user_id):
        """Disable MFA for a specific user"""
        try:
            self._check_api_access()
            user = request.env['res.users'].sudo().browse(user_id)
            
            if not user.exists():
                return {
                    'success': False,
                    'error': _('User not found')
                }
            
            user.action_disable_mfa()
            
            return {
                'success': True,
                'message': _('MFA disabled for user %s') % user.name
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @http.route('/api/mfa/logs', type='json', auth='user', methods=['GET'])
    def get_mfa_logs(self, limit=100, offset=0, user_id=None, action=None, success=None):
        """Get MFA logs with filtering"""
        try:
            self._check_api_access()
            
            domain = []
            if user_id:
                domain.append(('user_id', '=', int(user_id)))
            if action:
                domain.append(('action', '=', action))
            if success is not None:
                domain.append(('success', '=', bool(success)))
            
            logs = request.env['mfa.log'].sudo().search(
                domain, 
                limit=int(limit), 
                offset=int(offset), 
                order='timestamp desc'
            )
            
            log_data = []
            for log in logs:
                log_data.append({
                    'id': log.id,
                    'user_name': log.user_id.name,
                    'action': log.action,
                    'success': log.success,
                    'timestamp': log.timestamp.isoformat(),
                    'ip_address': log.ip_address,
                    'details': log.details
                })
            
            return {
                'success': True,
                'data': log_data,
                'total': len(log_data)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @http.route('/api/mfa/compliance/report', type='json', auth='user', methods=['POST'])
    def generate_compliance_report(self, report_type='iso27001', period_days=30):
        """Generate compliance report"""
        try:
            self._check_api_access()
            
            end_date = fields.Date.today()
            start_date = end_date - timedelta(days=int(period_days))
            
            report = request.env['mfa.compliance.report'].sudo().create({
                'name': f'{report_type.upper()} Report - {end_date}',
                'report_type': report_type,
                'period_start': start_date,
                'period_end': end_date
            })
            
            report.generate_report()
            
            return {
                'success': True,
                'data': {
                    'report_id': report.id,
                    'compliance_score': report.compliance_score,
                    'status': report.status
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @http.route('/api/mfa/stats', type='json', auth='user', methods=['GET'])
    def get_mfa_statistics(self):
        """Get MFA system statistics"""
        try:
            self._check_api_access()
            
            # User statistics
            total_users = request.env['res.users'].sudo().search_count([('active', '=', True)])
            mfa_users = request.env['res.users'].sudo().search_count([('mfa_enabled', '=', True)])
            locked_users = request.env['res.users'].sudo().search_count([
                ('mfa_locked_until', '>', fields.Datetime.now())
            ])
            
            # Recent activity (last 24 hours)
            yesterday = fields.Datetime.now() - timedelta(hours=24)
            recent_successful = request.env['mfa.log'].sudo().search_count([
                ('timestamp', '>=', yesterday),
                ('success', '=', True)
            ])
            recent_failed = request.env['mfa.log'].sudo().search_count([
                ('timestamp', '>=', yesterday),
                ('success', '=', False)
            ])
            
            return {
                'success': True,
                'data': {
                    'users': {
                        'total': total_users,
                        'mfa_enabled': mfa_users,
                        'locked': locked_users,
                        'adoption_rate': round((mfa_users / max(total_users, 1)) * 100, 2)
                    },
                    'activity_24h': {
                        'successful_attempts': recent_successful,
                        'failed_attempts': recent_failed,
                        'total_attempts': recent_successful + recent_failed
                    },
                    'system_status': 'operational',
                    'last_updated': fields.Datetime.now().isoformat()
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    @http.route('/api/mfa/health', type='http', auth='none', methods=['GET'])
    def health_check(self):
        """Health check endpoint"""
        try:
            # Check database connectivity
            request.env['res.users'].sudo().search([], limit=1)
            
            # Check MFA module status
            module = request.env['ir.module.module'].sudo().search([
                ('name', '=', 'mfa_auth'),
                ('state', '=', 'installed')
            ])
            
            status = {
                'status': 'healthy',
                'timestamp': fields.Datetime.now().isoformat(),
                'database': 'connected',
                'mfa_module': 'installed' if module else 'not_installed',
                'version': '1.0.0'
            }
            
            return request.make_response(
                json.dumps(status),
                headers=[('Content-Type', 'application/json')]
            )
        except Exception as e:
            error_response = {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': fields.Datetime.now().isoformat()
            }
            return request.make_response(
                json.dumps(error_response),
                status=500,
                headers=[('Content-Type', 'application/json')]
            )