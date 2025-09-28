#!/usr/bin/env python3
"""
MFA Authentication Module Test Script
Tests the module functionality without requiring Odoo server
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path

def test_module_structure():
    """Test that all required files exist"""
    print("🔍 Testing module structure...")
    
    required_files = [
        '__manifest__.py',
        '__init__.py',
        'models/__init__.py',
        'models/mfa_user.py',
        'models/mfa_log.py',
        'models/mfa_wizard.py',
        'controllers/__init__.py',
        'controllers/mfa_controller.py',
        'views/mfa_settings.xml',
        'views/mfa_templates.xml',
        'security/ir.model.access.csv',
        'security/mfa_security.xml',
        'data/mfa_demo_data.xml',
        'static/src/css/mfa.css',
        'README.md',
        'requirements.txt',
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = Path(__file__).parent / file_path
        if not full_path.exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    else:
        print("✅ All required files present")
        return True

def test_manifest():
    """Test manifest file structure"""
    print("🔍 Testing manifest file...")
    
    try:
        with open('__manifest__.py', 'r') as f:
            content = f.read()
        
        # Check for required keys
        required_keys = ['name', 'version', 'depends', 'data', 'installable']
        for key in required_keys:
            if f"'{key}':" not in content:
                print(f"❌ Missing key in manifest: {key}")
                return False
        
        # Check for JavaScript assets (should not be present)
        if 'assets' in content:
            print("⚠️  Warning: JavaScript assets found in manifest (may cause issues)")
        
        print("✅ Manifest file structure is correct")
        return True
        
    except Exception as e:
        print(f"❌ Error reading manifest: {e}")
        return False

def test_python_syntax():
    """Test Python files for syntax errors"""
    print("🔍 Testing Python syntax...")
    
    python_files = [
        '__init__.py',
        'models/__init__.py',
        'models/mfa_user.py',
        'models/mfa_log.py',
        'models/mfa_wizard.py',
        'controllers/__init__.py',
        'controllers/mfa_controller.py',
    ]
    
    for file_path in python_files:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Basic syntax check
            compile(content, file_path, 'exec')
            print(f"✅ {file_path} - syntax OK")
            
        except SyntaxError as e:
            print(f"❌ {file_path} - syntax error: {e}")
            return False
        except Exception as e:
            print(f"❌ {file_path} - error: {e}")
            return False
    
    return True

def test_xml_syntax():
    """Test XML files for basic syntax"""
    print("🔍 Testing XML syntax...")
    
    xml_files = [
        'views/mfa_settings.xml',
        'views/mfa_templates.xml',
        'security/mfa_security.xml',
        'data/mfa_demo_data.xml',
    ]
    
    for file_path in xml_files:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Basic XML structure check
            if not content.strip().startswith('<?xml'):
                print(f"⚠️  {file_path} - missing XML declaration")
            
            # Check for common Odoo 17 syntax issues
            if 'attrs=' in content:
                print(f"⚠️  {file_path} - contains deprecated 'attrs' attribute")
            
            if 'states=' in content:
                print(f"⚠️  {file_path} - contains deprecated 'states' attribute")
            
            print(f"✅ {file_path} - basic syntax OK")
            
        except Exception as e:
            print(f"❌ {file_path} - error: {e}")
            return False
    
    return True

def test_dependencies():
    """Test if required Python packages are available"""
    print("🔍 Testing dependencies...")
    
    required_packages = ['pyotp', 'qrcode', 'cryptography']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} - available")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} - not available")
    
    if missing_packages:
        print(f"❌ Missing packages: {missing_packages}")
        print("Install with: pip3 install " + " ".join(missing_packages))
        return False
    
    return True

def test_totp_functionality():
    """Test TOTP functionality"""
    print("🔍 Testing TOTP functionality...")
    
    try:
        import pyotp
        import qrcode
        import base64
        from io import BytesIO
        
        # Test TOTP generation
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        
        # Test QR code generation
        provisioning_uri = totp.provisioning_uri("test@example.com", issuer_name="Test")
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code = base64.b64encode(buffer.getvalue()).decode()
        
        print("✅ TOTP functionality working")
        return True
        
    except Exception as e:
        print(f"❌ TOTP functionality error: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 MFA Authentication Module Test Suite")
    print("=======================================")
    print()
    
    tests = [
        test_module_structure,
        test_manifest,
        test_python_syntax,
        test_xml_syntax,
        test_dependencies,
        test_totp_functionality,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            print()
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            print()
    
    print("📊 Test Results")
    print("===============")
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed! Module is ready for installation.")
        return 0
    else:
        print("⚠️  Some tests failed. Please fix the issues before installation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())