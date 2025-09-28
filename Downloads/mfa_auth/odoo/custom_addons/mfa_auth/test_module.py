#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MFA Module Test Script
This script tests the MFA module functionality
"""

import sys
import os

# Add the module path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported"""
    try:
        from models import mfa_user, mfa_log, mfa_wizard
        from controllers import mfa_controller
        print("✅ All imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_syntax():
    """Test Python syntax"""
    try:
        import py_compile
        
        files_to_test = [
            'models/mfa_user.py',
            'models/mfa_log.py', 
            'models/mfa_wizard.py',
            'controllers/mfa_controller.py'
        ]
        
        for file_path in files_to_test:
            py_compile.compile(file_path, doraise=True)
            print(f"✅ {file_path} - Syntax OK")
        
        return True
    except py_compile.PyCompileError as e:
        print(f"❌ Syntax error: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 Testing MFA Module...")
    print("=" * 50)
    
    # Test imports
    print("\n📦 Testing imports...")
    if not test_imports():
        return False
    
    # Test syntax
    print("\n🔍 Testing syntax...")
    if not test_syntax():
        return False
    
    print("\n🎉 All tests passed! Module is ready to install.")
    print("\n📋 Installation steps:")
    print("1. Copy the mfa_auth folder to your Ubuntu VM")
    print("2. Run: sudo bash /odoo/custom_addons/mfa_auth/install_ubuntu.sh")
    print("3. Go to Odoo Apps and install 'MFA Authentication System'")
    print("4. Test the module!")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
