#!/usr/bin/env python3
"""
Simple test script to validate the MFA Authentication module
This script checks for common issues and validates the module structure.
"""

import os
import sys
import ast
import xml.etree.ElementTree as ET
from pathlib import Path

def print_status(message, status="INFO"):
    colors = {
        "INFO": "\033[0;34m",
        "SUCCESS": "\033[0;32m",
        "WARNING": "\033[1;33m",
        "ERROR": "\033[0;31m",
    }
    reset = "\033[0m"
    print(f"{colors.get(status, '')}[{status}]{reset} {message}")

def test_python_syntax():
    """Test Python syntax for all Python files"""
    print_status("Testing Python syntax...", "INFO")
    
    python_files = list(Path("mfa_auth").glob("**/*.py"))
    errors = []
    
    for py_file in python_files:
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            ast.parse(content)
            print_status(f"✓ {py_file}", "SUCCESS")
        except SyntaxError as e:
            errors.append(f"{py_file}: {e}")
            print_status(f"✗ {py_file}: {e}", "ERROR")
    
    return len(errors) == 0

def test_xml_syntax():
    """Test XML syntax for all XML files"""
    print_status("Testing XML syntax...", "INFO")
    
    xml_files = list(Path("mfa_auth").glob("**/*.xml"))
    errors = []
    
    for xml_file in xml_files:
        try:
            ET.parse(xml_file)
            print_status(f"✓ {xml_file}", "SUCCESS")
        except ET.ParseError as e:
            errors.append(f"{xml_file}: {e}")
            print_status(f"✗ {xml_file}: {e}", "ERROR")
    
    return len(errors) == 0

def test_manifest():
    """Test manifest file"""
    print_status("Testing manifest file...", "INFO")
    
    manifest_path = Path("mfa_auth/__manifest__.py")
    if not manifest_path.exists():
        print_status("✗ Manifest file not found", "ERROR")
        return False
    
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest_content = f.read()
        
        manifest = ast.literal_eval(manifest_content)
        
        # Check required fields
        required_fields = ['name', 'version', 'depends', 'data']
        missing_fields = [field for field in required_fields if field not in manifest]
        
        if missing_fields:
            print_status(f"✗ Missing required fields: {missing_fields}", "ERROR")
            return False
        
        # Check for JavaScript assets (should be empty)
        assets = manifest.get('assets', {})
        if assets:
            print_status("⚠ JavaScript assets found in manifest (may cause issues)", "WARNING")
        
        # Check dependencies
        depends = manifest.get('depends', [])
        if 'base' not in depends:
            print_status("✗ 'base' dependency missing", "ERROR")
            return False
        
        print_status("✓ Manifest file is valid", "SUCCESS")
        return True
        
    except Exception as e:
        print_status(f"✗ Manifest file error: {e}", "ERROR")
        return False

def test_file_structure():
    """Test file structure"""
    print_status("Testing file structure...", "INFO")
    
    required_files = [
        "mfa_auth/__init__.py",
        "mfa_auth/__manifest__.py",
        "mfa_auth/models/__init__.py",
        "mfa_auth/models/mfa_user.py",
        "mfa_auth/models/mfa_log.py",
        "mfa_auth/models/mfa_wizard.py",
        "mfa_auth/controllers/__init__.py",
        "mfa_auth/controllers/mfa_controller.py",
        "mfa_auth/security/ir.model.access.csv",
        "mfa_auth/security/mfa_security.xml",
        "mfa_auth/views/mfa_settings.xml",
        "mfa_auth/views/mfa_templates.xml",
        "mfa_auth/views/mfa_wizard_views.xml",
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
            print_status(f"✗ Missing: {file_path}", "ERROR")
        else:
            print_status(f"✓ Found: {file_path}", "SUCCESS")
    
    return len(missing_files) == 0

def test_imports():
    """Test critical imports"""
    print_status("Testing critical imports...", "INFO")
    
    try:
        # Test if pyotp can be imported
        import pyotp
        print_status("✓ pyotp import successful", "SUCCESS")
    except ImportError:
        print_status("✗ pyotp not available (pip install pyotp)", "ERROR")
        return False
    
    try:
        # Test if qrcode can be imported
        import qrcode
        print_status("✓ qrcode import successful", "SUCCESS")
    except ImportError:
        print_status("✗ qrcode not available (pip install qrcode)", "ERROR")
        return False
    
    try:
        # Test if cryptography can be imported
        import cryptography
        print_status("✓ cryptography import successful", "SUCCESS")
    except ImportError:
        print_status("✗ cryptography not available (pip install cryptography)", "ERROR")
        return False
    
    return True

def test_csv_files():
    """Test CSV files"""
    print_status("Testing CSV files...", "INFO")
    
    csv_files = list(Path("mfa_auth").glob("**/*.csv"))
    
    for csv_file in csv_files:
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if not lines:
                print_status(f"✗ {csv_file}: Empty file", "ERROR")
                return False
            
            # Check header
            header = lines[0].strip()
            if not header.startswith('id,name,model_id:id'):
                print_status(f"✗ {csv_file}: Invalid header", "ERROR")
                return False
            
            print_status(f"✓ {csv_file}", "SUCCESS")
            
        except Exception as e:
            print_status(f"✗ {csv_file}: {e}", "ERROR")
            return False
    
    return True

def main():
    """Run all tests"""
    print_status("Starting MFA Authentication Module Tests", "INFO")
    print("=" * 50)
    
    os.chdir(Path(__file__).parent.parent)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Python Syntax", test_python_syntax),
        ("XML Syntax", test_xml_syntax),
        ("Manifest File", test_manifest),
        ("CSV Files", test_csv_files),
        ("Critical Imports", test_imports),
    ]
    
    results = {}
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * 20)
        results[test_name] = test_func()
    
    # Summary
    print("\n" + "=" * 50)
    print_status("Test Summary", "INFO")
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "SUCCESS" if result else "ERROR"
        print_status(f"{test_name}: {'PASSED' if result else 'FAILED'}", status)
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print_status("All tests passed! Module is ready for installation.", "SUCCESS")
        return 0
    else:
        print_status(f"{total - passed} tests failed. Please fix the issues before installation.", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())