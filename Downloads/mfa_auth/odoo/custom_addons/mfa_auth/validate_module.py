#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MFA Module Validation Script
This script validates the MFA module structure and syntax
"""

import os
import sys
import ast
import re
from pathlib import Path

class MFAValidator:
    def __init__(self, module_path):
        self.module_path = Path(module_path)
        self.errors = []
        self.warnings = []
        
    def validate_structure(self):
        """Validate module structure"""
        print("🔍 Validating module structure...")
        
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
            'data/mfa_demo_data.xml'
        ]
        
        missing_files = []
        for file_path in required_files:
            full_path = self.module_path / file_path
            if not full_path.exists():
                missing_files.append(file_path)
        
        if missing_files:
            self.errors.append(f"Missing files: {', '.join(missing_files)}")
            return False
        
        print("✅ All required files present")
        return True
    
    def validate_manifest(self):
        """Validate manifest file"""
        print("🔍 Validating manifest...")
        
        manifest_path = self.module_path / '__manifest__.py'
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for required keys
            required_keys = ['name', 'version', 'depends', 'data', 'installable']
            for key in required_keys:
                if f"'{key}'" not in content and f'"{key}"' not in content:
                    self.errors.append(f"Missing required key in manifest: {key}")
                    return False
            
            # Check for JavaScript assets (should not be present)
            if 'assets' in content:
                self.warnings.append("Manifest contains assets - ensure no JavaScript")
            
            print("✅ Manifest structure valid")
            return True
            
        except Exception as e:
            self.errors.append(f"Error reading manifest: {e}")
            return False
    
    def validate_python_syntax(self):
        """Validate Python syntax"""
        print("🔍 Validating Python syntax...")
        
        python_files = [
            'models/mfa_user.py',
            'models/mfa_log.py',
            'models/mfa_wizard.py',
            'controllers/mfa_controller.py'
        ]
        
        for file_path in python_files:
            full_path = self.module_path / file_path
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse AST to check syntax
                ast.parse(content)
                print(f"✅ {file_path} - Syntax OK")
                
            except SyntaxError as e:
                self.errors.append(f"Syntax error in {file_path}: {e}")
                return False
            except Exception as e:
                self.errors.append(f"Error reading {file_path}: {e}")
                return False
        
        return True
    
    def validate_xml_syntax(self):
        """Validate XML syntax"""
        print("🔍 Validating XML syntax...")
        
        xml_files = [
            'views/mfa_settings.xml',
            'views/mfa_templates.xml',
            'security/mfa_security.xml',
            'data/mfa_demo_data.xml'
        ]
        
        for file_path in xml_files:
            full_path = self.module_path / file_path
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for deprecated attrs usage
                if 'attrs=' in content:
                    self.errors.append(f"Deprecated 'attrs' found in {file_path} - use 'invisible' instead")
                    return False
                
                # Check for proper XML structure
                if not content.strip().startswith('<?xml'):
                    self.warnings.append(f"{file_path} should start with XML declaration")
                
                print(f"✅ {file_path} - XML OK")
                
            except Exception as e:
                self.errors.append(f"Error reading {file_path}: {e}")
                return False
        
        return True
    
    def validate_imports(self):
        """Validate import statements"""
        print("🔍 Validating imports...")
        
        # Check models/__init__.py
        init_path = self.module_path / 'models' / '__init__.py'
        try:
            with open(init_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            required_imports = ['mfa_user', 'mfa_log', 'mfa_wizard']
            for imp in required_imports:
                if f'import {imp}' not in content:
                    self.errors.append(f"Missing import in models/__init__.py: {imp}")
                    return False
            
            print("✅ Model imports valid")
            return True
            
        except Exception as e:
            self.errors.append(f"Error reading models/__init__.py: {e}")
            return False
    
    def validate_security(self):
        """Validate security files"""
        print("🔍 Validating security...")
        
        # Check CSV format
        csv_path = self.module_path / 'security' / 'ir.model.access.csv'
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if len(lines) < 2:  # Header + at least one rule
                self.errors.append("Security CSV should have access rules")
                return False
            
            print("✅ Security files valid")
            return True
            
        except Exception as e:
            self.errors.append(f"Error reading security CSV: {e}")
            return False
    
    def run_validation(self):
        """Run all validations"""
        print("🧪 MFA Module Validation")
        print("=" * 50)
        
        validations = [
            self.validate_structure,
            self.validate_manifest,
            self.validate_python_syntax,
            self.validate_xml_syntax,
            self.validate_imports,
            self.validate_security
        ]
        
        all_passed = True
        for validation in validations:
            if not validation():
                all_passed = False
        
        print("\n" + "=" * 50)
        if all_passed and not self.errors:
            print("🎉 ALL VALIDATIONS PASSED!")
            print("✅ Module is ready for installation")
            print("\n📋 Installation steps:")
            print("1. Copy mfa_auth folder to Ubuntu VM")
            print("2. Run: sudo bash /odoo/custom_addons/mfa_auth/install_ubuntu.sh")
            print("3. Install module in Odoo Apps")
            return True
        else:
            print("❌ VALIDATION FAILED!")
            for error in self.errors:
                print(f"❌ {error}")
            for warning in self.warnings:
                print(f"⚠️  {warning}")
            return False

def main():
    """Main validation function"""
    module_path = Path(__file__).parent
    validator = MFAValidator(module_path)
    success = validator.run_validation()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
