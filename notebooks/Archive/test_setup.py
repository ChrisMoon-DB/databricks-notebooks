#!/usr/bin/env python3
"""
Local validation script to test notebook logic before uploading to Databricks.
This helps catch syntax errors and logic issues early.
"""

import re
import sys

def validate_sql_syntax(sql_statement):
    """Basic SQL syntax validation"""
    keywords = ['CREATE', 'INSERT', 'SELECT', 'DROP', 'ALTER', 'GRANT', 'REVOKE']
    sql_upper = sql_statement.upper()
    
    # Check for basic SQL keywords
    has_keyword = any(keyword in sql_upper for keyword in keywords)
    
    # Check for balanced parentheses
    if sql_statement.count('(') != sql_statement.count(')'):
        return False, "Unbalanced parentheses"
    
    # Check for balanced quotes
    single_quotes = sql_statement.count("'")
    if single_quotes % 2 != 0:
        return False, "Unbalanced single quotes"
    
    if has_keyword:
        return True, "OK"
    return False, "No SQL keyword found"

def extract_sql_from_file(filepath):
    """Extract SQL statements from Python/notebook file"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Find SQL in spark.sql() calls
    pattern = r'spark\.sql\(f?"""(.*?)"""\)'
    matches = re.findall(pattern, content, re.DOTALL)
    
    return matches

def validate_notebook_file(filepath):
    """Validate a notebook/Python file"""
    print(f"\n{'='*70}")
    print(f"Validating: {filepath}")
    print('='*70)
    
    try:
        # Check file exists
        with open(filepath, 'r') as f:
            content = f.read()
        
        print(f"✓ File readable ({len(content)} bytes)")
        
        # Extract and validate SQL statements
        sql_statements = extract_sql_from_file(filepath)
        print(f"✓ Found {len(sql_statements)} SQL statements")
        
        errors = []
        for i, sql in enumerate(sql_statements, 1):
            is_valid, message = validate_sql_syntax(sql)
            if not is_valid:
                errors.append(f"  SQL #{i}: {message}")
                print(f"  ⚠️  SQL #{i}: {message}")
            else:
                print(f"  ✓ SQL #{i}: {message}")
        
        # Check for common issues
        issues = []
        
        if 'USE_TEMP_TABLES' in content and 'get_table_type()' not in content:
            issues.append("References USE_TEMP_TABLES but missing get_table_type() helper")
        
        if 'IS_ACCOUNT_GROUP_MEMBER' in content or 'IS_MEMBER' in content:
            issues.append("Uses group membership checks - update group names for your environment")
        
        if issues:
            print(f"\n⚠️  {len(issues)} Configuration Note(s):")
            for issue in issues:
                print(f"  • {issue}")
        
        if errors:
            print(f"\n❌ {len(errors)} Error(s) found")
            return False
        else:
            print(f"\n✅ Validation passed!")
            return True
            
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Validate all notebook files"""
    files_to_validate = [
        'setup_environment.py',
        'data_privacy.ipynb',
    ]
    
    print("="*70)
    print("DATABRICKS NOTEBOOK VALIDATION")
    print("="*70)
    print("\nThis script performs basic validation of notebook logic")
    print("before uploading to Databricks.\n")
    
    all_valid = True
    for filename in files_to_validate:
        try:
            valid = validate_notebook_file(filename)
            all_valid = all_valid and valid
        except Exception as e:
            print(f"❌ Failed to validate {filename}: {e}")
            all_valid = False
    
    print("\n" + "="*70)
    if all_valid:
        print("✅ ALL VALIDATIONS PASSED")
        print("="*70)
        print("\nNext steps:")
        print("1. Upload notebooks to Databricks workspace")
        print("2. Ensure both files are in the same folder")
        print("3. Run data_privacy.ipynb")
        print("4. Update group names to match your environment")
        return 0
    else:
        print("❌ VALIDATION FAILED")
        print("="*70)
        print("\nPlease fix the errors above before uploading.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

