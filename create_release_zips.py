#!/usr/bin/env python
"""
Create ZIP release assets for SendX (simplified version)

This script creates the ZIP files mentioned in the README.md for easy download:
- sendx-release.zip: Full SendX application
- sendx-ai-shield-demo.zip: Demo of SendX AI Shield

This is a simplified version that doesn't require additional dependencies.
"""

import os
import zipfile
import shutil

def create_main_release_zip():
    """Create the main SendX release ZIP file"""
    print("Creating sendx-release.zip...")
    
    with zipfile.ZipFile('sendx-release.zip', 'w') as zipf:
        # Add all Python files
        for file in os.listdir('.'):
            if file.endswith('.py') and file != 'create_release_assets.py' and file != 'create_release_zips.py':
                zipf.write(file)
        
        # Add templates directory
        for root, _, files in os.walk('templates'):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path)
        
        # Add static directory
        for root, _, files in os.walk('static'):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path)
        
        # Add requirements file if it exists
        if os.path.exists('requirements.txt'):
            zipf.write('requirements.txt')
        
        # Add project configuration
        if os.path.exists('pyproject.toml'):
            zipf.write('pyproject.toml')
        
        # Add README
        if os.path.exists('README.md'):
            zipf.write('README.md')
    
    print("Created sendx-release.zip")

def create_ai_shield_demo_zip():
    """Create the SendX AI Shield demo ZIP file"""
    print("Creating sendx-ai-shield-demo.zip...")
    
    with zipfile.ZipFile('sendx-ai-shield-demo.zip', 'w') as zipf:
        # Add AI security files
        if os.path.exists('ai_security.py'):
            zipf.write('ai_security.py')
        
        if os.path.exists('demo_security.py'):
            zipf.write('demo_security.py')
        
        # Add AI security documentation
        if os.path.exists('AI_SECURITY.md'):
            zipf.write('AI_SECURITY.md')
        
        if os.path.exists('SECURITY_ENHANCEMENTS.md'):
            zipf.write('SECURITY_ENHANCEMENTS.md')
        
        if os.path.exists('sendx_security_report.md'):
            zipf.write('sendx_security_report.md')
        
        if os.path.exists('sendx_security_infographic.html'):
            zipf.write('sendx_security_infographic.html')
        
        # Add static/ai_security.js if it exists
        if os.path.exists('static/ai_security.js'):
            zipf.write('static/ai_security.js')
        
        # Add README
        if os.path.exists('README.md'):
            zipf.write('README.md')
    
    print("Created sendx-ai-shield-demo.zip")

def main():
    """Main function to create all release assets"""
    # Create output directory for release assets
    os.makedirs('release_assets', exist_ok=True)
    
    # Change to working directory
    current_dir = os.getcwd()
    os.chdir('release_assets')
    
    # Create all assets
    create_main_release_zip()
    create_ai_shield_demo_zip()
    
    # Return to original directory
    os.chdir(current_dir)
    
    print("\nAll release assets created in the 'release_assets' directory.")
    print("You can now upload these files to the GitHub releases page.")

if __name__ == "__main__":
    main()
