#!/usr/bin/env python
"""
Create release assets for SendX

This script creates the ZIP files mentioned in the README.md for easy download:
- sendx-release.zip: Full SendX application
- sendx-ai-shield-demo.zip: Demo of SendX AI Shield
- sendx-documentation.pdf: Documentation in PDF format
"""

import os
import zipfile
import shutil
import markdown
import tempfile
from weasyprint import HTML

def create_main_release_zip():
    """Create the main SendX release ZIP file"""
    print("Creating sendx-release.zip...")
    
    with zipfile.ZipFile('sendx-release.zip', 'w') as zipf:
        # Add all Python files
        for file in os.listdir('.'):
            if file.endswith('.py') and file != 'create_release_assets.py':
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

def create_documentation_pdf():
    """Create comprehensive PDF documentation from Markdown files"""
    print("Creating sendx-documentation.pdf...")
    
    # Collect all documentation content
    content = []
    
    # Start with README
    if os.path.exists('README.md'):
        with open('README.md', 'r', encoding='utf-8') as f:
            content.append(f.read())
    
    # Add security documentation
    for doc_file in ['SECURITY_ENHANCEMENTS.md', 'AI_SECURITY.md', 'sendx_security_report.md']:
        if os.path.exists(doc_file):
            with open(doc_file, 'r', encoding='utf-8') as f:
                content.append("\n\n" + f.read())
    
    # Add documentation from docs directory
    if os.path.exists('docs'):
        for file in os.listdir('docs'):
            if file.endswith('.md'):
                with open(os.path.join('docs', file), 'r', encoding='utf-8') as f:
                    content.append("\n\n" + f.read())
    
    # Convert markdown to HTML
    html_content = markdown.markdown('\n\n'.join(content), extensions=['tables', 'fenced_code'])
    
    # Add CSS styling
    html_doc = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>SendX Documentation</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
            h1 {{ color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
            h2 {{ color: #3498db; margin-top: 30px; }}
            h3 {{ color: #2980b9; }}
            code {{ background: #f8f8f8; padding: 2px 5px; border-radius: 3px; }}
            pre {{ background: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            img {{ max-width: 100%; }}
            blockquote {{ border-left: 4px solid #ccc; padding-left: 15px; color: #555; }}
            .page-break {{ page-break-after: always; }}
        </style>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """
    
    # Create PDF from HTML
    HTML(string=html_doc).write_pdf('sendx-documentation.pdf')
    
    print("Created sendx-documentation.pdf")

def main():
    """Main function to create all release assets"""
    # Create output directory for release assets
    os.makedirs('release_assets', exist_ok=True)
    
    # Change to working directory
    os.chdir('release_assets')
    
    # Create all assets
    create_main_release_zip()
    create_ai_shield_demo_zip()
    
    try:
        create_documentation_pdf()
    except Exception as e:
        print(f"Error creating PDF documentation: {e}")
        print("Please install weasyprint dependencies: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html")
    
    print("\nAll release assets created in the 'release_assets' directory.")
    print("You can now upload these files to the GitHub releases page.")

if __name__ == "__main__":
    main()
