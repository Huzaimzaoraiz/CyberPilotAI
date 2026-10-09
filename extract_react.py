import re
import os

def extract_react_code():
    html_path = '/Users/huzaimzaoraiz/code/CyberPilotAI/web/index.html'
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()

    match = re.search(r'<script type="text/babel">(.*?)</script>', content, re.DOTALL)
    if match:
        react_code = match.group(1).strip()
        
        # Replace React object destructuring with standard ES module imports
        react_code = react_code.replace("const { useState, useEffect, useRef, useMemo } = React;", "")
        
        imports = "import React, { useState, useEffect, useRef, useMemo } from 'react';\n\n"
        exports = "\nexport default App;\n"
        
        final_code = imports + react_code + exports
        
        # Write to frontend/src/App.jsx
        with open('/Users/huzaimzaoraiz/code/CyberPilotAI/frontend/src/App.jsx', 'w', encoding='utf-8') as f:
            f.write(final_code)
        print("Successfully extracted React code to frontend/src/App.jsx")
    else:
        print("Could not find React code block in index.html")

if __name__ == '__main__':
    extract_react_code()
