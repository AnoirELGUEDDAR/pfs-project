# Direct fix for main_window.py issue
import re

try:
    # Read the file
    with open('gui/main_window.py', 'r') as f:
        content = f.readlines()
    
    # Check if the problematic lines are present at the end
    if len(content) >= 959:
        # Remove only lines 959 and 960 if they contain the problematic code
        if "self.monitoring_tab =" in content[958] and "self.tab_widget.addTab" in content[959]:
            print(f"Found problematic code at lines 959-960. Removing...")
            content = content[:958]
            
            # Make sure the file ends with a newline
            if not content[-1].endswith('\n'):
                content[-1] += '\n'
                
            # Write the fixed content back
            with open('gui/main_window.py', 'w') as f:
                f.writelines(content)
            print("Fixed successfully!")
        else:
            print("Lines 959-960 don't contain the expected problematic code.")
            print(f"Line 959: {content[958]}")
            print(f"Line 960: {content[959]}")
    else:
        print(f"File has only {len(content)} lines, can't have problem at line 959.")
    
except Exception as e:
    print(f"Error during fix: {e}")