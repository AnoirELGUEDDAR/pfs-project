# Fix script for main_window.py
with open('gui/main_window.py', 'r') as file:
    content = file.read()

# Remove the problematic lines at the end of the file
fixed_content = content.replace(
    'self.monitoring_tab = MonitoringTab()\nself.tab_widget.addTab(self.monitoring_tab, "Monitoring")',
    ''
)

# Write the fixed content back
with open('gui/main_window.py', 'w') as file:
    file.write(fixed_content)

print("Fixed main_window.py - removed trailing code outside class methods")