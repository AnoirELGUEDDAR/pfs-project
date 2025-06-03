"""
Style manager for the Network Scanner & Management Tool
Current Date and Time (UTC): 2025-06-02 19:09:14
Current User's Login: AnoirELGUEDDAR
"""

class StyleManager:
    """Manages application-wide styling"""
    
    @staticmethod
    def get_dark_theme():
        """Returns the complete dark theme stylesheet"""
        return """
        /* Main Application Style */
        QMainWindow, QDialog {
            background-color: #1a2633;
            color: #e0e0e0;
        }
        
        /* Tab Widget Style */
        QTabWidget::pane {
            border: 1px solid #324a5f;
            background-color: #1a2633;
        }
        
        QTabBar::tab {
            background-color: #213243;
            color: white;  /* Changed to white */
            padding: 8px 12px;
            margin-right: 2px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        
        QTabBar::tab:selected {
            background-color: #375a7f;
            color: white;
            font-weight: bold;
        }
        
        QTabBar::tab:hover:!selected {
            background-color: #2a3f50;
        }
        
        /* Table Styles */
        QTableView, QTreeView, QListView {
            background-color: #1a2633;
            color: white;  /* Changed to white */
            gridline-color: #324a5f;
            selection-background-color: #375a7f;
            selection-color: white;
            alternate-background-color: #213243;
            border: 1px solid #324a5f;
        }
        
        QHeaderView::section {
            background-color: #2c4a63;
            color: white;
            padding: 6px;
            border: none;
            border-bottom: 2px solid #4a6b8a;
            font-weight: bold;
        }
        
        QHeaderView {
            background-color: #2c4a63;
        }
        
        /* Form Controls */
        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: #213243;
            color: white;  /* Changed to white */
            border: 1px solid #324a5f;
            padding: 4px;
            selection-background-color: #375a7f;
            selection-color: white;
            border-radius: 3px;
        }
        
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
            border: 1px solid #4a90e2;
        }
        
        /* Enhanced ComboBox Styling - UPDATED FOR WHITE TEXT */
        QComboBox {
            background-color: #213243;
            color: white !important;  /* Force white text with !important */
            border: 1px solid #324a5f;
            padding: 4px;
            border-radius: 3px;
        }
        
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 20px;
            border-left: 1px solid #324a5f;
            background-color: #2c4a63;
        }
        
        QComboBox::down-arrow {
            image: url(icons/arrow_down.png);
            width: 12px;
            height: 12px;
        }
        
        /* CRITICAL FIX for dropdown items - Force white text */
        QComboBox QAbstractItemView {
            background-color: #1e3d59 !important;
            color: white !important;
            border: 1px solid #324a5f;
            selection-background-color: #375a7f;
            selection-color: white;
        }
        
        /* Ensure all items are white, even when not selected */
        QComboBox::item {
            color: white !important;
        }
        
        QComboBox::item:selected {
            background-color: #375a7f;
            color: white !important;
        }
        
        QComboBox::item:!selected {
            color: white !important;
        }
        
        /* Main Scan Button */
        QPushButton#startScanBtn {
            background-color: #0078D7;
            color: white;
            border: none;
            padding: 30px;
            font-size: 16pt;
            font-weight: bold;
            border-radius: 10px;
            min-width: 180px;
            min-height: 180px;
        }
        
        QPushButton#startScanBtn:hover {
            background-color: #1683D9;
        }
        
        QPushButton#startScanBtn:pressed {
            background-color: #0067C0;
        }
        
        /* Feature Button Styles - CIRCULAR */
        QPushButton.featureButton {
            background-color: #2c3e50;
            color: white;
            border: none;
            border-radius: 50px; /* This makes the buttons circular */
            font-size: 16pt;
            min-width: 100px;
            min-height: 100px;
            padding: 5px;
            text-align: center;
        }
        
        QPushButton.featureButton:hover {
            background-color: #0078D7;
            border: 3px solid #4a90e2;
            
        }
        
        QPushButton.featureButton:pressed {
            background-color: #0078D7;
        }
        
        /* Regular Buttons */
        QPushButton:not(.featureButton):not(#startScanBtn) {
            background-color: #2c4a63;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 3px;
            min-width: 80px;
        }
        
        QPushButton:not(.featureButton):not(#startScanBtn):hover {
            background-color: #375a7f;
        }
        
        QPushButton:not(.featureButton):not(#startScanBtn):pressed {
            background-color: #1c3a53;
        }
        
        QPushButton:disabled {
            background-color: #384e63;
            color: #808080;
        }
        
        /* Toolbar */
        QToolBar {
            background-color: #213243;
            border: none;
            spacing: 3px;
        }
        
        QToolButton {
            background-color: transparent;
            color: white;  /* Changed to white */
            border: none;
            padding: 4px;
            border-radius: 3px;
        }
        
        QToolButton:hover {
            background-color: #2a3f50;
        }
        
        QToolButton:pressed {
            background-color: #1c3a53;
        }
        
        /* Group Boxes and Frames */
        QGroupBox {
            border: 1px solid #324a5f;
            border-radius: 5px;
            margin-top: 20px;
            font-weight: bold;
            color: white;  /* Changed to white from #60b5ff */
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 5px;
            left: 10px;
        }
        
        QFrame {
            border: 1px solid #324a5f;
        }
        
        /* Labels */
        QLabel {
            color: white;  /* Changed to white from #e0e0e0 */
        }
        
        QLabel#titleLabel {
            color: white;  /* Changed to white from #60b5ff */
            font-weight: bold;
            font-size: 14pt;
        }
        
        /* Main title styling */
        QLabel#mainTitle {
            color: white;
            font-size: 36pt;
            font-weight: bold;
        }
        
        QLabel#subtitle {
            color: white;  /* Changed to white from #CCCCCC */
            font-size: 14pt;
        }
        
        /* Status Bar */
        QStatusBar {
            background-color: #213243;
            color: white;  /* Changed to white */
        }
        
        QStatusBar::item {
            border: none;
        }
        
        /* Progress Bar */
        QProgressBar {
            border: 1px solid #324a5f;
            border-radius: 3px;
            text-align: center;
            background-color: #213243;
            color: white;
        }
        
        QProgressBar::chunk {
            background-color: #4a90e2;
            width: 10px;
        }
        
        /* Checkbox and Radio Button */
        QCheckBox, QRadioButton {
            color: white;  /* Changed to white from #e0e0e0 */
            spacing: 5px;
        }
        
        QCheckBox::indicator, QRadioButton::indicator {
            width: 13px;
            height: 13px;
        }
        
        QCheckBox::indicator:unchecked, QRadioButton::indicator:unchecked {
            border: 1px solid #324a5f;
            background-color: #213243;
        }
        
        QCheckBox::indicator:checked, QRadioButton::indicator:checked {
            border: 1px solid #4a90e2;
            background-color: #4a90e2;
        }
        
        /* Menus - UPDATED TO FIX CONTEXT MENU BACKGROUND */
        QMenuBar {
            background-color: #213243;
            color: white;
        }
        
        QMenuBar::item {
            background-color: transparent;
        }
        
        QMenuBar::item:selected {
            background-color: #375a7f;
        }
        
        /* UPDATED MENU STYLING - Ensure blue background with white text */
        QMenu {
            background-color: #1e3d59 !important;
            color: white !important;
            border: 1px solid #324a5f;
            padding: 5px;
            margin: 2px;
        }
        
        QMenu::item {
            background-color: #1e3d59 !important;
            color: white !important;
            padding: 5px 20px 5px 20px;
            margin: 2px;
        }
        
        QMenu::item:selected {
            background-color: #2a5885 !important;
            color: white !important;
        }
        
        QMenu::item:pressed {
            background-color: #3a7ca5 !important;
            color: white !important;
        }
        
        QMenu::separator {
            height: 1px;
            background: #4d4d4d;
            margin: 5px 15px;
        }
        
        /* For sub-menus and popup menus */
        QMenu QMenu, QComboBox QAbstractItemView {
            background-color: #1e3d59 !important;
            color: white !important;
        }
        
        /* Splitter */
        QSplitter::handle {
            background-color: #324a5f;
        }
        
        /* Scrollbars */
        QScrollBar:vertical {
            border: none;
            background-color: #1a2633;
            width: 12px;
            margin: 15px 0 15px 0;
        }
        
        QScrollBar::handle:vertical {
            background-color: #324a5f;
            min-height: 30px;
            border-radius: 6px;
        }
        
        QScrollBar::handle:vertical:hover {
            background-color: #375a7f;
        }
        
        QScrollBar::sub-line:vertical, QScrollBar::add-line:vertical {
            border: none;
            background: none;
            height: 15px;
        }
        
        QScrollBar:horizontal {
            border: none;
            background-color: #1a2633;
            height: 12px;
            margin: 0 15px 0 15px;
        }
        
        QScrollBar::handle:horizontal {
            background-color: #324a5f;
            min-width: 30px;
            border-radius: 6px;
        }
        
        QScrollBar::handle:horizontal:hover {
            background-color: #375a7f;
        }
        
        QScrollBar::sub-line:horizontal, QScrollBar::add-line:horizontal {
            border: none;
            background: none;
            width: 15px;
        }
        
        /* Form section labels - ensure they're white */
        QLabel[formSection="true"] {
            color: white;
            font-weight: bold;
            font-size: 11pt;
        }
        
        /* Field labels - ensure proper spacing and white color */
        QLabel[fieldLabel="true"] {
            color: white;
            margin-right: 5px;
        }
        
        /* Special status labels */
        QLabel#statusConnected {
            color: #4CAF50;  /* Green */
        }
        
        QLabel#statusDisconnected {
            color: #F44336;  /* Red */
        }
        
        QLabel#statusWarning {
            color: #FF9800;  /* Orange/Amber */
        }
        
        /* Scanner tab specific labels */
        QLabel#interface_label, QLabel#ip_range_label, 
        QLabel#advanced_options_label, QLabel#timeout_label {
            color: white;
        }
        """
    
    @staticmethod
    def apply_style(app):
        """Apply the dark theme style to the entire application
        
        Args:
            app: QApplication instance
        """
        app.setStyleSheet(StyleManager.get_dark_theme())
        
        # Force white text on all form elements if needed
        # This is an additional measure to ensure all text is white
        additional_white_text = """
        QLabel, QCheckBox, QRadioButton, QGroupBox, QTabBar::tab, 
        QPushButton, QToolTip, QMenu::item, QMenuBar::item {
            color: white;
        }
        
        /* Additional enforced styling for ComboBox items */
        QComboBox, QComboBox QAbstractItemView, QComboBox::item {
            color: white !important;
        }
        
        /* Force blue background for context menus */
        QMenu {
            background-color: #1e3d59 !important;
        }
        
        /* Dialog-specific fixes */
        QDialog QComboBox QAbstractItemView {
            background-color: #1e3d59 !important;
            color: white !important;
        }
        
        QDialog QComboBox::item {
            color: white !important;
        }
        
        /* Ensure "No devices available" shows in white */
        QComboBox::item:!selected {
            color: white !important;
        }
        """
        app.setStyleSheet(app.styleSheet() + additional_white_text)