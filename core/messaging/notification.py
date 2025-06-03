import platform
import logging

class NotificationManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.platform = platform.system()
        
    def send_notification(self, title, message, level="info"):
        """Send a system notification"""
        try:
            if self.platform == "Windows":
                self._send_windows_notification(title, message, level)
            elif self.platform == "Darwin":  # macOS
                self._send_macos_notification(title, message, level)
            elif self.platform == "Linux":
                self._send_linux_notification(title, message, level)
            else:
                self.logger.warning(f"Notifications not supported on {self.platform}")
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
    
    def _send_windows_notification(self, title, message, level):
        # Windows notification implementation
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(title, message, duration=5)
        except ImportError:
            self.logger.warning("win10toast not installed. Install with: pip install win10toast")
            
    def _send_macos_notification(self, title, message, level):
        # macOS notification implementation
        import os
        os.system(f"""osascript -e 'display notification "{message}" with title "{title}"'""")
        
    def _send_linux_notification(self, title, message, level):
        # Linux notification implementation
        try:
            import subprocess
            subprocess.Popen(['notify-send', title, message])
        except Exception:
            self.logger.warning("Could not send Linux notification. Make sure notify-send is installed.")