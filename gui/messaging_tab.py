"""
Messaging tab for Network Scanner application
Handles all messaging functionality including:
- Conversations list (modified to be direct chat)
- Message display
- Composing/sending messages

Current Date and Time (UTC): 2025-06-03 00:29:18
Current User's Login: AnoirELGUEDDAR
"""

import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QListWidget, QListWidgetItem, QTextEdit, QLineEdit,
    QPushButton, QLabel, QComboBox, QDialog, QDialogButtonBox,
    QFormLayout, QGroupBox, QRadioButton, QCheckBox, QMessageBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QInputDialog
)
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QMargins
from PyQt5.QtGui import QColor, QBrush, QFont

from core.messaging.message_service import MessageService
from core.messaging.message import Message, MessageType

logger = logging.getLogger(__name__)

# Style global pour l'application
APP_STYLE = """
QInputDialog {
    background-color: #1a2633;
}
QInputDialog QLabel {
    color: white;
}
QInputDialog QLineEdit {
    color: white;
    background-color: #213243;
    border: 1px solid #375a7f;
}
QInputDialog QPushButton {
    color: white;
    background-color: #2c3e50;
}
QInputDialog QPushButton:hover {
    background-color: #34495e;
}

/* Style supplémentaire pour les tableaux */
QTableView {
    color: white;
    selection-background-color: #0078d7;
}
QTableWidget::item {
    color: white;
}
QHeaderView::section {
    color: white;
}
"""

class MessagingTab(QWidget):
    """Tab for messaging functionality"""
    
    def __init__(self, message_service, parent=None):
        super().__init__(parent)
        self.message_service = message_service
        self.current_conversation_id = None # To keep track of the active chat
        self.current_chat_partner_display_name = "No Client Selected" # To store the name of the person we are chatting with
        
        # Appliquer le style global
        self.setStyleSheet(APP_STYLE)
        
        self._setup_ui()
        
    def _setup_ui(self):
        """Set up the messaging UI"""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Tab widget for messaging and client management
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Messaging tab (now a direct chat interface)
        self.messages_widget = QWidget()
        self._setup_messages_ui(self.messages_widget)
        self.tab_widget.addTab(self.messages_widget, "Messages")
        
        # Clients tab
        self.clients_widget = QWidget()
        self._setup_clients_ui(self.clients_widget)
        self.tab_widget.addTab(self.clients_widget, "Connected Clients")

        # Connect the message_received signal from MessageService
        # This will allow the chat display to update when new messages arrive
        self.message_service.message_received.connect(self._handle_incoming_message)
        
    def _setup_messages_ui(self, parent):
        """Set up the direct chat UI"""
        # Main layout for the chat interface
        main_layout = QVBoxLayout(parent)
        
        # Current conversation info (will show the selected client's name)
        self.conversation_info = QLabel("Select a client from 'Connected Clients' to start chatting.")
        self.conversation_info.setStyleSheet("font-weight: bold; font-size: 14px; padding: 5px; background-color: #0078d7; color: white;")
        self.conversation_info.setWordWrap(True)
        main_layout.addWidget(self.conversation_info)
        
        # Messages display area (the chat history)
        self.messages_display = QTextEdit()
        self.messages_display.setReadOnly(True)
        self.messages_display.setStyleSheet("""
            QTextEdit {
                background-color: #9eb8cf;
                border: 1px solid #ddd;
                font-size: 13px;
                color: white;
            }
        """)
        main_layout.addWidget(self.messages_display)
        
        # Message composition area
        message_input_label = QLabel("Type your message here:")
        message_input_label.setStyleSheet("color: white;")
        main_layout.addWidget(message_input_label)
        
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.setMaximumHeight(100)
        self.message_input.setMinimumHeight(80)
        self.message_input.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ddd;
                padding: 5px;
                font-size: 13px;
                color: white;
                background-color: #213243;
            }
        """)
        main_layout.addWidget(self.message_input)
        
        # Send button
        send_button = QPushButton("Send")
        send_button.setStyleSheet("""
            QPushButton {
                padding: 8px; 
                font-size: 13px; 
                background-color: #0078d7; 
                color: white;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #0086f0;
            }
            QPushButton:pressed {
                background-color: #0066b8;
            }
        """)
        send_button.clicked.connect(self._send_message)
        main_layout.addWidget(send_button)
        
    def _setup_clients_ui(self, parent):
        """Set up the clients UI"""
        # Main layout
        main_layout = QVBoxLayout(parent)
        
        # Header
        header = QLabel("Connected Client Devices")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        main_layout.addWidget(header)
        
        # Clients table
        self.clients_table = QTableWidget()
        self.clients_table.setColumnCount(5)
        self.clients_table.setHorizontalHeaderLabels(["Client ID", "Username", "Last Seen", "IP Address", "Platform"])
        self.clients_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.clients_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.clients_table.setAlternatingRowColors(True)
        self.clients_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #ddd;
                gridline-color: #f0f0f0;
                font-size: 13px;
                color: white;
            }
            QHeaderView::section {
                background-color: #0078d7;
                padding: 5px;
                border: 1px solid #ddd;
                font-weight: bold;
                color: white;
            }
            QTableView {
                color: white;
            }
            QTableWidget::item {
                color: white;
            }
        """)
        main_layout.addWidget(self.clients_table)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        
        refresh_clients_button = QPushButton("Refresh Clients")
        refresh_clients_button.setStyleSheet("""
            QPushButton {
                padding: 8px; 
                font-size: 13px; 
                background-color: #0078d7; 
                color: white;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #0086f0;
            }
            QPushButton:pressed {
                background-color: #0066b8;
            }
        """)
        refresh_clients_button.clicked.connect(self.refresh_clients)
        buttons_layout.addWidget(refresh_clients_button)
        
        message_client_button = QPushButton("Message Selected Client")
        message_client_button.setStyleSheet("""
            QPushButton {
                padding: 8px; 
                font-size: 13px; 
                background-color: #0078d7; 
                color: white;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #0086f0;
            }
            QPushButton:pressed {
                background-color: #0066b8;
            }
        """)
        message_client_button.clicked.connect(self._message_selected_client)
        buttons_layout.addWidget(message_client_button)
        
        broadcast_button = QPushButton("Broadcast to All Clients")
        broadcast_button.setStyleSheet("""
            QPushButton {
                padding: 8px; 
                font-size: 13px; 
                background-color: #0078d7; 
                color: white;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #0086f0;
            }
            QPushButton:pressed {
                background-color: #0066b8;
            }
        """)
        broadcast_button.clicked.connect(self._broadcast_message)
        buttons_layout.addWidget(broadcast_button)
        
        main_layout.addLayout(buttons_layout)
        
        # Initial load of clients
        self.refresh_clients()
            
    def refresh_conversations(self):
        """This method is now essentially deprecated for the simplified chat view.
        It will be triggered when a client is selected to load their history."""
        if self.current_conversation_id:
            self._display_conversation_messages(self.current_conversation_id)
        else:
            self.conversation_info.setText("Select a client from 'Connected Clients' to start chatting.")
            self.messages_display.clear()

    def refresh_clients(self):
        """Refresh the clients table"""
        try:
            # Get active clients from the message server
            devices = self.message_service.get_devices()
            
            # Clear the table
            self.clients_table.setRowCount(0)
            
            # Add each device
            for i, client_id in enumerate(devices):
                self.clients_table.insertRow(i)
                
                # Client ID
                id_item = QTableWidgetItem(client_id)
                id_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                self.clients_table.setItem(i, 0, id_item)
                
                # Username (may be same as ID if not available)
                username = client_id.split('-')[0] if '-' in client_id else client_id
                username_item = QTableWidgetItem(username)
                username_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                self.clients_table.setItem(i, 1, username_item)
                
                # Last seen - may need to be fetched from message server
                last_seen_item = QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                last_seen_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                self.clients_table.setItem(i, 2, last_seen_item)
                
                # IP Address - may need to be fetched from message server
                ip_item = QTableWidgetItem("N/A")
                ip_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                self.clients_table.setItem(i, 3, ip_item)
                
                # Platform - may need to be fetched from message server
                platform_item = QTableWidgetItem("N/A")
                platform_item.setForeground(QBrush(QColor(255, 255, 255)))  # White text
                self.clients_table.setItem(i, 4, platform_item)
                
        except Exception as e:
            logger.error(f"Error refreshing clients: {e}")
            
    def _display_conversation_messages(self, conversation_id):
        """Helper to display messages for a given conversation ID."""
        try:
            # --- CHANGE START ---
            messages = self.message_service.get_conversation(conversation_id=conversation_id)
            # --- CHANGE END ---
            
            if messages:
                # Assuming the conversation_id *is* the client's ID for direct chats
                # Or that self.current_chat_partner_display_name is already set.
                self.conversation_info.setText(f"Chat with: {self.current_chat_partner_display_name}")
                
                self.messages_display.clear()
                
                # Create simplified HTML for messages
                html = "<html><body style='background-color:#9eb8cf;'>"
                
                for msg in messages:
                    # Format timestamp
                    # Ensure timestamp is a float (epoch) before converting
                    if isinstance(msg.timestamp, datetime):
                        timestamp = msg.timestamp
                    else: # Assume it's an epoch if not datetime object
                        timestamp = datetime.fromtimestamp(msg.timestamp)

                    time_str = timestamp.strftime("%H:%M")
                    
                    # Format sender name (simplified)
                    sender = msg.sender or "System"
                    
                    # Determine if the message is from "You" (ADMIN) or the recipient
                    if sender == self.message_service.username: # Use the actual username set in MessageService
                        sender_display = "You"
                        align = "right"
                        bg_color = "#0078d7"  # Blue for your messages
                        text_color = "white"
                    else:
                        sender_display = sender
                        align = "left"
                        bg_color = "#f5f5f5"  # Light background for others' messages
                        text_color = "black"
                        
                    # Message formatting based on type
                    content_style = ""
                    if msg.type == MessageType.WARNING:
                        # Warning - make it bold and red
                        content_style = "font-weight:bold; color:red;"
                        if align == "left": # Ensure warning from others is still visible
                            text_color = "red" # Keep the text red for warnings from others
                    
                    # Add the message bubble
                    html += f"""
                    <div style="text-align:{align}; margin:15px 5px;">
                        <div style="display:inline-block; max-width:80%;">
                            <div style="font-weight:bold; color:{text_color if align == 'right' else 'white'};">{sender_display}</div>
                            <div style="background-color:{bg_color}; padding:10px; border-radius:10px;">
                                <div style="{content_style}; color:{text_color};">{msg.content}</div>
                                <div style="font-size:10px; color:{'#ddd' if align == 'right' else '#ddd'}; text-align:right; margin-top:5px;">{time_str}</div>
                            </div>
                        </div>
                    </div>
                    """
                
                html += "</body></html>"
                self.messages_display.setHtml(html)
                self.messages_display.verticalScrollBar().setValue(self.messages_display.verticalScrollBar().maximum()) # Scroll to bottom
                
                # In your MessageService, you don't have a mark_conversation_read
                # self.message_service.mark_conversation_read(conversation_id) 
            else:
                self.conversation_info.setText(f"Chat with: {self.current_chat_partner_display_name} (No messages yet)")
                self.messages_display.clear()
        except Exception as e:
            logger.error(f"Error loading conversation: {e}")
            self.conversation_info.setText(f"Error loading chat: {str(e)}")
            self.messages_display.clear()
            
    def _send_message(self):
        """Send a message to the currently selected client in the chat view."""
        if not self.current_conversation_id:
            QMessageBox.warning(self, "No Client Selected",
                                "Please select a client from 'Connected Clients' to send a message.")
            return
            
        content = self.message_input.toPlainText().strip()
        if not content:
            return
            
        try:
            # The recipient is the current conversation ID itself, as per your MessageService design
            recipient = self.current_conversation_id
            
            message = Message(
                content=content,
                msg_type=MessageType.INFO, # Default to INFO for user sent messages
                sender=self.message_service.username, # Use the actual username from the service
                recipient=recipient,
                conversation_id=self.current_conversation_id 
            )
            
            self.message_service.send_message(message)
            
            self.message_input.clear()
            
            # Refresh the current conversation display
            self._display_conversation_messages(self.current_conversation_id)
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            QMessageBox.critical(self, "Error", f"Could not send message: {str(e)}")
            
    def _handle_incoming_message(self, message: Message):
        """
        Handles incoming messages and updates the current chat display if relevant.
        This method is connected to message_service.message_received signal.
        """
        # If the incoming message's conversation ID matches the currently open one, refresh the display
        if message.conversation_id == self.current_conversation_id:
            self._display_conversation_messages(self.current_conversation_id)
        # Also, if it's a broadcast and "broadcast" conversation is open, refresh
        elif message.is_broadcast and self.current_conversation_id == "broadcast":
             self._display_conversation_messages("broadcast")
        
    def _new_message(self):
        """This function is no longer directly used in the simplified chat interface,
        as messaging is initiated by selecting a client from the table."""
        QMessageBox.information(self, "Information", "Please select a client from the 'Connected Clients' tab to start a new message.")

    def _broadcast_message(self):
        """Broadcast a message to all clients with proper white text"""
        # Créer un dialogue personnalisé au lieu d'utiliser QInputDialog.getText()
        dialog = QDialog(self)
        dialog.setWindowTitle("Broadcast Message")
        dialog.resize(400, 150)
        
        # Appliquer le style sombre avec texte blanc
        dialog.setStyleSheet("""
            QDialog {
                background-color: #1a2633;
            }
            QLabel {
                color: white;
            }
            QLineEdit {
                color: white;
                background-color: #213243;
                border: 1px solid #375a7f;
                padding: 5px;
            }
            QPushButton {
                padding: 6px 12px;
                color: white;
            }
        """)
        
        # Créer le layout et les widgets
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Enter message to broadcast to all devices:"))
        
        text_edit = QLineEdit()
        layout.addWidget(text_edit)
        
        # Boutons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        
        # Style pour les boutons
        for button in buttons.buttons():
            if buttons.buttonRole(button) == QDialogButtonBox.AcceptRole:
                button.setStyleSheet("background-color: #0078d7;")
                button.setText("OK")
            else:
                button.setStyleSheet("background-color: #2c3e50;")
                button.setText("Cancel")
        
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        # Exécuter le dialogue
        result = dialog.exec_()
        text = text_edit.text().strip()
        
        if result == QDialog.Accepted and text:
            # Créer un dialogue pour sélectionner le type de message
            msg_type_dialog = QDialog(self)
            msg_type_dialog.setWindowTitle("Message Type")
            msg_type_layout = QVBoxLayout(msg_type_dialog)
            
            # Style pour le dialogue de type de message
            msg_type_dialog.setStyleSheet("""
                QDialog {
                    background-color: #1a2633;
                }
                QLabel {
                    color: white;
                }
                QRadioButton {
                    color: white;
                }
                QPushButton {
                    padding: 6px 12px;
                    color: white;
                }
            """)
            
            # Boutons radio
            info_radio = QRadioButton("Information")
            info_radio.setChecked(True)
            warning_radio = QRadioButton("Warning")
            
            msg_type_layout.addWidget(QLabel("Select message type:"))
            msg_type_layout.addWidget(info_radio)
            msg_type_layout.addWidget(warning_radio)
            
            # Boutons
            button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            
            # Style pour les boutons
            for btn in button_box.buttons():
                if button_box.buttonRole(btn) == QDialogButtonBox.AcceptRole:
                    btn.setStyleSheet("background-color: #0078d7;")
                else:
                    btn.setStyleSheet("background-color: #2c3e50;")
            
            button_box.accepted.connect(msg_type_dialog.accept)
            button_box.rejected.connect(msg_type_dialog.reject)
            msg_type_layout.addWidget(button_box)
            
            if msg_type_dialog.exec_():
                # Déterminer le type de message
                msg_type = MessageType.WARNING if warning_radio.isChecked() else MessageType.INFO
                
                try:
                    # Envoyer le message de diffusion
                    self.message_service.broadcast_message(
                        content=text,
                        msg_type=msg_type
                    )
                    
                    # Set the current conversation to 'broadcast' if it's not already
                    # and refresh the display so broadcast messages show up in the chat area.
                    self.current_conversation_id = "broadcast"
                    self.current_chat_partner_display_name = "All Clients (Broadcast)"
                    self.tab_widget.setCurrentWidget(self.messages_widget)
                    self._display_conversation_messages("broadcast")
                    
                    QMessageBox.information(self, "Broadcast Sent", "Your broadcast message has been sent to all clients.")
                    
                except Exception as e:
                    logger.error(f"Error broadcasting message: {e}")
                    QMessageBox.critical(self, "Error", f"Could not broadcast message: {str(e)}")
            
    def _message_selected_client(self):
        """Open a chat interface with the selected client."""
        selected_rows = self.clients_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Client Selected",
                                "Please select a client to message.")
            return
            
        row = selected_rows[0].row()
        client_id = self.clients_table.item(row, 0).text()
        client_username = self.clients_table.item(row, 1).text() # Get the username for display
        
        # --- CHANGE START ---
        # The conversation ID for direct messages is simply the client_id itself
        # as per your MessageService's send_message logic
        conversation_id = client_id 
        # --- CHANGE END ---

        self.current_conversation_id = conversation_id
        self.current_chat_partner_display_name = client_username # Store username for display
        
        # Switch to the Messages tab and display the conversation
        self.tab_widget.setCurrentWidget(self.messages_widget)
        self._display_conversation_messages(self.current_conversation_id)