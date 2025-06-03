"""
Messaging tab for Network Scanner application
Handles all messaging functionality including:
- Conversations list
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
        
        # Messaging tab
        self.messages_widget = QWidget()
        self._setup_messages_ui(self.messages_widget)
        self.tab_widget.addTab(self.messages_widget, "Messages")
        
        # Clients tab
        self.clients_widget = QWidget()
        self._setup_clients_ui(self.clients_widget)
        self.tab_widget.addTab(self.clients_widget, "Connected Clients")
        
    def _setup_messages_ui(self, parent):
        """Set up the messages UI"""
        # Main layout
        main_layout = QVBoxLayout(parent)
        
        # Create a horizontal splitter
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left side - conversations list
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # List of conversations
        conv_label = QLabel("Conversations")
        conv_label.setStyleSheet("font-weight: bold; font-size: 14px; color: white;")
        left_layout.addWidget(conv_label)
        
        self.conversations_list = QListWidget()
        self.conversations_list.setMinimumWidth(250)
        self.conversations_list.currentItemChanged.connect(self._conversation_selected)
        self.conversations_list.setAlternatingRowColors(True)
        self.conversations_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #ddd;
                background-color: #9eb8cf;
                color: white;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #eee;
                color: white;
            }
            QListWidget::item:selected {
                background-color: #375a7f;
                color: white;
            }
        """)
        left_layout.addWidget(self.conversations_list)
        
        # Buttons - Updated to blue color
        buttons_layout = QVBoxLayout()
        
        refresh_button = QPushButton("Refresh")
        refresh_button.setStyleSheet("""
            QPushButton {
                padding: 5px; 
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
        refresh_button.clicked.connect(self.refresh_conversations)
        buttons_layout.addWidget(refresh_button)
        
        new_message_button = QPushButton("New Message")
        new_message_button.setStyleSheet("""
            QPushButton {
                padding: 5px; 
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
        new_message_button.clicked.connect(self._new_message)
        buttons_layout.addWidget(new_message_button)
        
        broadcast_button = QPushButton("Broadcast Message")
        broadcast_button.setStyleSheet("""
            QPushButton {
                padding: 5px; 
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
        
        left_layout.addLayout(buttons_layout)
        
        # Add the left side to the splitter
        splitter.addWidget(left_widget)
        
        # Right side - message display and input
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Current conversation info - Changed from green to blue
        self.conversation_info = QLabel("Select a conversation")
        self.conversation_info.setStyleSheet("font-weight: bold; font-size: 14px; padding: 5px; background-color: #0078d7; color: white;")
        self.conversation_info.setWordWrap(True)
        right_layout.addWidget(self.conversation_info)
        
        # Messages display
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
        right_layout.addWidget(self.messages_display)
        
        # Message composition area
        message_input_label = QLabel("Type your message here:")
        message_input_label.setStyleSheet("color: white;")
        right_layout.addWidget(message_input_label)
        
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
        right_layout.addWidget(self.message_input)
        
        # Send button - Changed from green to blue
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
        right_layout.addWidget(send_button)
        
        # Add the right side to the splitter
        splitter.addWidget(right_widget)
        
        # Set stretch factors
        splitter.setStretchFactor(0, 1)  # Left side
        splitter.setStretchFactor(1, 3)  # Right side
        
        # Initial load of conversations
        self.refresh_conversations()
        
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
        
        # Buttons - Updated to blue color
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
        """Refresh the conversations list with proper handling for dictionary format"""
        try:
            # Obtenir toutes les conversations
            conversations_data = self.message_service.get_conversations()
            
            # Vérifier si nous avons reçu un dictionnaire au lieu d'une liste
            conversations_list = []
            if isinstance(conversations_data, dict):
                # Convertir le dictionnaire en liste
                for conv_id, conv_info in conversations_data.items():
                    # S'assurer que conv_info est un dictionnaire
                    if isinstance(conv_info, dict):
                        # Ajouter l'ID à l'objet conversation
                        conv_info["id"] = conv_id
                        conversations_list.append(conv_info)
                    else:
                        # Créer un dictionnaire avec des valeurs par défaut
                        conversations_list.append({
                            "id": conv_id,
                            "participants": ["Unknown"],
                            "timestamp": datetime.now().timestamp(),
                            "last_message": "No message content",
                            "unread_count": 0
                        })
            elif isinstance(conversations_data, list):
                # Si c'est déjà une liste, l'utiliser directement
                conversations_list = conversations_data
            else:
                # Ni liste ni dictionnaire - utiliser une liste vide
                logger.error(f"Unexpected conversations data type: {type(conversations_data)}")
                conversations_list = []
            
            # Sauvegarder la sélection actuelle
            current_id = None
            if self.conversations_list.currentItem():
                current_id = self.conversations_list.currentItem().data(Qt.UserRole)
                
            # Vider la liste
            self.conversations_list.clear()
            
            # Ajouter les conversations à la liste
            for conv in conversations_list:
                # S'assurer que conv est un dictionnaire
                if not isinstance(conv, dict):
                    logger.warning(f"Skipping invalid conversation format: {conv}")
                    continue
                    
                try:
                    # Créer l'élément de liste
                    item = QListWidgetItem()
                    
                    # Formater les participants
                    participants = ", ".join(conv.get("participants", ["Unknown"]))
                    
                    # Formater l'horodatage et l'aperçu
                    timestamp = datetime.fromtimestamp(conv.get("timestamp", 0))
                    time_str = timestamp.strftime("%Y-%m-%d %H:%M")
                    
                    # Texte d'affichage simplifié comme dans l'image
                    display_text = f"{participants}\n{time_str}\n{conv.get('last_message', 'No message')}"
                    
                    # Ajouter le nombre de non lus le cas échéant
                    unread_count = conv.get("unread_count", 0)
                    if unread_count > 0:
                        display_text += f" ({unread_count} unread)"
                    
                    item.setText(display_text)
                    item.setData(Qt.UserRole, conv.get("id", "unknown"))
                    
                    # Ajouter l'élément à la liste
                    self.conversations_list.addItem(item)
                except Exception as inner_e:
                    logger.error(f"Error processing conversation: {inner_e}")
                    
            # Restaurer la sélection si possible
            if current_id:
                for i in range(self.conversations_list.count()):
                    item = self.conversations_list.item(i)
                    if item.data(Qt.UserRole) == current_id:
                        self.conversations_list.setCurrentItem(item)
                        break
        except Exception as e:
            logger.error(f"Error refreshing conversations: {e}")
            # Ne pas afficher de message d'erreur à l'utilisateur ici
            # pour éviter de perturber l'interface
            
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
            
    def _conversation_selected(self, current, previous):
        """Handle selection of a conversation"""
        if not current:
            self.conversation_info.setText("Select a conversation")
            self.messages_display.clear()
            return
            
        # Get conversation ID from the selected item
        conversation_id = current.data(Qt.UserRole)
        
        try:
            # Load conversation messages
            messages = self.message_service.get_message_history(conversation_id=conversation_id)
            
            # Display conversation info (simplified like in the image)
            if messages:
                participants = set()
                for msg in messages:
                    if msg.sender:
                        participants.add(msg.sender)
                    if msg.recipient:
                        participants.add(msg.recipient)
                
                self.conversation_info.setText(f"Conversation with: {', '.join(participants)}")
                
                # Format and display messages in a simplified format like in the image
                self.messages_display.clear()
                
                # Create simplified HTML for messages
                html = "<html><body style='background-color:#9eb8cf;'>"
                
                for msg in messages:
                    # Format timestamp
                    timestamp = datetime.fromtimestamp(msg.timestamp)
                    time_str = timestamp.strftime("%H:%M")
                    
                    # Format sender name (simplified)
                    sender = msg.sender or "System"
                    
                    # Format the message based on type and sender
                    if sender == "ADMIN" or sender == "Administrator":
                        sender_display = "You"
                        align = "right" 
                    else:
                        sender_display = sender
                        align = "left"
                        
                    # Message formatting based on type
                    if msg.type == MessageType.WARNING:
                        # Warning - make it bold and red
                        content_style = "font-weight:bold; color:red;"
                    else:
                        # Normal information message
                        content_style = ""
                    
                    # Add the message bubble - Updated to use blue for user messages
                    bg_color = "#0078d7" if sender == "ADMIN" or sender == "Administrator" else "#f5f5f5"
                    text_color = "white" if sender == "ADMIN" or sender == "Administrator" else "black"
                    
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
                
                # Mark conversation as read
                self.message_service.mark_conversation_read(conversation_id)
                
            else:
                self.conversation_info.setText("No messages in this conversation")
                self.messages_display.clear()
        except Exception as e:
            logger.error(f"Error loading conversation: {e}")
            self.conversation_info.setText(f"Error loading conversation: {str(e)}")
            self.messages_display.clear()
            
    def _send_message(self):
        """Send a message in the current conversation"""
        # Check if we have a selected conversation
        if not self.conversations_list.currentItem():
            QMessageBox.warning(self, "No Conversation Selected", 
                              "Please select a conversation to send a message.")
            return
        
        # Get the message content
        content = self.message_input.toPlainText().strip()
        if not content:
            return
            
        # Get conversation ID
        conversation_id = self.conversations_list.currentItem().data(Qt.UserRole)
        
        try:
            # Get the recipient from the conversation
            messages = self.message_service.get_message_history(conversation_id=conversation_id)
            
            # Determine the recipient (first recipient that isn't us)
            recipient = None
            for msg in messages:
                if msg.sender and msg.sender != "Administrator" and msg.sender != "ADMIN":
                    recipient = msg.sender
                    break
                if msg.recipient and msg.recipient != "Administrator" and msg.recipient != "ADMIN":
                    recipient = msg.recipient
                    break
            
            if not recipient:
                QMessageBox.warning(self, "Error", "Could not determine message recipient.")
                return
                
            # Create and send the message - default to INFO type
            message = Message(
                content=content,
                msg_type=MessageType.INFO,
                sender="ADMIN",
                recipient=recipient,
                conversation_id=conversation_id
            )
            
            self.message_service.send_message(message)
            
            # Clear the input field
            self.message_input.clear()
            
            # Refresh the conversation display
            self._conversation_selected(self.conversations_list.currentItem(), None)
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            QMessageBox.critical(self, "Error", f"Could not send message: {str(e)}")
            
    def _new_message(self):
        """Create a new message"""
        dialog = NewMessageDialog(self.message_service, self)
        if dialog.exec_():
            # Get message data from dialog
            msg_data = dialog.get_message_data()
            if not msg_data["content"]:
                return
                
            # Create and send the message
            message = Message(
                content=msg_data["content"],
                msg_type=msg_data["msg_type"],
                sender="ADMIN",  
                recipient=msg_data["recipient"],
                is_broadcast=msg_data["is_broadcast"]
            )
            
            self.message_service.send_message(message)
            
            # Refresh conversations and select the new one
            self.refresh_conversations()
            
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
                    
                    # Rafraîchir les conversations
                    self.refresh_conversations()
                except Exception as e:
                    logger.error(f"Error broadcasting message: {e}")
                    QMessageBox.critical(self, "Error", f"Could not broadcast message: {str(e)}")
            
    def _message_selected_client(self):
        """Send a message to the selected client"""
        # Get selected client
        selected_rows = self.clients_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "No Client Selected", 
                              "Please select a client to message.")
            return
            
        row = selected_rows[0].row()
        client_id = self.clients_table.item(row, 0).text()
        
        # Show new message dialog
        dialog = NewMessageDialog(self.message_service, self)
        dialog.recipient_combo.setCurrentText(client_id)
        dialog.recipient_combo.setEnabled(False)  # Lock to selected client
        
        if dialog.exec_():
            # Get message data from dialog
            msg_data = dialog.get_message_data()
            if not msg_data["content"]:
                return
                
            # Create and send the message
            message = Message(
                content=msg_data["content"],
                msg_type=msg_data["msg_type"],
                sender="ADMIN",
                recipient=client_id,
                is_broadcast=False
            )
            
            self.message_service.send_message(message)
            
            # Refresh conversations
            self.refresh_conversations()


class NewMessageDialog(QDialog):
    """Dialog for composing a new message"""
    
    def __init__(self, message_service, parent=None):
        super().__init__(parent)
        self.message_service = message_service
        self.setWindowTitle("New Message")
        self.resize(500, 400)
        
        # Set dialog background and text colors
        self.setStyleSheet("""
            QDialog {
                background-color: #1a2633;
            }
            QLabel {
                color: white;
            }
            QCheckBox {
                color: white;
            }
            QGroupBox {
                color: white;
            }
            QRadioButton {
                color: white;
            }
        """)
        
        # Layout
        layout = QVBoxLayout(self)
        
        # Form for recipient
        form_layout = QFormLayout()
        
        # Recipient selection
        self.recipient_combo = QComboBox()
        self.recipient_combo.setStyleSheet("""
            font-size: 13px; 
            padding: 5px;
            color: white;
            background-color: #213243;
            selection-background-color: #0078d7;
        """)
        form_layout.addRow("Recipient:", self.recipient_combo)
        
        # Populate recipients
        self.populate_recipients()
        
        # Broadcast option
        self.broadcast_check = QCheckBox("Broadcast to all devices")
        self.broadcast_check.setStyleSheet("font-size: 13px; color: white;")
        self.broadcast_check.toggled.connect(self._broadcast_toggled)
        form_layout.addRow("", self.broadcast_check)
        
        layout.addLayout(form_layout)
        
        # Message type - REMOVED ERROR, KEPT ONLY INFO AND WARNING
        type_group = QGroupBox("Message Type")
        type_group.setStyleSheet("font-size: 13px; color: white;")
        type_layout = QHBoxLayout()
        
        self.type_info = QRadioButton("Information")
        self.type_info.setChecked(True)
        self.type_info.setStyleSheet("color: white;")
        type_layout.addWidget(self.type_info)
        
        self.type_warning = QRadioButton("Warning")
        self.type_warning.setStyleSheet("color: white;")
        type_layout.addWidget(self.type_warning)
        
        type_group.setLayout(type_layout)
        layout.addWidget(type_group)
        
        # Message content
        message_label = QLabel("Message:")
        message_label.setStyleSheet("color: white;")
        layout.addWidget(message_label)
        
        self.message_edit = QTextEdit()
        self.message_edit.setStyleSheet("""
            font-size: 13px;
            color: white;
            background-color: #213243;
            border: 1px solid #375a7f;
        """)
        layout.addWidget(self.message_edit)
        
        # Buttons with blue style
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        
        # Apply blue styling to the buttons
        for button in button_box.buttons():
            if button_box.buttonRole(button) == QDialogButtonBox.AcceptRole:
                button.setStyleSheet("""
                    QPushButton {
                        padding: 6px 12px;
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
            else:
                button.setStyleSheet("""
                    QPushButton {
                        padding: 6px 12px;
                        background-color: #2c3e50;
                        color: white;
                        border: none;
                        border-radius: 3px;
                    }
                    QPushButton:hover {
                        background-color: #34495e;
                    }
                """)
        
        layout.addWidget(button_box)
        
    def populate_recipients(self):
        """Populate the recipients dropdown"""
        self.recipient_combo.clear()
        
        # Add system devices
        devices = self.message_service.get_devices()
        for device in devices:
            self.recipient_combo.addItem(device, device)
            
        if not devices:
            self.recipient_combo.addItem("No devices available", "")
            
    def _broadcast_toggled(self, checked):
        """Handle toggling of broadcast option"""
        self.recipient_combo.setEnabled(not checked)
        
    def get_message_data(self):
        """Get the message data from the dialog"""
        # Determine message type - only INFO or WARNING now
        if self.type_warning.isChecked():
            msg_type = MessageType.WARNING
        else:
            msg_type = MessageType.INFO
            
        # Determine recipient
        is_broadcast = self.broadcast_check.isChecked()
        recipient = "all" if is_broadcast else self.recipient_combo.currentData()
        
        return {
            "recipient": recipient,
            "is_broadcast": is_broadcast,
            "msg_type": msg_type,
            "content": self.message_edit.toPlainText().strip()
        }


class ClientMessagingMode(QDialog):
    """Dialog to simulate being a client for testing"""
    
    def __init__(self, message_service, parent=None):
        super().__init__(parent)
        self.message_service = message_service
        self.setWindowTitle("Client Messaging Mode")
        self.resize(600, 500)
        
        # Set dialog styling for dark theme
        self.setStyleSheet("""
            QDialog {
                background-color: #1a2633;
            }
            QLabel {
                color: white;
            }
        """)
        
        # Layout
        layout = QVBoxLayout(self)
        
        # Client identity
        form = QFormLayout()
        self.client_id = QLineEdit("TestClient-1")
        self.client_id.setStyleSheet("""
            color: white;
            background-color: #213243;
            border: 1px solid #375a7f;
            padding: 5px;
        """)
        form.addRow("Client ID:", self.client_id)
        layout.addLayout(form)
        
        # Messages display
        layout.addWidget(QLabel("Messages:"))
        self.messages_display = QTextEdit()
        self.messages_display.setReadOnly(True)
        self.messages_display.setStyleSheet("""
            QTextEdit {
                color: white;
                background-color: #213243;
                border: 1px solid #375a7f;
            }
        """)
        layout.addWidget(self.messages_display)
        
        # New message
        layout.addWidget(QLabel("New Message:"))
        self.message_edit = QTextEdit()
        self.message_edit.setMaximumHeight(100)
        self.message_edit.setStyleSheet("""
            QTextEdit {
                color: white;
                background-color: #213243;
                border: 1px solid #375a7f;
                padding: 5px;
            }
        """)
        layout.addWidget(self.message_edit)
        
        # Buttons with blue styling
        buttons_layout = QHBoxLayout()
        
        send_button = QPushButton("Send Message")
        send_button.setStyleSheet("""
            QPushButton {
                padding: 6px 12px;
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
        buttons_layout.addWidget(send_button)
        
        refresh_button = QPushButton("Refresh Messages")
        refresh_button.setStyleSheet("""
            QPushButton {
                padding: 6px 12px;
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
        refresh_button.clicked.connect(self._refresh_messages)
        buttons_layout.addWidget(refresh_button)
        
        close_button = QPushButton("Close")
        close_button.setStyleSheet("""
            QPushButton {
                padding: 6px 12px;
                background-color: #2c3e50;
                color: white;
                border: none;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #34495e;
            }
        """)
        close_button.clicked.connect(self.close)
        buttons_layout.addWidget(close_button)
        
        layout.addLayout(buttons_layout)
        
        # Initial refresh
        self._refresh_messages()
        
    def _send_message(self):
        """Send a message as the client"""
        content = self.message_edit.toPlainText().strip()
        if not content:
            return
            
        # Create a message
        message = Message(
            content=content,
            msg_type=MessageType.INFO,
            sender=self.client_id.text(),
            recipient="Administrator"
        )
        
        # Send the message
        self.message_service.send_message(message)
        
        # Clear the input
        self.message_edit.clear()
        
        # Refresh messages
        self._refresh_messages()
        
    def _refresh_messages(self):
        """Refresh messages for this client"""
        try:
            # Get messages where this client is involved
            client_id = self.client_id.text()
            messages = (
                self.message_service.get_message_history(sender=client_id) + 
                self.message_service.get_message_history(recipient=client_id)
            )
            
            # Sort by timestamp
            messages.sort(key=lambda x: x.timestamp)
            
            # Format and display messages
            self.messages_display.clear()
            html = "<html><body style='background-color:#213243;'>"
            
            for msg in messages:
                # Format timestamp
                timestamp = datetime.fromtimestamp(msg.timestamp)
                time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                
                # Format message - simplified like in the image
                sender = msg.sender or "System"
                
                # Message formatting based on type
                if msg.type == MessageType.WARNING:
                    content_style = "font-weight:bold; color:red;"
                else:
                    content_style = ""
                
                if sender == client_id:
                    sender_display = "Me"
                    color = "#0078d7"  # Blue background
                    text_color = "white"  # White text for better contrast
                    align = "right"
                else:
                    sender_display = sender
                    color = "#2c3e50"  # Dark gray background
                    text_color = "white"  # White text
                    align = "left"
                
                html += f"""
                <div style="text-align:{align}; margin:15px 5px;">
                    <div style="display:inline-block; max-width:80%;">
                        <div style="font-weight:bold; color:{text_color};">{sender_display}</div>
                        <div style="background-color:{color}; padding:10px; border-radius:10px;">
                            <div style="{content_style}; color:{text_color};">{msg.content}</div>
                            <div style="font-size:10px; color:#ddd; text-align:right; margin-top:5px;">{time_str}</div>
                        </div>
                    </div>
                </div>
                """
            
            html += "</body></html>"
            self.messages_display.setHtml(html)
            
        except Exception as e:
            logger.error(f"Error refreshing client messages: {e}")
            QMessageBox.critical(self, "Error", f"Could not refresh messages: {str(e)}")