from PySide6 import QtWidgets, QtCore, QtGui
from PySide6.QtWidgets import (
     QVBoxLayout, QHBoxLayout,
     QLabel, QLineEdit, QDialog,
    QFormLayout, 
     QDialogButtonBox, QTabWidget, QCheckBox,
    
)
from PySide6.QtCore import (
    Qt, QTimer, QPropertyAnimation,
    QEasingCurve, QRect
)
from PySide6.QtGui import (
    QImage
)

import qrcode
from web3 import Web3

from wallet.constants import LIGHT_BLUE_BACKGROUND, TEXT_COLOR, TITLE_TEXT_COLOR, ACCENT_BLUE, IMG_FOLDER, WIDGET_RADIUS
from wallet.ui_components import RoundedButton, SecondaryButton, HeadlineLabel, BodyLabel, SeedPhraseBox, RoundedLineEdit, RoundedTextEdit, load_and_scale_image
from security import verify_pin_hash

from PySide6.QtCore import Qt, QAbstractTableModel

class TransactionTableModel(QAbstractTableModel):
    def __init__(self, transactions=None, parent=None):
        super().__init__(parent)
        self.transactions = transactions or []
        self.headers = ["TxHash", "Block", "From", "To", "Value", "Timestamp"]

    def rowCount(self, parent=None):
        return len(self.transactions)

    def columnCount(self, parent=None):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.DisplayRole:
            tx = self.transactions[index.row()]
            # Map header to key (lowercase)
            key = self.headers[index.column()].lower()
            return tx.get(key, "")
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if 0 <= section < len(self.headers):
                return self.headers[section]
        return super().headerData(section, orientation, role)

    def setTransactions(self, transactions):
        self.beginResetModel()
        self.transactions = transactions
        self.endResetModel()

# --- QR Code Generation ---
BACKGROUND_COLOR = LIGHT_BLUE_BACKGROUND

def generate_qr_code(data: str, scale_factor: int = 1) -> QImage:
    """Generates a QR code QImage from given data."""
    if not isinstance(data, str):
        raise ValueError("QR code data must be a string.")
    box_size = 10 * scale_factor
    border = 4

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white") # Black QR code on white
    pil_image = img.convert("RGB")

    data = pil_image.tobytes("raw", "RGB")
    qimage = QtGui.QImage(data, pil_image.width, pil_image.height,
                         pil_image.width * 3, QtGui.QImage.Format.Format_RGB888)
    return qimage


# --- Welcome Screen ---
class WelcomeScreen(QtWidgets.QWidget):
    """Welcome screen widget."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QtWidgets.QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        # Enhanced Welcome Screen with larger logo and tagline
        logo_pixmap = load_and_scale_image("0n1-black.svg", 150) # Larger logo
        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        headline = HeadlineLabel("Welcome to Wallet0n1") # More welcoming headline
        headline.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        btn_create = RoundedButton("Create New Wallet")
        btn_import = SecondaryButton("Import Existing Wallet")
        tagline = BodyLabel("Your Secure & Private Wallet.") # Clearer tagline
        tagline.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        tagline.setStyleSheet("font-style: italic;") # Italic style for tagline

        self.anim_create = QPropertyAnimation(btn_create, b"geometry")
        self.anim_create.setDuration(500)
        self.anim_create.setEasingCurve(QEasingCurve.Type.OutCubic)

        self.anim_import = QPropertyAnimation(btn_import, b"geometry")
        self.anim_import.setDuration(500)
        self.anim_import.setEasingCurve(QEasingCurve.Type.OutCubic)

        layout.addWidget(logo_label)
        layout.addWidget(headline)
        layout.addWidget(tagline) # Tagline placed before buttons
        layout.addWidget(btn_create)
        layout.addWidget(btn_import)

        self.setLayout(layout)
        self.btn_create = btn_create
        self.btn_import = btn_import

    def showEvent(self, event):
        super().showEvent(event)
        start_y_create = self.btn_create.y() + 50
        end_rect_create = self.btn_create.geometry()
        self.btn_create.move(self.btn_create.x(), start_y_create)
        self.anim_create.setStartValue(QRect(self.btn_create.x(), start_y_create, end_rect_create.width(), end_rect_create.height()))
        self.anim_create.setEndValue(end_rect_create)
        self.anim_create.start()

        start_y_import = self.btn_import.y() + 50
        end_rect_import = self.btn_import.geometry()
        self.btn_import.move(self.btn_import.x(), start_y_import)
        self.anim_import.setStartValue(QRect(self.btn_import.x(), start_y_import, end_rect_import.width(), end_rect_import.height()))
        self.anim_import.setEndValue(end_rect_import)
        self.anim_import.start()

# --- Create Wallet Screen ---
class CreateWalletScreen(QtWidgets.QWidget):
    """Screen for initiating wallet creation."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        headline = HeadlineLabel("Create Your Secure Wallet")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        explanation = BodyLabel("Creating a new wallet generates a unique set of keys that give you full control over your Ethereum assets. This is the most secure way to start.")
        explanation.setWordWrap(True)
        explanation.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_generate = RoundedButton("Generate Seed Phrase")
        layout.addWidget(headline)
        layout.addWidget(explanation)
        layout.addWidget(btn_generate)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(layout)
        self.btn_generate = btn_generate

# --- Seed Phrase Display Screen ---
class SeedPhraseDisplayScreen(QtWidgets.QWidget):
    """Screen to display the generated seed phrase."""
    def __init__(self, seed_phrase="", parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        self.seed_phrase = seed_phrase
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(50, 30, 50, 30)
        headline = HeadlineLabel("Your Secret Seed Phrase - Write This Down!")
        headline.setStyleSheet(f"font-size: 24px; color: {TITLE_TEXT_COLOR};")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        seed_box = SeedPhraseBox()
        seed_box.setText(seed_phrase)
        seed_box.setWordWrap(True)
        seed_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning = BodyLabel("Important Security Notice!\n• This seed phrase is your only backup. If lost, funds cannot be recovered.\n• Write it down exactly and offline.\n• **Never share it with anyone.**\n• **Do NOT copy and paste or screenshot this seed phrase.**") # Stronger warning, removed 'Copy' button
        warning.setStyleSheet("color: #FF5722; font-weight: bold;")
        warning.setWordWrap(True)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        #btn_copy = RoundedButton("Copy Seed Phrase") # Removed copy button for security
        btn_confirm = RoundedButton("I Have Written It Down - Continue")

        self.copy_confirmation_label = QLabel() # Kept for potential future use, currently unused
        self.copy_confirmation_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.copy_confirmation_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        self.copy_confirmation_label.setVisible(False)

        # Visual separator for Seed Phrase confirmation button
        separator_line = QtWidgets.QFrame()
        separator_line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        separator_line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)

        layout.addWidget(headline)
        layout.addWidget(seed_box)
        layout.addWidget(warning)
        #layout.addWidget(btn_copy) # Removed copy button
        layout.addWidget(self.copy_confirmation_label) # Kept label, but hidden
        layout.addWidget(separator_line) # Separator line
        layout.addWidget(btn_confirm)


        self.setLayout(layout)
        #self.btn_copy = btn_copy # Removed copy button
        self.btn_confirm = btn_confirm
        self.copy_confirmation_timer = QTimer()

    def show_copy_confirmation(self): # Kept for potential future use, currently unused
        self.copy_confirmation_label.setText("Seed Phrase Copied!")
        self.copy_confirmation_label.setVisible(True)
        self.copy_confirmation_timer.singleShot(1500, lambda: self.copy_confirmation_label.setVisible(False))


# --- Seed Phrase Confirmation Screen ---
class SeedPhraseConfirmationScreen(QtWidgets.QWidget):
    """Screen to confirm seed phrase entry."""
    def __init__(self, expected_words, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        self.expected_words = expected_words
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(50, 30, 50, 30)
        headline = HeadlineLabel("Verify Your Seed Phrase")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        instruction = BodyLabel("Enter the words in the correct order:")
        instruction.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(headline)
        layout.addWidget(instruction)
        self.wordEdits = []
        form_layout = QFormLayout()
        for i in range(len(expected_words)):
            edit = RoundedLineEdit()
            self.wordEdits.append(edit)
            form_layout.addRow(f"Word {i+1}:", edit)
        layout.addLayout(form_layout)
        btn_verify = RoundedButton("Verify & Continue")
        layout.addWidget(btn_verify)
        self.setLayout(layout)
        self.btn_verify = btn_verify

# --- Set Password Screen ---
class SetPasswordScreen(QtWidgets.QWidget):
    """Screen to set the PIN password."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QtWidgets.QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 20, 40, 20)

        lock_pixmap = load_and_scale_image("lock.png", 40)
        lock_label = QLabel()
        lock_label.setPixmap(lock_pixmap)
        lock_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        headline = HeadlineLabel("Secure Your App with a PIN Code")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        prompt = BodyLabel("Set a 4-digit PIN to protect your wallet.\n\n**Important Security Note:** A 4-digit PIN offers basic security suitable for convenience. For enhanced security, consider using a stronger passphrase or enabling device-level security features. This PIN protects access to your wallet *within this app* on this device. It is not a recovery method for your blockchain assets. **Your seed phrase is your ultimate recovery method.**") # Added security note
        prompt.setWordWrap(True)
        prompt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pwd_label = BodyLabel("Enter PIN - 4 digits:")
        self.pwd_edit = RoundedLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_edit.setInputMask("9999") # Input mask for 4 digits
        confirm_label = BodyLabel("Confirm PIN:")
        confirm_label.setObjectName("confirm_pin_label")
        self.confirm_edit = RoundedLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit.setInputMask("9999") # Input mask for 4 digits

        self.pin_match_label = BodyLabel("")
        self.pin_match_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(lock_label)
        layout.addWidget(headline)
        layout.addWidget(prompt)
        layout.addWidget(pwd_label)
        layout.addWidget(self.pwd_edit)
        layout.addWidget(confirm_label)
        layout.addWidget(self.confirm_edit)
        layout.addWidget(self.pin_match_label)

        self.btn_set = RoundedButton("Set PIN")
        layout.addWidget(self.btn_set)


        self.setLayout(layout)

        self.confirm_edit.textChanged.connect(self.check_pin_match)

    def check_pin_match(self):
        pin = self.pwd_edit.text()
        confirm_pin = self.confirm_edit.text()
        if confirm_pin:
            if pin == confirm_pin:
                self.pin_match_label.setText("<font color='#4CAF50'>PINs Match!</font>")
            else:
                self.pin_match_label.setText("<font color='#F44336'>PINs Do Not Match!</font>")
        else:
            self.pin_match_label.setText("")

# --- Wallet Creation Success Screen ---
class WalletCreationSuccessScreen(QtWidgets.QWidget):
    """Screen displayed after successful wallet creation."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QtWidgets.QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        headline = HeadlineLabel("Wallet Created Successfully!")
        headline.setStyleSheet("color: #4CAF50;")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message = BodyLabel("Your Ethereum wallet is now ready.")
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        backup_reminder = BodyLabel("Important: Please ensure you have securely backed up your seed phrase offline. This is crucial for wallet recovery.")
        backup_reminder.setStyleSheet("color: #FF9800; font-weight: bold;")
        backup_reminder.setWordWrap(True)
        backup_reminder.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_go = RoundedButton("Go to Wallet")
        layout.addWidget(headline)
        layout.addWidget(message)
        layout.addWidget(backup_reminder)
        layout.addWidget(btn_go)
        self.setLayout(layout)
        self.btn_go = btn_go

# --- Seed Phrase Import Screen ---
class SeedPhraseImportScreen(QtWidgets.QWidget):
    """Screen to import wallet using seed phrase."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(30, 20, 30, 20)
        headline = HeadlineLabel("Enter Your Seed Phrase")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        explanation = BodyLabel("Enter your 12 or 24-word seed phrase to restore your wallet.")
        explanation.setWordWrap(True)
        explanation.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.seed_edit = RoundedTextEdit()
        self.seed_edit.setPlaceholderText("Enter seed phrase here...")
        note = BodyLabel("Ensure you are entering your seed phrase in a secure environment.")
        note.setStyleSheet("font-size: 14px; color: #757575;")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.btn_import = RoundedButton("Import Wallet")
        layout.addWidget(headline)
        layout.addWidget(explanation)
        layout.addWidget(self.seed_edit)
        layout.addWidget(note)
        layout.addWidget(self.btn_import)
        self.setLayout(layout)

# --- Private Key Import Screen ---
class PrivateKeyImportScreen(QtWidgets.QWidget):
    """Screen to import wallet using private key."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(30, 20, 30, 20)
        headline = HeadlineLabel("Enter Your Private Key")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pk_edit = RoundedLineEdit()
        self.pk_edit.setPlaceholderText("Enter private key here...")
        self.btn_import = RoundedButton("Import Wallet")
        layout.addWidget(headline)
        layout.addWidget(self.pk_edit)
        layout.addWidget(self.btn_import)
        self.setLayout(layout)

# --- Import Wallet Screen (Tabbed) ---
class ImportWalletScreen(QtWidgets.QWidget):
    """Tabbed screen for different wallet import methods."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QtWidgets.QVBoxLayout()
        headline = HeadlineLabel("Import Your Existing Wallet")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(headline)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border-top: 2px solid {ACCENT_BLUE};
                background-color: {BACKGROUND_COLOR};
            }}

            QTabWidget::tab-bar {{
                left: 5px;
            }}

            QTabBar::tab {{
                background: white;
                color: {TEXT_COLOR};
                border: 1px solid #B0BEC5;
                border-bottom-color: none;
                border-top-left-radius: {WIDGET_RADIUS};
                border-top-right-radius: {WIDGET_RADIUS};
                min-width: 8ex;
                padding: 8px 20px;
            }}

            QTabBar::tab:selected, QTabBar::tab:hover {{
                background: {BACKGROUND_COLOR};
            }}

            QTabBar::tab:!selected {{
                margin-top: 2px;
            }}
        """)
        self.seed_tab = SeedPhraseImportScreen()
        self.pk_tab = PrivateKeyImportScreen()
        self.tabs.addTab(self.seed_tab, "Seed Phrase")
        self.tabs.addTab(self.pk_tab, "Private Key")
        layout.addWidget(self.tabs)
        self.setLayout(layout)

# --- Send ETH Dialog ---
class SendEthDialog(QDialog):
    """Dialog for sending ETH."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Send Ethereum")
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        self.setFixedSize(400,400)
        self.layout = QVBoxLayout()

        self.recipient_label = BodyLabel("Recipient Address:")
        self.recipient_edit = RoundedLineEdit()
        self.amount_label = BodyLabel("Amount (ETH):")
        self.amount_edit = RoundedLineEdit()
        self.amount_edit.setPlaceholderText("e.g., 0.01") # Added placeholder for amount

        self.confirmation_checkbox = QCheckBox("Confirm Transaction Details")
        self.confirmation_checkbox.setStyleSheet(f"color: {TEXT_COLOR}; font-family: {BodyLabel.font().family()};") # Consistent font
        self.confirmation_checkbox.setChecked(False)

        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)

        self.confirmation_checkbox.stateChanged.connect(lambda state: self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(state == Qt.CheckState.Checked))


        self.layout.addWidget(self.recipient_label)
        self.layout.addWidget(self.recipient_edit)
        self.layout.addWidget(self.amount_label)
        self.layout.addWidget(self.amount_edit)
        self.layout.addWidget(self.confirmation_checkbox)
        self.layout.addWidget(self.button_box)

        self.setLayout(self.layout)

    def get_recipient_address(self):
        address = self.recipient_edit.text().strip() # Get and strip whitespace
        if not Web3.is_address(address): # Address format validation in dialog
            raise ValueError("Invalid recipient address format.")
        return address

    def get_amount(self):
        amount_str = self.amount_edit.text().strip() # Get and strip whitespace
        try:
            amount = float(amount_str)
            if amount <= 0: # Amount value validation
                raise ValueError("Amount must be greater than zero.")
            return amount
        except ValueError:
            raise ValueError("Invalid amount format. Please enter a number.") # More informative error

# --- Settings Screen ---
class SettingsScreen(QtWidgets.QWidget):
    """Settings screen widget."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 20, 30, 20)
        headline = HeadlineLabel("Settings")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(headline)

        change_pin_button_layout = QHBoxLayout()
        change_pin_icon_label = QLabel()
        change_pin_icon = load_and_scale_image("pin_lock.png", 40)
        change_pin_icon_label.setPixmap(change_pin_icon)
        change_pin_button = RoundedButton("Change PIN Code")
        change_pin_button_layout.addWidget(change_pin_icon_label)
        change_pin_button_layout.addWidget(change_pin_button)
        layout.addLayout(change_pin_button_layout)


        export_pk_button_layout = QHBoxLayout()
        export_pk_icon_label = QLabel()
        pk_icon = load_and_scale_image("key_icon.svg", 40)
        export_pk_icon_label.setPixmap(pk_icon)
        export_pk_button = RoundedButton(" Export Private Key ")
        export_pk_button_layout.addWidget(export_pk_icon_label)
        export_pk_button_layout.addWidget(export_pk_button)
        layout.addLayout(export_pk_button_layout)

        export_seed_button_layout = QHBoxLayout()
        export_seed_icon_label = QLabel()
        seed_icon = load_and_scale_image("seed_phrase_icon.svg", 40)
        export_seed_icon_label.setPixmap(seed_icon)
        export_seed_button = RoundedButton(" Export Seed Phrase ")
        export_seed_button_layout.addWidget(export_seed_icon_label)
        export_seed_button_layout.addWidget(export_seed_button)
        layout.addLayout(export_seed_button_layout)

        forget_wallet_button_layout = QHBoxLayout() # Forget wallet in settings
        forget_wallet_icon_label = QLabel()
        forget_wallet_icon = load_and_scale_image("bin.png", 40) # Example delete icon
        forget_wallet_icon_label.setPixmap(forget_wallet_icon)
        forget_wallet_button = SecondaryButton("Forget Wallet") # Secondary button style
        forget_wallet_button.setStyleSheet(forget_wallet_button.styleSheet() + """
            QPushButton {
                background-color: #FFCDD2;
                color: #B71C1C;
                border: 5px solid #EF9A9A;
            }
            QPushButton:hover {
                background-color: #FFEBEE;
            }
        """)
        forget_wallet_button_layout.addWidget(forget_wallet_icon_label)
        forget_wallet_button_layout.addWidget(forget_wallet_button)
        layout.addLayout(forget_wallet_button_layout)


        back_button = RoundedButton("↩ Back" )
        layout.addWidget(back_button)
        about_button = RoundedButton("About ℹ")
        layout.addWidget(about_button)
        layout.addStretch()
        self.setLayout(layout)
        self.export_pk_button = export_pk_button
        self.export_seed_button = export_seed_button

    def open_change_pin_dialog(self):
        dialog = ChangePinDialog(self.parent())
        dialog.exec() # No need to handle result here, logic is in dialog accept

    def export_private_key(self):
        self.window().export_private_key_action()

    def export_seed_phrase(self):
        self.window().export_seed_phrase_action()

    def confirm_forget_wallet(self):
        self.window().forget_wallet() # Directly call forget wallet action on main window

    def back_to_dashboard(self):
        self.window().gotoDashboard()

# --- Change PIN Dialog ---
class ChangePinDialog(QDialog):
    """Dialog for changing the PIN code."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change PIN Code")
        self.setStyleSheet(f"background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR};")
        self.setFixedSize(400,400)
        self.layout = QVBoxLayout()

        self.old_pin_label = BodyLabel("Enter Current PIN - 4 digits:")
        self.old_pin_edit = RoundedLineEdit()
        self.old_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.old_pin_edit.setInputMask("9999") # Input mask for 4 digits

        self.new_pin_label = BodyLabel("Enter New PIN - 4 digits:")
        self.new_pin_edit = RoundedLineEdit()
        self.new_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pin_edit.setInputMask("9999") # Input mask for 4 digits

        self.confirm_pin_label = BodyLabel("Confirm New PIN:")
        self.confirm_pin_edit = RoundedLineEdit()
        self.confirm_pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_pin_edit.setInputMask("9999") # Input mask for 4 digits

        self.error_label = BodyLabel("")
        self.error_label.setStyleSheet("color: #F44336;")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.accepted.connect(self.accept_change_pin)
        self.button_box.rejected.connect(self.reject)

        self.layout.addWidget(self.old_pin_label)
        self.layout.addWidget(self.old_pin_edit)
        self.layout.addWidget(self.new_pin_label)
        self.layout.addWidget(self.new_pin_edit)
        self.layout.addWidget(self.confirm_pin_label)
        self.layout.addWidget(self.confirm_pin_edit)
        self.layout.addWidget(self.error_label)
        self.layout.addWidget(self.button_box)
        self.setLayout(self.layout)
        self.new_pin = None

    def wallet_data_loaded(self):
        self.old_pin_edit.setFocus()

    def accept_change_pin(self):
        old_pin = self.old_pin_edit.text()
        new_pin = self.new_pin_edit.text()
        confirm_pin = self.confirm_pin_edit.text()

        if not old_pin or not new_pin or not confirm_pin:
            self.error_label.setText("All fields are required.")
            return
        if new_pin != confirm_pin:
            self.error_label.setText("New PINs do not match.")
            return
        if len(new_pin) != 4: # PIN Length Validation
            self.error_label.setText("PIN must be 4 digits.")
            return

        main_window = self.window()
        wallet_data = main_window.wallet_data
        if not wallet_data:
            self.error_label.setText("Wallet data not loaded.")
            return

        try: # Using dedicated function for PIN verification
            if not verify_pin_hash(old_pin, wallet_data["pin_hash"]):
                self.error_label.setText("Incorrect current PIN.")
                return
        except ValueError as e: # Catch potential ValueErrors from verification function
            self.error_label.setText(f"PIN verification error: {e}")
            return

        self.new_pin = new_pin
        main_window.change_pin_code(new_pin) # Call change_pin_code on main window to update storage
        self.accept()


    def get_new_pin(self):
        return self.new_pin
