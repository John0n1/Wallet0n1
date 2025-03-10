# main.py
import sys
import os
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QDialog,
    QMessageBox, QProgressDialog, QInputDialog,
    QFileDialog, QStackedWidget,
    QGraphicsOpacityEffect,
    QTableView, QHeaderView, QAbstractItemView
)
from PySide6.QtCore import (
    Qt, QTimer, QPropertyAnimation,
    QEasingCurve, Signal, QThreadPool, QRunnable, QObject
)
from PySide6.QtGui import (
    QPixmap, QAction 
)
from PySide6 import QtCore
from eth_account import Account
from mnemonic import Mnemonic
import qrcode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import requests
from typing import List, Dict

from wallet.constants import  ETHERSCAN_API_KEY, LIGHT_BLUE_BACKGROUND, TEXT_COLOR, WALLET_DATA_SERVICE_NAME, WALLET_DATA_ACCOUNT_NAME, WalletError, NetworkError, EncryptionError, StorageError, InvalidInputError
from security import derive_fernet_key_from_pin, encrypt_data, decrypt_data, hash_pin, verify_pin_hash, SecureStorageManager
from wallet.blockchain import get_eth_balance, get_wallet_address, create_new_wallet, send_eth_transaction
from ui_components import RoundedButton, SecondaryButton, HeadlineLabel, BodyLabel,  RoundedLineEdit, load_and_scale_image, QRCodeLabel, AddressDropdown
from ui_screens import WelcomeScreen, CreateWalletScreen, SeedPhraseDisplayScreen, SeedPhraseConfirmationScreen, SetPasswordScreen, generate_qr_code, WalletCreationSuccessScreen, SettingsScreen, ImportWalletScreen, SendEthDialog, TransactionTableModel
from etherscan_api import EtherscanAPI
Account.enable_unaudited_hdwallet_features()

if sys.platform == "darwin":
    import keyring
elif sys.platform == "win32":
    import keyring
else:
    import keyring.backends.SecretService
    keyring.set_keyring(keyring.backends.SecretService.Keyring())


# --- Network Runnable (Threaded Operations) ---
class NetworkRunnable(QObject, QRunnable):
    """Runnable class for performing network operations in a separate thread."""
    balance_updated = Signal(str)
    tx_submitted = Signal(str)
    error_signal = Signal(str)

    def __init__(self, private_key, action, recipient=None, amount=None):
        QObject.__init__(self)
        QRunnable.__init__(self)
        self.private_key = private_key
        self.action = action
        self.recipient = recipient
        self.amount = amount

    @QtCore.Slot()
    def run(self):
        try:
            if self.action == "get_balance":
                balance = get_eth_balance(self.private_key)
                self.balance_updated.emit(balance)
            elif self.action == "send_eth":
                tx_hash_hex = send_eth_transaction(self.private_key, self.recipient, self.amount)
                self.tx_submitted.emit(tx_hash_hex)
        except NetworkError as e:
            self.error_signal.emit(str(e))
        except WalletError as e:
            self.error_signal.emit(str(e))
        except Exception as e:
            self.error_signal.emit(f"Unexpected error: {e}")


# --- Transaction History Runnable ---
class TransactionHistoryRunnable(QObject, QRunnable):
    """Runnable class for fetching transaction history in a separate thread."""
    history_updated = Signal(list)  # list of transactions
    error_signal = Signal(str)
    finished = Signal() # Signal when finished

    def __init__(self, address: str):
        QObject.__init__(self)
        QRunnable.__init__(self)
        self.address = address

    @QtCore.Slot()
    def run(self):
        try:
            transactions = EtherscanAPI.get_transactions(self.address, api_key=ETHERSCAN_API_KEY) # Pass Etherscan API key
            formatted_transactions = [EtherscanAPI.format_transaction(tx) for tx in transactions]
            self.history_updated.emit(formatted_transactions)
        except Exception as e:
            self.error_signal.emit(f"Error fetching transaction history: {e}")
        finally:
            self.finished.emit() # Emit finished signal when done (or error)


# --- Dashboard Application (Main Window) ---
class DashboardApp(QMainWindow):
    """Main application window for the Wallet0n1."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wallet0n1 –– Simplicity - Security - Privacy")
        self.setStyleSheet(f"background-color: {LIGHT_BLUE_BACKGROUND}; color: {TEXT_COLOR};")
        self.setFixedSize(400, 500)  # Fixed size for main window

        # Add top centered 0xbuild logo (80x80)
        self.top_logo = QLabel()
        logo_pixmap = load_and_scale_image("0n1-black.svg", 50) # Ensure you have this logo file
        self.top_logo.setPixmap(logo_pixmap)
        self.top_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.addWidget(self.top_logo) # Add logo to main layout

        self.stack = QStackedWidget()
        self.main_layout.addWidget(self.stack)

        self.welcomeScreen = WelcomeScreen()
        self.createWalletScreen = CreateWalletScreen()
        self.seedDisplayScreen = SeedPhraseDisplayScreen()
        self.seedConfirmScreen = None
        self.setPasswordScreen = SetPasswordScreen()
        self.successScreen = WalletCreationSuccessScreen()
        self.dashboardScreen = QWidget()
        self.importWalletScreen = ImportWalletScreen()
        self.settingsScreen = SettingsScreen(self)
        self.pinVerificationScreen = SetPasswordScreen()
        self.transactionsScreen = QWidget() # Transactions screen widget

        self.stack.addWidget(self.welcomeScreen)
        self.stack.addWidget(self.createWalletScreen)
        self.stack.addWidget(self.seedDisplayScreen)
        self.stack.addWidget(self.setPasswordScreen)
        self.stack.addWidget(self.successScreen)
        self.stack.addWidget(self.dashboardScreen)
        self.stack.addWidget(self.importWalletScreen)
        self.stack.addWidget(self.settingsScreen)
        self.stack.addWidget(self.pinVerificationScreen)
        self.stack.addWidget(self.transactionsScreen) # Add transactions screen


        self.welcomeScreen.btn_create.clicked.connect(self.gotoCreateWallet)
        self.welcomeScreen.btn_import.clicked.connect(self.gotoImportWallet)
        self.createWalletScreen.btn_generate.clicked.connect(self.generateSeedPhrase)
        #self.seedDisplayScreen.btn_copy.clicked.connect(self.copySeedPhrase) # Removed copy button
        self.seedDisplayScreen.btn_confirm.clicked.connect(self.gotoSeedConfirmation)
        self.setPasswordScreen.btn_set.clicked.connect(self.setPasswordAndComplete)
        self.successScreen.btn_go.clicked.connect(self.gotoDashboard)

        self.importWalletScreen.seed_tab.btn_import.clicked.connect(self.importWalletFromSeed)
        self.importWalletScreen.pk_tab.btn_import.clicked.connect(self.importWalletFromPrivateKey)

        pin_verify_layout = QVBoxLayout()

        pin_verify_lock_pixmap = load_and_scale_image("lock.png", 150)
        pin_verify_lock_label = QLabel()
        pin_verify_lock_label.setPixmap(pin_verify_lock_pixmap)
        pin_verify_lock_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pin_verify_layout.addWidget(pin_verify_lock_label)

        pin_verify_layout.addSpacing(10)  # Reduced spacing between lock and input

        pin_input_widget = QWidget()
        pin_input_widget.setContentsMargins(8, 8, 8, 8)  # Shrink margins for pin input widget
        pin_input_layout = QVBoxLayout(pin_input_widget)

        pin_label = BodyLabel("Enter PIN:")
        pin_label.setStyleSheet(f"color: {TEXT_COLOR}; font-size: 16px;")
        pin_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.pin_input = RoundedLineEdit()
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_input.setInputMask("9999") # Input mask for 4 digits
        self.pin_input.setFixedWidth(80)
        self.pin_input.setAlignment(Qt.AlignmentFlag.AlignCenter)

        unlock_btn = RoundedButton("Unlock Wallet")
        unlock_btn.clicked.connect(self.verify_pin_and_load_wallet)

        forget_btn = SecondaryButton("Forget Wallet") # Still present on PIN screen for emergency forget.
        forget_btn.clicked.connect(self.forget_wallet)
        forget_btn.setStyleSheet(forget_btn.styleSheet() + """
            QPushButton {
                background-color: #FFCDD2;
                color: #B71C1C;
                border: 1px solid #EF9A9A;
            }
            QPushButton:hover {
                background-color: #FFEBEE;
            }
        """)

        pin_input_layout.addWidget(pin_label, alignment=Qt.AlignmentFlag.AlignCenter)
        pin_input_layout.addWidget(self.pin_input, alignment=Qt.AlignmentFlag.AlignCenter)
        pin_input_layout.addSpacing(5)   # Reduced spacing after input field
        pin_input_layout.addWidget(unlock_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        pin_input_layout.addSpacing(10)  # Reduced spacing before forget button
        pin_input_layout.addWidget(forget_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        pin_verify_layout.addWidget(pin_input_widget)

        pin_verify_container = QWidget()
        pin_verify_container.setLayout(pin_verify_layout)

        self.stack.addWidget(pin_verify_container)
        self.pinVerificationScreen_index = self.stack.count() - 1

        self.price_label = BodyLabel("ETH Price: Loading...")
        self.price_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.init_dashboard()
        self.init_transactions_screen() # Initialize transactions screen with table
        self.price_timer = QTimer(self)
        self.price_timer.timeout.connect(self.fetch_eth_price)
        self.price_timer.start(30000)
        self.fetch_eth_price()
        self.storage_manager = SecureStorageManager(WALLET_DATA_SERVICE_NAME, WALLET_DATA_ACCOUNT_NAME)

        self.settings_button = None # Placeholder, initialized in create_menu

        self.create_menu() # Initialize menu bar and settings button

        try:
            self.wallet_data = self.storage_manager.load_wallet_data()
        except StorageError as e:
            QMessageBox.critical(self, "Storage Error", str(e))
            self.wallet_data = None
        if self.wallet_data:
            self.gotoPinVerification()
        else:
            self.gotoWelcome()


        # Add title to welcomeScreen
        welcome_title = HeadlineLabel("Wallet0n1")
        welcome_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.welcomeScreen.layout().insertWidget(0, welcome_title)

    def create_menu(self):
        """Creates the application menu bar."""
        menu_bar = self.menuBar()
        settings_menu = menu_bar.addMenu("&Settings") # Settings Menu
        self.settings_button = QAction("Settings", self) # Settings Action
        self.settings_button.triggered.connect(self.gotoSettings)
        self.settings_button.setEnabled(False) # Disabled initially, enabled after PIN verification
        settings_menu.addAction(self.settings_button)
        about_action = QAction("About", self) # About Action
        about_action.triggered.connect(self.show_about_dialog)
        settings_menu.addAction(about_action)

    def gotoPinVerification(self):
        """Navigates to the PIN verification screen."""
        self.stack.setCurrentIndex(self.pinVerificationScreen_index)

    def verify_pin_and_load_wallet(self):
        """Verifies PIN, loads wallet data, and navigates to dashboard."""
        entered_pin = self.pin_input.text()
        if not entered_pin or len(entered_pin) != 4:
            QMessageBox.critical(self, "Error", "Please enter a 4-digit PIN.")
            return

        try: # Using dedicated function for PIN verification
            if not verify_pin_hash(entered_pin, self.wallet_data["pin_hash"]):
                QMessageBox.critical(self, "Error", "Incorrect PIN.")
                return
        except ValueError as e: # Catch potential ValueErrors from verification function
            QMessageBox.critical(self, "Error", f"PIN verification error: {e}")
            return

        self.pin_verified = True
        self.settings_button.setEnabled(True) # Enable settings button after PIN verification

        encryption_key, _ = derive_fernet_key_from_pin(entered_pin, self.wallet_data["salt"])

        try:
            self.private_key = decrypt_data(self.wallet_data["encrypted_pk"], encryption_key)
            self.seed_phrase = decrypt_data(self.wallet_data["encrypted_seed_phrase"], encryption_key) if self.wallet_data["encrypted_seed_phrase"] else None
        except EncryptionError as e:
            QMessageBox.critical(self, "Decryption Error", str(e))
            return

        self.address = self.wallet_data["address"]
        self.update_dashboard_info()
        self.gotoDashboard()
        self.pinVerificationScreen.pwd_edit.clear()

        # Consider implementing brute-force protection here:
        # - Track failed login attempts.
        # - Implement a delay or lockout after too many failures.
        # - This is a conceptual note - rate limiting is more complex to implement robustly in a simple desktop app without backend.

    def gotoWelcome(self):
        """Navigates to the welcome screen."""
        self.stack.setCurrentIndex(0)
        self.settings_button.setEnabled(False) # Disable settings button on welcome screen

    def init_dashboard(self):
        """Initializes the dashboard screen UI elements."""
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)

        layout.addWidget(self.price_label, alignment=Qt.AlignmentFlag.AlignCenter)

        self.addr_dropdown = AddressDropdown()

        self.qr_code_label = QRCodeLabel(self) # Pass self (DashboardApp instance) as parent
        self.qr_code_label.setFixedSize(150, 150)

        # New balance header layout for icon and title text
        balance_header_layout = QHBoxLayout()
        balance_header_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Center align the entire layout
        balance_icon_label = QLabel()
        balance_icon = load_and_scale_image("Balance_icon.svg", 15)
        balance_icon_label.setPixmap(balance_icon)
        balance_icon_label.setContentsMargins(0, 0, 0, 0)  # Keep icon and text close together
        balance_title = BodyLabel("Balance:")
        balance_header_layout.addWidget(balance_icon_label, alignment=Qt.AlignmentFlag.AlignCenter)
        balance_header_layout.addWidget(balance_title, alignment=Qt.AlignmentFlag.AlignCenter)

        # New layout for balance value (ETH) and refresh button
        balance_value_layout = QHBoxLayout()
        balance_value_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Center the entire layout
        self.balance_value = BodyLabel("Loading...")
        balance_value_layout.addWidget(self.balance_value)
        self.refresh_button = QPushButton("↻")
        self.refresh_button.setFixedWidth(10)
        self.refresh_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 5px;
                font-size: 15px;
                color: {TEXT_COLOR};
            }
            QPushButton:hover {
                background-color: #ECEFF1;
                border-radius: 5px;
            }
        """)
        self.refresh_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_button.clicked.connect(self.refresh_balance)
        balance_value_layout.addWidget(self.refresh_button)

        # Make send ETH button smaller
        send_eth_button = RoundedButton("Send ETH")
        send_eth_button.setFixedWidth(170)  # Reduced from 180 to 140
        send_eth_button.clicked.connect(self.open_send_eth_dialog)

        receive_eth_button = RoundedButton("Receive ETH") # Receive button
        receive_eth_button.setFixedWidth(170) # Same width as send button
        receive_eth_button.clicked.connect(self.show_receive_qr_code) # Connect to receive function

        transactions_button = RoundedButton("Transactions") # Transactions button
        transactions_button.setFixedWidth(170)
        transactions_button.clicked.connect(self.gotoTransactions)


        layout.addWidget(self.addr_dropdown, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.qr_code_label, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(balance_header_layout)  # (optional reuse, or remove if duplicate)
        layout.addLayout(balance_value_layout)
        layout.addWidget(receive_eth_button, alignment=Qt.AlignmentFlag.AlignCenter) # Receive button added
        layout.addWidget(send_eth_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(transactions_button, alignment=Qt.AlignmentFlag.AlignCenter) # Transactions button
        layout.addStretch()

        self.dashboardScreen.setLayout(layout)

    def init_transactions_screen(self):
        """Initializes the transactions screen with a table view."""
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        headline = HeadlineLabel("Transaction History")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(headline)

        self.transactions_table_view = QTableView() # Using QTableView for structured transaction display
        self.transactions_table_view.setSelectionBehavior(QAbstractItemView.SelectRows) # Select full row
        self.transactions_table_view.setEditTriggers(QAbstractItemView.NoEditTriggers) # Disable editing
        self.transactions_table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents) # Resize columns to content
        self.transactions_table_view.verticalHeader().setVisible(False) # Hide vertical header numbers

        # Basic styling for table (can be further customized with QSS)
        self.transactions_table_view.setStyleSheet("""
            QTableView {
                background-color: white;
                border: 1px solid #B0BEC5;
                border-radius: 12px;
                gridline-color: #ECEFF1;
                font-family: Roboto;
                font-size: 14px;
            }
            QHeaderView::section {
                background-color: #ECEFF1;
                border: 0px;
                padding: 4px;
                font-weight: bold;
            }
            QTableView::item {
                padding: 5px;
            }
            QTableView::item:selected {
                background-color: #64B5F6; /* Accent Blue - Selected Row Highlight */
                color: white;
            }
        """)

        self.transaction_model = TransactionTableModel() # Initialize table model
        self.transactions_table_view.setModel(self.transaction_model) # Set model to table view

        layout.addWidget(self.transactions_table_view)

        back_button = RoundedButton("↩ Back to Dashboard")
        back_button.clicked.connect(self.gotoDashboard)
        layout.addWidget(back_button)

        self.transactionsScreen.setLayout(layout)


    def update_dashboard_info(self):
        """Updates balance, address, and QR code on the dashboard."""
        if self.private_key:
            self.address = get_wallet_address(self.private_key)
            self.addr_dropdown.setAddress(self.address)
            self.balance_value.setText("Loading...")

            qr_image = generate_qr_code(self.address)
            qr_pixmap = QPixmap.fromImage(qr_image)
            qr_pixmap = qr_pixmap.scaled(140, 140, Qt.AspectRatioMode.KeepAspectRatio,
                                        Qt.TransformationMode.SmoothTransformation)
            self.qr_code_label.setPixmap(qr_pixmap)

            self.network_thread = NetworkRunnable(self.private_key, "get_balance") # Use NetworkRunnable
            self.network_thread.balance_updated.connect(self.update_balance_display)
            self.network_thread.error_signal.connect(self.handle_network_error)
            self.threadpool = QThreadPool.globalInstance()
            self.threadpool.start(self.network_thread) # Start runnable in threadpool # Thread Management
        else:
            self.addr_dropdown.setAddress("")
            self.balance_value.setText("N/A")
            self.qr_code_label.clear()

    def update_balance_display(self, balance_text):
        """Updates the balance display with animation."""
        self.balance_value.setText(balance_text)
        # Balance update animation
        anim = QPropertyAnimation(self.balance_value, b"styleSheet")
        anim.setDuration(500)
        anim.setStartValue("color: "+TEXT_COLOR+";")
        anim.setEndValue("color: #4CAF50;")
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def handle_network_error(self, error_message):
        """Handles network errors and displays error messages."""
        self.balance_value.setText("Error")
        QMessageBox.critical(self, "Network Error", error_message)

    def gotoCreateWallet(self):
        """Navigates to the create wallet screen."""
        self.stack.setCurrentIndex(1)

    def generateSeedPhrase(self):
        """Generates a new seed phrase and navigates to the display screen."""
        progress_dialog = QProgressDialog("Generating Wallet...", "Cancel", 0, 0, self)
        progress_dialog.setCancelButtonText(None)
        progress_dialog.setModal(True)
        progress_dialog.show()
        QApplication.processEvents()

        try:
            pk, info, mnemonic_phrase = create_new_wallet()
            self.seed_phrase = mnemonic_phrase
            self.private_key = pk
            self.seedDisplayScreen.seed_phrase = self.seed_phrase
            self.seedDisplayScreen.layout().itemAt(1).widget().setText(self.seed_phrase)
            self.stack.setCurrentIndex(2)
        except WalletError as e:
            QMessageBox.critical(self, "Wallet Error", str(e))
        finally:
            progress_dialog.close()

    #def copySeedPhrase(self): # Removed copy button
    #    """Copies seed phrase to clipboard (removed for security, kept for reference)."""
    #    QApplication.clipboard().setText(self.seed_phrase)
    #    self.seedDisplayScreen.show_copy_confirmation()

    def gotoSeedConfirmation(self):
        """Navigates to the seed phrase confirmation screen."""
        expected = self.seed_phrase.split()
        self.seedConfirmScreen = SeedPhraseConfirmationScreen(expected)
        self.seedConfirmScreen.btn_verify.clicked.connect(self.verifySeedPhrase)
        self.stack.addWidget(self.seedConfirmScreen)
        self.stack.setCurrentIndex(3)

    def verifySeedPhrase(self):
        """Verifies the entered seed phrase against the generated one."""
        expected = self.seed_phrase.split()
        for i, edit in enumerate(self.seedConfirmScreen.wordEdits):
            if edit.text().strip() != expected[i]:
                QMessageBox.critical(self, "Error", f"Word {i+1} is incorrect!")
                return
        QMessageBox.information(self, "Success", "Seed phrase verified!")
        self.gotoSetPassword()

    def gotoSetPassword(self):
        """Navigates to the set password screen."""
        self.stack.setCurrentIndex(4)

    def setPasswordAndComplete(self):
        """Sets the PIN password, encrypts wallet data, and completes wallet creation."""
        pin = self.setPasswordScreen.pwd_edit.text()
        confirm_pin = self.setPasswordScreen.confirm_edit.text()
        if pin != confirm_pin or not pin or len(pin) != 4: # PIN Length Validation
            QMessageBox.critical(self, "Error", "PIN codes do not match, are empty, or not 4 digits!")
            return

        pin_hash_val = hash_pin(pin)
        encryption_key_val, salt_val = derive_fernet_key_from_pin(pin)

        encrypted_pk_val = encrypt_data(self.private_key, encryption_key_val)
        encrypted_seed_phrase_val = encrypt_data(self.seed_phrase, encryption_key_val) if self.seed_phrase else None

        try:
            self.storage_manager.save_wallet_data(pin_hash_val, encrypted_pk_val, encrypted_seed_phrase_val, salt_val, get_wallet_address(self.private_key))
        except StorageError as e:
            QMessageBox.critical(self, "Storage Error", str(e))
            return

        self.wallet_data = self.storage_manager.load_wallet_data()
        self.pin_verified = True
        self.settings_button.setEnabled(True) # Enable settings button after wallet creation
        self.stack.setCurrentIndex(5)

    def change_pin_code(self, new_pin):
        """Changes the PIN code and updates secure storage."""
        if not self.wallet_data:
            QMessageBox.critical(self, "Error", "Wallet data not loaded.")
            return

        new_pin_hash = hash_pin(new_pin)
        encryption_key_val, salt_val = derive_fernet_key_from_pin(new_pin, self.wallet_data["salt"])
        encrypted_pk_val = encrypt_data(self.private_key, encryption_key_val)
        encrypted_seed_phrase_val = encrypt_data(self.seed_phrase, encryption_key_val) if self.seed_phrase else None

        try:
            self.storage_manager.save_wallet_data(new_pin_hash, encrypted_pk_val, encrypted_seed_phrase_val, salt_val, self.wallet_data["address"])
        except StorageError as e:
            QMessageBox.critical(self, "Storage Error", str(e))
            return

        self.wallet_data = self.storage_manager.load_wallet_data()
        QMessageBox.information(self, "Success", "PIN code changed successfully.")

    def gotoSuccess(self): # Unused, kept for potential future animated success screen
        """Navigates to the success screen (unused, kept for potential future use)."""
        headline = self.successScreen.findChild(HeadlineLabel)
        if headline:
            anim = QPropertyAnimation(headline, b"geometry")
            orig_geom = headline.geometry()
            anim.setDuration(800)
            anim.setStartValue(orig_geom)
            bigger = orig_geom.adjusted(-5, -5, 5, 5)
            anim.setKeyValueAt(0.5, bigger)
            anim.setEndValue(orig_geom)
            anim.setEasingCurve(QEasingCurve.Type.OutBounce)
            anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        QMessageBox.warning(self, "Backup Seed Phrase!", "Please ensure you have securely backed up your seed phrase offline. This is crucial for wallet recovery.")
        self.gotoDashboard()

    def gotoDashboard(self):
        """Navigates to the dashboard screen."""
        self.stack.setCurrentIndex(5)
        self.update_dashboard_info()

    def gotoImportWallet(self):
        """Navigates to the import wallet screen."""
        self.stack.setCurrentIndex(6)

    def importWalletFromSeed(self):
        """Imports wallet from seed phrase."""
        seed = self.importWalletScreen.seed_tab.seed_edit.toPlainText().strip()

        progress_dialog = QProgressDialog("Importing Wallet...", "Cancel", 0, 0, self)
        progress_dialog.setCancelButtonText(None)
        progress_dialog.setModal(True)
        progress_dialog.show()
        QApplication.processEvents()

        words = seed.split()
        if len(words) not in (12, 24):
            QMessageBox.critical(self, "Error", "Seed phrase must be 12 or 24 words!")
            progress_dialog.close()
            return
        try:
            Mnemonic("english").to_seed(seed) # Validate seed phrase format - Input Validation
        except ValueError: # Specific Exception
            QMessageBox.critical(self, "Error", "Invalid seed phrase format or checksum failed.") # More specific error
            progress_dialog.close()
            return

        self.seed_phrase = seed
        try:
            account = Account.from_mnemonic(seed)
            self.private_key = account.key.hex()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import wallet from seed: {e}")
        finally:
            progress_dialog.close()

        self.gotoSetPassword()

    def importWalletFromPrivateKey(self):
        """Imports wallet from private key."""
        pk = self.importWalletScreen.pk_tab.pk_edit.text().strip()

        progress_dialog = QProgressDialog("Importing Wallet...", "Cancel", 0, 0, self)
        progress_dialog.setCancelButtonText(None)
        progress_dialog.setModal(True)
        progress_dialog.show()
        QApplication.processEvents()

        if not pk:
            QMessageBox.critical(self, "Error", "Please enter a valid private key!")
            progress_dialog.close()
            return
        if len(pk) != 64 or not all(c in '0123456789abcdefABCDEF' for c in pk):
            QMessageBox.critical(self, "Error", "Invalid private key format. Must be a 64-character hexadecimal string.")
            progress_dialog.close()
            return
        try:
            account = Account.from_key(pk) # Attempt to import to validate - Input Validation
            self.private_key = pk
        except Exception as e: # Catch specific exception if possible, or keep broad for now.
            QMessageBox.critical(self, "Error", f"Failed to import wallet: Invalid Private Key.") # More specific error
        finally:
            progress_dialog.close()

        self.gotoSetPassword()

    def copy_address_to_clipboard(self): # Unused, functionality moved to AddressDropdown
        """Copies address to clipboard (unused, functionality moved to AddressDropdown)."""
        if self.address:
            QApplication.clipboard().setText(self.address)
            QMessageBox.information(self, "Copied", "Address copied to clipboard!")
        else:
            QMessageBox.warning(self, "Warning", "No address to copy.")

    def refresh_balance(self):
        """Refreshes the ETH balance."""
        self.update_dashboard_info()

    def open_send_eth_dialog(self):
        """Opens the send ETH dialog."""
        if not self.private_key:
            QMessageBox.warning(self, "Warning", "No wallet loaded. Please create or import a wallet first.")
            return

        dialog = SendEthDialog(self)
        dialog.setFixedSize(400,400)
        try: # Input validation moved to dialog's get_recipient_address and get_amount methods, error handling here
            if dialog.exec():
                recipient_address = dialog.get_recipient_address()
                amount_eth = dialog.get_amount()

                confirmation_msg = f"Send {amount_eth} ETH to {recipient_address}?"
                confirm_dialog = QMessageBox.question(self, "Confirm Transaction", confirmation_msg, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
                if confirm_dialog == QMessageBox.StandardButton.No:
                    return

                self.progress_dialog = QProgressDialog("Sending ETH...", "Cancel", 0, 0, self)
                self.progress_dialog.setCancelButtonText(None)
                self.progress_dialog.setModal(True)
                self.progress_dialog.show()

                self.network_runnable = NetworkRunnable(self.private_key, "send_eth", recipient_address, amount_eth) # Use NetworkRunnable
                self.network_runnable.tx_submitted.connect(self.handle_tx_submitted)
                self.network_runnable.error_signal.connect(self.handle_send_eth_error)
                self.network_runnable.finished.connect(self.progress_dialog.close)
                self.threadpool = QThreadPool.globalInstance()
                self.threadpool.start(self.network_runnable) # Start runnable in threadpool # Thread Management

        except InvalidInputError as e: # Catch input validation errors from dialog
            QMessageBox.critical(self, "Input Error", str(e))

    def handle_tx_submitted(self, tx_hash_hex):
        """Handles successful transaction submission."""
        QMessageBox.information(self, "Success", f"ETH sent! Transaction Hash: {tx_hash_hex}")
        self.refresh_balance()
        self.fetch_transaction_history() # Refresh transaction history after sending

    def handle_send_eth_error(self, error_message):
        """Handles errors during ETH sending."""
        QMessageBox.critical(self, "Error Sending ETH", error_message)

    def gotoSettings(self):
        """Navigates to the settings screen."""
        self.stack.setCurrentIndex(7)

    def export_private_key_action(self):
        """Exports private key to a file after PIN verification."""
        if not self.private_key:
            QMessageBox.warning(self, "Warning", "No wallet loaded.")
            return

        pin, ok = QInputDialog.getText(self, "Export Private Key", "Enter your PIN to decrypt and export your Private Key:", echo=QLineEdit.EchoMode.Password)
        if ok and pin:
            try: # Using dedicated function for PIN verification
                if not verify_pin_hash(pin, self.wallet_data["pin_hash"]):
                    QMessageBox.critical(self, "Error", "Incorrect PIN.")
                    return
            except ValueError as e: # Catch potential ValueErrors from verification function
                QMessageBox.critical(self, "Error", f"PIN verification error: {e}")
                return

            try:
                encryption_key, _ = derive_fernet_key_from_pin(pin, self.wallet_data["salt"])
                decrypted_pk = decrypt_data(self.wallet_data["encrypted_pk"], encryption_key)
            except EncryptionError as e:
                QMessageBox.critical(self, "Decryption Error", str(e))
                return

            file_path, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "", "Text Files (*.txt);;All Files (*)")
            if file_path:
                try:
                    with open(file_path, 'w') as f:
                        f.write(decrypted_pk)
                    QMessageBox.information(self, "Success", f"Private Key exported to:\n{file_path}\n\nKeep this file VERY secure and private!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Error saving private key: {e}")

    def export_seed_phrase_action(self):
        """Exports seed phrase to a file after PIN verification."""
        if not self.seed_phrase:
            QMessageBox.warning(self, "Warning", "No seed phrase available.")
            return

        pin, ok = QInputDialog.getText(self, "Export Seed Phrase", "Enter your PIN to decrypt and export your Seed Phrase:", echo=QLineEdit.EchoMode.Password)
        if ok and pin:
            try: # Using dedicated function for PIN verification
                if not verify_pin_hash(pin, self.wallet_data["pin_hash"]):
                    QMessageBox.critical(self, "Error", "Incorrect PIN.")
                    return
            except ValueError as e: # Catch potential ValueErrors from verification function
                QMessageBox.critical(self, "Error", f"PIN verification error: {e}")
                return

            try:
                encryption_key, _ = derive_fernet_key_from_pin(pin, self.wallet_data["salt"])
                seed_phrase_to_export = decrypt_data(self.wallet_data["encrypted_seed_phrase"], encryption_key)
            except EncryptionError as e:
                QMessageBox.critical(self, "Decryption Error", str(e))
                return

            file_path, _ = QFileDialog.getSaveFileName(self, "Save Seed Phrase", "", "Text Files (*.txt);;All Files (*)")
            if file_path:
                try:
                    with open(file_path, 'w') as f:
                        f.write(seed_phrase_to_export)
                    QMessageBox.information(self, "Success", f"Seed Phrase exported to:\n{file_path}\n\nKeep this file VERY secure and private!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Error saving seed phrase: {e}")

    def forget_wallet(self):
        """Deletes wallet data from secure storage after confirmation."""
        reply = QMessageBox.question(
            self,
            "Forget Wallet",
            "Are you sure you want to forget this wallet?\n\nThis will delete all stored wallet data. Make sure you have your seed phrase or private key backed up if you want to restore this wallet later.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.storage_manager.delete_wallet_data()

                self.private_key = None
                self.seed_phrase = ""
                self.address = None
                self.wallet_data = None
                self.pin_verified = False

                self.settings_button.setEnabled(False) # Disable settings button after forgetting wallet
                self.pinVerificationScreen.pwd_edit.clear()

                self.gotoWelcome()

                QMessageBox.information(self, "Success", "Wallet data has been deleted.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete wallet data: {e}")

    def show_about_dialog(self):
        """Displays the 'About' dialog."""
        dialog = QDialog(self)
        dialog.setWindowTitle("About Wallet0n1")
        dialog.setStyleSheet(f"background-color: {LIGHT_BLUE_BACKGROUND}; color: {TEXT_COLOR};")
        dialog.setFixedSize(400,400)
        layout = QVBoxLayout()
        about_label = BodyLabel("Wallet0n1 –– Simplicity - Security - Privacy\nVersion 1.0.0\nReady for the Business Expo!")
        about_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ok_btn = RoundedButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        layout.addWidget(about_label)
        layout.addWidget(ok_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        dialog.setLayout(layout)
        dialog.exec()

    def fetch_eth_price(self):
        """Fetches and updates the ETH price display."""
        try:
            url = "https://api.coingecko.com/api/v3/simple/price"
            params = {"ids": "ethereum", "vs_currencies": "usd"}
            resp = requests.get(url, params=params, timeout=5)
            resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            data = resp.json()
            price = data["ethereum"]["usd"]
            self.price_label.setText(f"ETH Price: ${price:.2f}")
        except requests.exceptions.RequestException as e: # Specific exception for network issues
            self.price_label.setText("ETH Price: Error")
            print(f"Error fetching ETH price: {e}") # Log the error for debugging

    def animate_screen_transition(self, next_screen): # Unused, kept for potential future screen transitions
        """Animates screen transitions (unused, kept for potential future use)."""
        # First change to the next screen
        self.stack.setCurrentWidget(next_screen)

        # Then apply and start the animation
        opacity_effect = QGraphicsOpacityEffect()
        next_screen.setGraphicsEffect(opacity_effect)
        opacity_effect.setOpacity(0)  # Start fully transparent

        animation = QPropertyAnimation(opacity_effect, b"opacity")
        animation.setDuration(200)
        animation.setStartValue(0)
        animation.setEndValue(1)
        animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def closeEvent(self, event):
        """Handles application close event, ensuring thread pool shutdown."""
        # Ensure thread pool is shutdown gracefully
        self.threadpool.clear()
        self.threadpool.waitForDone()
        event.accept()

    def show_receive_qr_code(self):
        """Displays the receive ETH QR code dialog."""
        if not self.address:
            QMessageBox.warning(self, "Warning", "No wallet address available.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Receive Ethereum")
        dialog.setStyleSheet(f"background-color: {LIGHT_BLUE_BACKGROUND}; color: {TEXT_COLOR};")
        dialog.setFixedSize(400,400)
        layout = QVBoxLayout()
        address_label = BodyLabel(f"Your Ethereum Address:\n{self.address}") # Display address
        address_label.setWordWrap(True)
        address_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_image = generate_qr_code(self.address, scale_factor=2)
        large_qr = QLabel()
        large_qr.setPixmap(QPixmap.fromImage(qr_image).scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        large_qr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        copy_btn = RoundedButton("Copy Address")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.address))
        layout.addWidget(address_label)
        layout.addWidget(large_qr)
        layout.addWidget(copy_btn)
        dialog.setLayout(layout)
        dialog.exec()

    def gotoTransactions(self):
        """Navigates to the transactions screen."""
        self.stack.setCurrentIndex(9)
        self.fetch_transaction_history()

    def fetch_transaction_history(self):
        """Fetches and displays transaction history in the table view."""
        if not self.address:
            QMessageBox.warning(self, "Warning", "No wallet address available to fetch transactions.")
            return

        progress_dialog = QProgressDialog("Fetching Transactions...", "Cancel", 0, 0, self)
        progress_dialog.setCancelButtonText(None)
        progress_dialog.setModal(True)
        progress_dialog.show()
        QApplication.processEvents() # Update UI immediately

        self.history_runnable = TransactionHistoryRunnable(self.address) # Runnable for fetching history
        self.history_runnable.history_updated.connect(self.update_transaction_display)
        self.history_runnable.error_signal.connect(lambda msg: QMessageBox.critical(self, "Transaction History Error", msg)) # Error handling for history
        self.history_runnable.finished.connect(progress_dialog.close) # Close progress dialog when finished
        self.threadpool = QThreadPool.globalInstance()
        self.threadpool.start(self.history_runnable)

    def update_transaction_display(self, formatted_transactions: List[Dict]):
        """Updates the transaction table view with fetched transaction data."""
        if not formatted_transactions:
            QMessageBox.information(self, "Info", "No transactions found for this address.") # Inform user if no transactions
        self.transaction_model.setTransactions(formatted_transactions) # Set data to table model
        # No need for QApplication.processEvents() within this method as table updates are handled by the model


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DashboardApp()
    window.show()
    sys.exit(app.exec())
