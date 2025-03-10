import os

# --- Constants and Configuration ---
# Consider moving API keys to environment variables for better security in a production environment
INFURA_API_KEY = "8e98c3c060a54a668a955e7bc876532f" # ***IMPORTANT: For production, use environment variables!***
ETHERSCAN_API_KEY = "PPEMJHN5UEH77GX2KA16629W1CQPSTYMWV" # ***IMPORTANT: For production, use environment variables!***
INFURA_URL = f"https://mainnet.infura.io/v3/{INFURA_API_KEY}" # Hardcoded to Mainnet - Network switching is a future enhancement

LIGHT_BLUE_BACKGROUND = "#E3F2FD"
PRIMARY_BLUE = "#29B6F6"
ACCENT_BLUE = "#64B5F6"
TEXT_COLOR = "#212121"
TITLE_TEXT_COLOR = "#000000"
BUTTON_RADIUS = "12px"
WIDGET_RADIUS = "6px"
FONT_FAMILY = "Roboto" # Using Roboto font

WALLET_DATA_SERVICE_NAME = "PyWalletData"
WALLET_DATA_ACCOUNT_NAME = "user_wallet"

IMG_FOLDER = "img"  # Specify the image folder path

# --- Custom Exceptions ---
class WalletError(Exception):
    """Base class for wallet related exceptions."""
    pass

class NetworkError(WalletError):
    """Exception raised for network related errors."""
    pass

class EncryptionError(WalletError):
    """Exception raised for encryption/decryption errors."""
    pass

class StorageError(WalletError):
    """Exception raised for secure storage errors."""
    pass

class InvalidInputError(WalletError):
    """Exception raised for invalid user input."""
    pass

class PinVerificationError(WalletError): # Added specific exception for PIN verification
    """Exception raised when PIN verification fails."""
    pass
