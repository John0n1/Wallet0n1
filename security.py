
import hashlib
import secrets
import json
import base64
from typing import Tuple, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from wallet.constants import InvalidInputError, EncryptionError, StorageError, PinVerificationError
import keyring
import keyring.backends.SecretService
keyring.set_keyring(keyring.backends.SecretService.Keyring())


def derive_fernet_key_from_pin(pin: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]: # Type hinting with Tuple
    """Derives a Fernet encryption key from a user PIN using PBKDF2HMAC."""
    if not isinstance(pin, str): # Input validation for PIN type
        raise InvalidInputError("PIN must be a string.")
    if len(pin) != 4 or not pin.isdigit(): # PIN format validation (4 digits)
        raise InvalidInputError("PIN must be a 4-digit number.")

    if salt is None:
        salt = secrets.token_bytes(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
    return key, salt

def encrypt_data(data: str, encryption_key: bytes) -> str:
    """Encrypts data using Fernet encryption."""
    if not isinstance(data, str):
        raise ValueError("Data to encrypt must be a string.")
    if not isinstance(encryption_key, bytes):
        raise ValueError("Encryption key must be bytes.")
    try:
        f = Fernet(encryption_key)
        encrypted_data_bytes = f.encrypt(data.encode())
        return encrypted_data_bytes.decode()
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}") from e

def decrypt_data(encrypted_data: str, encryption_key: bytes) -> str:
    """Decrypts data using Fernet decryption."""
    if not isinstance(encrypted_data, str):
        raise ValueError("Data to decrypt must be a string.")
    if not isinstance(encryption_key, bytes):
        raise ValueError("Decryption key must be bytes.")
    try:
        f = Fernet(encryption_key)
        decrypted_data_bytes = f.decrypt(encrypted_data.encode())
        return decrypted_data_bytes.decode()
    except Exception as e:
        raise EncryptionError(f"Decryption failed: {e}") from e

def hash_pin(pin: str) -> str:
    """Hashes a PIN using SHA256."""
    if not isinstance(pin, str):
        raise ValueError("PIN must be a string.")
    return hashlib.sha256(pin.encode()).hexdigest()

def verify_pin_hash(entered_pin: str, stored_pin_hash: str) -> bool: # Function to verify PIN against stored hash
    """Verifies if the entered PIN matches the stored PIN hash."""
    if not isinstance(entered_pin, str) or not isinstance(stored_pin_hash, str):
        raise ValueError("PINs must be strings.")
    return hash_pin(entered_pin) == stored_pin_hash


class SecureStorageManager:
    """Manages secure storage of wallet data using OS-specific keychains."""

    def __init__(self, service_name: str, account_name: str):
        self.service_name = service_name
        self.account_name = account_name
        self.keyring_instance = keyring

    def save_wallet_data(self, pin_hash: str, encrypted_pk: str, encrypted_seed_phrase: Optional[str], salt: bytes, address: str): # Type hinting
        """Saves wallet data to secure storage."""
        if not all(isinstance(arg, str) for arg in [pin_hash, encrypted_pk, address]) or not isinstance(salt, bytes): # Input validation
            raise ValueError("Invalid data types for save_wallet_data.")
        try:
            data_dict = {
                "pin_hash": pin_hash,
                "encrypted_pk": encrypted_pk,
                "encrypted_seed_phrase": encrypted_seed_phrase,
                "salt": base64.b64encode(salt).decode('utf-8'),
                "address": address
            }
            data_json = json.dumps(data_dict)
            self.keyring_instance.set_password(self.service_name, self.account_name, data_json)
        except Exception as e:
            raise StorageError(f"Failed to save wallet data to secure storage: {e}") from e

    def load_wallet_data(self):
        """Loads wallet data from secure storage."""
        try:
            data_json = self.keyring_instance.get_password(self.service_name, self.account_name)
            if data_json:
                data_dict = json.loads(data_json)
                if not isinstance(data_dict, dict) or not all(key in data_dict for key in ["pin_hash", "encrypted_pk", "salt", "address"]): # Data integrity check
                    raise StorageError("Corrupted wallet data found in storage.")
                data_dict["salt"] = base64.b64decode(data_dict["salt"].encode('utf-8'))
                return data_dict
            return None
        except Exception as e:
            raise StorageError(f"Failed to load wallet data from secure storage: {e}") from e

    def delete_wallet_data(self):
        """Deletes wallet data from secure storage."""
        try:
            self.keyring_instance.delete_password(self.service_name, self.account_name)
        except keyring.errors.PasswordDeleteError:
            pass # It's okay if the password doesn't exist to delete
        except Exception as e:
            raise StorageError(f"Failed to delete wallet data from secure storage: {e}") from e

    def wallet_data_exists(self):
        """Checks if wallet data exists in secure storage."""
        try:
            return self.keyring_instance.get_password(self.service_name, self.account_name) is not None
        except Exception as e:
            raise StorageError(f"Failed to check if wallet data exists in secure storage: {e}") from e
