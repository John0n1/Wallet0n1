
from typing import Tuple

from web3 import Web3
from eth_account import Account
from mnemonic import Mnemonic
import requests

from wallet.constants import INFURA_URL, NetworkError, WalletError, InvalidInputError

Account.enable_unaudited_hdwallet_features()

# --- Blockchain Interaction Functions ---
def get_eth_balance(private_key: str) -> str:
    """Fetches the ETH balance for a given private key."""
    if not isinstance(private_key, str) or not private_key: # Input validation
        raise InvalidInputError("Private key must be a non-empty string.")
    try:
        account = Account.from_key(private_key)
        w3 = Web3(Web3.HTTPProvider(INFURA_URL))
        if not w3.is_connected():
            raise NetworkError("Failed to connect to Infura. Please check your internet connection.") # More specific error
        balance_wei = w3.eth.get_balance(account.address)
        balance_eth = w3.from_wei(balance_wei, 'ether')
        return f"{balance_eth:.4f} ETH"
    except NetworkError as e:
        raise e
    except requests.exceptions.RequestException as e: # Specific exception for network issues
        raise NetworkError(f"Network request failed: {e}. Please check your internet connection.") from e
    except Exception as e:
        raise NetworkError(f"Error fetching balance: {e}") from e

def get_wallet_address(private_key: str) -> str:
    """Gets the Ethereum address from a private key."""
    if not isinstance(private_key, str) or not private_key: # Input validation
        raise InvalidInputError("Private key must be a non-empty string.")
    try:
        account = Account.from_key(private_key)
        return account.address
    except Exception as e:
        raise WalletError(f"Error getting wallet address: {e}") from e

def create_new_wallet() -> Tuple[str, str, str]: # Type hinting with Tuple
    """Creates a new Ethereum wallet and returns private key, info, and mnemonic phrase."""
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)
    try:
        account = Account.from_mnemonic(mnemonic_phrase)
    except Exception as e:
        raise WalletError(f"Error creating account from mnemonic: {e}") from e
    private_key = account.key.hex()
    address = account.address
    wallet_info = f"New wallet created:\nAddress: {address}\nPrivate Key: {private_key}\nSeed Phrase: {mnemonic_phrase}" # Consider removing private key from info for security in logs
    return private_key, wallet_info, mnemonic_phrase

def send_eth_transaction(private_key, recipient_address, amount_eth):
    """Sends an ETH transaction."""
    if not Web3.is_address(recipient_address): # Address format validation before sending
        raise InvalidInputError("Invalid recipient address format in transaction.")
    if not isinstance(amount_eth, float) or amount_eth <= 0: # Amount value validation before sending
        raise InvalidInputError("Invalid transaction amount.")

    w3 = Web3(Web3.HTTPProvider(INFURA_URL))
    if not w3.is_connected():
        raise NetworkError("Failed to connect to Infura.")

    account = Account.from_key(private_key)
    nonce = w3.eth.get_transaction_count(account.address)
    gas_price = w3.eth.gas_price

    try:
        gas_estimate = w3.eth.estimate_gas({
            'to': recipient_address,
            'value': w3.to_wei(amount_eth, 'ether'),
            'from': account.address
        })
        gas_limit = gas_estimate + 2000 # Added buffer to gas limit
    except Exception as gas_err:
        print(f"Gas estimation failed: {gas_err}. Using default gas limit.") # Log gas estimation failure
        gas_limit = 21000 # Fallback gas limit

    amount_wei = w3.to_wei(amount_eth, 'ether')

    transaction = {
        'nonce': nonce,
        'gasPrice': gas_price,
        'gas': gas_limit,
        'to': recipient_address,
        'value': amount_wei,
        'data': b'',
        'chainId': 1 # Hardcoded to Mainnet - Network switching is a future enhancement
    }

    try:
        signed_txn = account.sign_transaction(transaction)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return tx_hash.hex()
    except ValueError as e: # Catch specific ValueError for transaction parameters
        raise InvalidInputError(f"Invalid transaction parameters: {e}") from e
    except Exception as e: # Catch general exceptions during transaction send
        raise NetworkError(f"Transaction failed: {e}") from e
