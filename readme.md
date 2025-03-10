# Wallet0n1 - Simple & Private Ethereum Wallet

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![PySide6](https://img.shields.io/badge/PySide6-6.x-brightgreen.svg?style=flat-square&logo=qt&logoColor=white)](https://www.pyside.org/)

**Wallet0n1** is a simple and secure desktop Ethereum wallet built with Python and PySide6. Focused on providing a user-friendly experience while prioritizing security and privacy, it allows you to manage your Ethereum assets the way you want.

## Key Features

*   **Wallet Creation:** Generate new Ethereum wallets with seed phrases.
*   **Wallet Import:** Import existing wallets using seed phrases or private keys.
*   **ETH Balance:** Check your Ethereum balance in real-time.
*   **Send ETH:** Easily send Ether (ETH) to other Ethereum addresses.
*   **Receive ETH:** Generate QR codes to receive ETH.
*   **Transaction History:** View your transaction history directly within the app.
*   **PIN Security:** Secure your wallet with a 4-digit PIN code.
*   **Secure Storage:** Utilizes OS-level keychain for secure storage of private keys and sensitive data.
*   **Privacy Focused:**  Designed with privacy in mind, ensuring you have control over your keys and data.
*   **User-Friendly Interface:** Clean and intuitive interface built with PySide6 for a smooth user experience.

## Technologies Used

*   **Python:**  The primary programming language.
*   **PySide6:**  For creating the graphical user interface.
*   **Web3.py:**  For interacting with the Ethereum blockchain.
*   **eth-account:** For Ethereum account management and transaction signing.
*   **mnemonic:** For generating and managing seed phrases.
*   **cryptography:** For encryption and secure key derivation.
*   **keyring:** For secure storage of sensitive data using OS keychains.
*   **qrcode:** For generating QR codes for wallet addresses.
*   **requests:** For fetching ETH price and interacting with Etherscan API.

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/John0n1/Wallet0n1.git
    cd Wallet0n1
    ```

2.  **Install Python Dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate  # On Windows
    pip install -r requirements.txt
    ```

3.  **Run the Wallet:**
    ```bash
    python wallet/main.py
    ```


## Important Notes and Disclaimer

**Security is paramount. Please read carefully:**

*   **Seed Phrase is Key:** Your seed phrase is the ultimate backup for your wallet. **Write it down securely offline and never share it with anyone.** Loss of your seed phrase means loss of access to your funds.
*   **PIN Security is for Convenience:** The 4-digit PIN provides basic security within this application on your device. It is **not** a replacement for securing your seed phrase.
*   **Use at Your Own Risk:** This wallet is provided as is, for educational and personal use.  **Use caution when managing real funds.** The developers are not responsible for any loss of funds due to the use of this software.
*   **API Keys:**  API keys for Infura and Etherscan are currently hardcoded for demonstration purposes. 
*   **Mainnet Only (Currently):** This wallet is currently configured for the Ethereum Mainnet. Network switching is a potential future enhancement.

## Future Enhancements (Roadmap)

*   **Network Switching:** Support for different Ethereum networks (e.g., Goerli, Sepolia).
*   **Token Support:**  Support for viewing and sending ERC-20 tokens.
*   **Transaction Speed/Gas Fee Customization:**  Options to adjust gas fees for transactions.
*   **Improved Transaction History Details:**  More detailed transaction information and filtering.
*   **Fiat Currency Conversion:** Display balances in fiat currencies.
*   **Hardware Wallet Support:** Integration with hardware wallets for enhanced security.

## License

This project is open-source and available under the [MIT License](LICENSE).  See the `LICENSE` file for more details.

---

**Enjoy using Wallet0n1!**

For any questions or feedback, feel free to open an issue in this repository.
