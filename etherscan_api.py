import requests
from datetime import datetime
from typing import List, Dict

from wallet.constants import ETHERSCAN_API_KEY

BASE_URL = "https://api.etherscan.io/api"

class EtherscanAPI:
    @staticmethod
    def get_transactions(address: str, page: int = 1, offset: int = 10, api_key=ETHERSCAN_API_KEY) -> List[Dict]:
        """Get transactions for an address with pagination."""
        params = {
            'module': 'account',
            'action': 'txlist',
            'address': address,
            'startblock': 0,
            'endblock': 99999999,
            'page': page,
            'offset': offset,
            'sort': 'desc',
            'apikey': api_key
        }

        response = requests.get(BASE_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == '1':
                return data['result']
            return []
        return []

    @staticmethod
    def format_transaction(tx: Dict) -> Dict:
        """Format transaction data for display."""
        timestamp = datetime.fromtimestamp(int(tx['timeStamp']))
        value_eth = float(tx['value']) / 1e18  # Convert from wei to ETH

        return {
            'hash': tx['hash'],
            'date': timestamp.strftime('%Y-%m-%d %H:%M'),
            'from': tx['from'],
            'to': tx['to'],
            'value': f"{value_eth:.4f} ETH",
            'gas_used': tx['gasUsed'],
            'status': 'Success' if tx['txreceipt_status'] == '1' else 'Failed',
            'direction': 'in' if tx['to'].lower() == tx['from'].lower() else 'out',
            'raw': tx  # Keep raw data for detailed view
        }
