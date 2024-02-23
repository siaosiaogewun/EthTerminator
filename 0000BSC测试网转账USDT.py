import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os
from web3 import Web3
from web3.middleware import geth_poa_middleware
import json
import time 
sys.stdout.reconfigure(encoding='utf-8')

w3 = Web3(Web3.HTTPProvider("https://data-seed-prebsc-1-s1.binance.org:8545/"))
with open("bscusdtabi.json", "r") as fp:
        erc20_abi = json.loads(fp.read())
        ###查询的合约地址
        TETHER_USD_CA = "0x337610d27c682E347C9cD60BD4b3b107C9d34dDd"
        ##转出的合于地址
        CONTRACT_ADDRESS = '0x337610d27c682E347C9cD60BD4b3b107C9d34dDd'
        ##转出地址
        BURN_ADDRESS = "0x6E6714eB0D06bbCc6653D77E4334a777C898862a"
        ##转出地址私钥
        # Replace with your private key
        private_key = "3d7d5eb010c2f405be59fd8c3feabf7a35c963df553c5a6b24fec09c6ee10ca0"
        ##收款低地址
        TO_ADDRESS = '0x8c9bcE7D9D7d5A2614F3BbC70398760c59939046'  # Adjust the to address 
        USDT_CONTRACT = w3.eth.contract(TETHER_USD_CA, abi=erc20_abi)
        #print(dir(USDT_CONTRACT.functions))
        balance=USDT_CONTRACT.functions.balanceOf(BURN_ADDRESS).call()
        #print(balance)
        balancelv = balance/1000000000000000000
        print("账户余额",balancelv)
        RPC_URL = 'https://data-seed-prebsc-1-s1.binance.org:8545/'
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        if not w3.isConnected():
            raise ConnectionError("Failed to connect to HTTPProvider")
        with open('bscusdtabi.json') as abi_file:
                contract_abi = json.load(abi_file)
                contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
                token_amount = w3.toWei(balancelv, 'ether')  
                nonce = w3.eth.getTransactionCount(w3.eth.account.privateKeyToAccount(private_key).address)
                transaction = contract.functions.transfer(TO_ADDRESS, token_amount).buildTransaction({
                'chainId': 97,
                'gas': 2000000,  
                'nonce': nonce,
                })
                signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
                try:
                    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
                    print(f"Transaction sent! Hash: {tx_hash.hex()}")
                except Exception as e:
                    print(f"Error sending transaction: {e}")
                balance2=USDT_CONTRACT.functions.balanceOf(BURN_ADDRESS).call()
                balance22 = balance2/1000000
                print("第二次查询账户余额",balance22)