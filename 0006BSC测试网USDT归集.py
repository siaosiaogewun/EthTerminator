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

def derive_key(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt.encode('utf-8'),
        iterations=100000,  # You can adjust the number of iterations based on your security needs
        length=length
    )
    return kdf.derive(password.encode('utf-8'))


def decrypt(ciphertext, password):
    ciphertext_bytes = b64decode(ciphertext)
    salt = ciphertext_bytes[:16]
    iv = ciphertext_bytes[16:32]
    encrypted_message = ciphertext_bytes[32:]

    key = derive_key(password, salt.decode('latin1'), 32)
    key_bytes = key[:32]

    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

password = "an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM="



with open('output.txt', 'r') as file:
    lines = file.readlines()

i = 0
while i < len(lines):
    line1 = lines[i].strip()
    line2 = lines[i + 1].strip()


    decrypted_text = decrypt(line2, password)


    print("开始迭代地址",line1)
    w3 = Web3(Web3.HTTPProvider("https://data-seed-prebsc-1-s1.binance.org:8545/"))
    with open("bscusdtabi.json", "r") as fp:
        erc20_abi = json.loads(fp.read())
        ###查询的合约地址
        TETHER_USD_CA = "0x337610d27c682E347C9cD60BD4b3b107C9d34dDd"
        ##转出的合于地址
        CONTRACT_ADDRESS = '0x337610d27c682E347C9cD60BD4b3b107C9d34dDd'
        ##转出地址
        BURN_ADDRESS = line1
        ##转出地址私钥
        # Replace with your private key
        private_key = decrypted_text
        ##收款低地址
        TO_ADDRESS = '0x8c9bcE7D9D7d5A2614F3BbC70398760c59939046'  # Adjust the to address 
        USDT_CONTRACT = w3.eth.contract(TETHER_USD_CA, abi=erc20_abi)
        #print(dir(USDT_CONTRACT.functions))
        balance=USDT_CONTRACT.functions.balanceOf(BURN_ADDRESS).call()
        #print(balance)
        balancelv = balance/1000000000000000000
        print("账户余额",balancelv)


        if balancelv > 0:
            RPC_URL = 'https://data-seed-prebsc-1-s1.binance.org:8545/'
            if not private_key:
                raise ValueError("Private key not provided.")
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
                'chainId': 11155111,
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
                time.sleep(0.5)  # 暂停0.5秒   
                balance22 = balance2/1000000000000000000
                print("第二次查询账户余额",balance22)

                

        





             # 在这里执行你的自定义操作，例如打印或其他处理
 

    i += 2  # 每次操作两行
     

    










