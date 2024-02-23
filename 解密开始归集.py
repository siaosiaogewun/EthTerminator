from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os
from web3 import Web3
from web3.middleware import geth_poa_middleware
import json


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


    #print("hello")
    w3 = Web3(Web3.HTTPProvider("https://sepolia.infura.io/v3/04b7923be53e4534b0c97d11b529085d"))
    with open("abi.json", "r") as fp:
        erc20_abi = json.loads(fp.read())
        ###查询的合约地址
        TETHER_USD_CA = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
        ##转出的合于地址
        CONTRACT_ADDRESS = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'
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
        balancelv = balance/1000000
        print("账户余额",balancelv)
        # Constants for the RPC URL and contract details
        RPC_URL = 'https://sepolia.infura.io/v3/04b7923be53e4534b0c97d11b529085d'
        # Check if the private key is provided
        if not private_key:
            raise ValueError("Private key not provided.")
        # Create a Web3 instance connected to the specified RPC URL
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        # Inject PoA middleware for networks using Proof of Authority consensus
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        # Check for connection to the Ethereum network
        if not w3.isConnected():
            raise ConnectionError("Failed to connect to HTTPProvider")
        # Load the contract ABI from a file
        with open('abi.json') as abi_file:
            contract_abi = json.load(abi_file)
            # Create a contract object
            contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)
            # Define transaction details
            token_amount = w3.toWei(1, 'ether')  # Adjust the amount as needed
            token_amount=balance
            # Get the nonce for the transaction
            nonce = w3.eth.getTransactionCount(w3.eth.account.privateKeyToAccount(private_key).address)
            # Build the transaction
            transaction = contract.functions.transfer(TO_ADDRESS, token_amount).buildTransaction({
                'chainId': 11155111,
                'gas': 2000000,  # Adjust the gas limit as needed
                'nonce': nonce,
                })
            # Sign the transaction with the private key
            signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
            # Attempt to send the transaction
            try:
                tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
                print(f"Transaction sent! Hash: {tx_hash.hex()}")
            except Exception as e:
                print(f"Error sending transaction: {e}")
                
                
                
                ##能成功转账，只是小狐狸同步有点慢
                print(f"Decrypted: {decrypted_text}")

             # 在这里执行你的自定义操作，例如打印或其他处理
    print("Custom operation for lines {} and {}:".format(i + 1, i + 2))
    print(line1)
    print(line2)
    print()

    i += 2  # 每次操作两行

    










