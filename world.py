from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode
import os
import base64

import codecs

def convert_hex_to_binary(hex_string):
    return codecs.decode(hex_string, 'hex')

# 提供的数据
data_line = "-214cc6fcd28c9e29c0d9dd5d4120c8da-7e669eaad5e2a9d328c92981989cb52ebc3b716b6b9d45971e50b845ec13a5975dc75ac4cc21d3c5792914f3d13b9ff2c59465343d4690d8a1ac8f414d1675ab8aa9d8da890f71dcde8c3d2d4769b539"

# 分割字符串
parts = data_line.split('-')
iv_hex = parts[1]
encrypted_private_key_hex = parts[2]

# 将 IV 和加密后的私钥转换为原始二进制数据
iv_binary = convert_hex_to_binary(iv_hex)
encrypted_private_key_binary = convert_hex_to_binary(encrypted_private_key_hex)

print(f"IV (Binary): {iv_binary}")
print(f"Encrypted Private Key (Binary): {encrypted_private_key_binary}")





def decrypt(encoded_ivv, encoded_textv):    

    key = b"an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM="[:32]  # 使用256位密钥

    # 使用base64进行解码
    

    encoded_ivv = bytes.fromhex(encoded_ivv)

    print("还原后的iv:", encoded_ivv)

    iv = encoded_ivv



    
   
    # 使用AES算法和CFB模式创建Cipher对象
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # 创建解密器
    decryptor = cipher.decryptor()
    
    # 解密文本
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    
    return decrypted_text.decode('utf-8')


iv = os.urandom(16)
encoded_ivv = "889b579fbcee2177df04d7da40ccff33"
encoded_textv = "0422ce64b90127249aaeefa676efa712e0325cdcfac82833ed23d90329453b09774190accc1ac815e9b7b85e9549f77c6e87da1fb7e2c746e39b46ab8f320ec927cd0c4586304bdb6b4a9c843e234242"
encrypted_text = b64decode(encoded_textv.encode('utf-8'))

# 解密
decrypted_text = decrypt(encoded_ivv, encoded_textv)

print(f"解密后: {decrypted_text}")
