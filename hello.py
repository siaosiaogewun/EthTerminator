import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

decryption_key_base64 = 'an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM='
decryption_key = base64.b64decode(decryption_key_base64)

def decrypt_data(address, iv, encrypted_data):
    # Create cipher object and decrypt the text
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    return address, decrypted_text.decode('utf-8')

# Assign values to address, iv, and encrypted_data
address = "0x4fBC35B68FE36f1510BB40B548BFb67366c0c250"
iv_base64 = "889b579fbcee2177df04d7da40ccff33"
encrypted_data_base64 = "0422ce64b90127249aaeefa676efa712e0325cdcfac82833ed23d90329453b09774190accc1ac815e9b7b85e9549f77c6e87da1fb7e2c746e39b46ab8f320ec927cd0c4586304bdb6b4a9c843e234242"

# Decode base64 strings to bytes
iv = base64.b64decode(iv_base64)
encrypted_data = base64.b64decode(encrypted_data_base64)

# Decrypt the data
address, decrypted_text = decrypt_data(address, iv, encrypted_data)

# Print the result
print(f"Address: {address}\nDecrypted Private Key: {decrypted_text}")
