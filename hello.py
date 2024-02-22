from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def decrypt_private_key(encrypted_private_key, iv, decryption_key):
    encrypted_private_key = base64.b64decode(encrypted_private_key)
    iv = bytes.fromhex(iv)

    cipher = Cipher(algorithms.AES(decryption_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_private_key = decryptor.update(encrypted_private_key) + decryptor.finalize()
    return decrypted_private_key.decode('utf-8')

def decrypt_encrypted_string(encrypted_string, decryption_key):
    try:
        address, iv, encrypted_private_key = encrypted_string.split('-')
        decrypted_private_key = decrypt_private_key(encrypted_private_key, iv, decryption_key)
        return f"Address: {address}\nDecrypted Private Key: {decrypted_private_key}"
    except Exception as e:
        return f"Error decrypting string: {e}"

# Provide the correct base64-encoded decryption key
decryption_key_base64 = 'an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM='
decryption_key = base64.b64decode(decryption_key_base64)

# Check if the key size is 32 bytes
if len(decryption_key) != 32:
    raise ValueError("Invalid key size. The key should be 32 bytes.")

encrypted_string = "-214cc6fcd28c9e29c0d9dd5d4120c8da-7e669eaad5e2a9d328c92981989cb52ebc3b716b6b9d45971e50b845ec13a5975dc75ac4cc21d3c5792914f3d13b9ff2c59465343d4690d8a1ac8f414d1675ab8aa9d8da890f71dcde8c3d2d4769b539"
result = decrypt_encrypted_string(encrypted_string, decryption_key)

print(result)
