from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os

def derive_key(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt.encode('utf-8'),
        iterations=100000,  # You can adjust the number of iterations based on your security needs
        length=length
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt(message, password):
    salt = os.urandom(16)  # Generate a random salt for key derivation
    key = derive_key(password, salt.decode('latin1'), 32)  # 32 bytes for AES-256
    key_bytes = key[:32]

    iv = os.urandom(16)  # Generate a random initialization vector

    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    message_bytes = message.encode('utf-8')
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
    return b64encode(salt + iv + ciphertext).decode('utf-8')

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

# Example usage:
password = "an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM="
message = "Hello, AES!"

encrypted_text = encrypt(message, password)
print(f"Encrypted: {encrypted_text}")

decrypted_text = decrypt(encrypted_text, password)
print(f"Decrypted: {decrypted_text}")
