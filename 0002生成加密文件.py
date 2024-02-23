from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os

def derive_key(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt.encode('utf-8'),
        iterations=100000,
        length=length
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt(message, password):
    salt = os.urandom(16)
    key = derive_key(password, salt.decode('latin1'), 32)
    key_bytes = key[:32]

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    message_bytes = message.encode('utf-8')
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()

    # Check if the message is empty or not encrypted
    if message.strip() and len(ciphertext) > 0:
        # Print the encrypted string
        encrypted_string = b64encode(salt + iv + ciphertext).decode('utf-8')
        return encrypted_string
    else:
        return None

def encrypt_even_lines(file_path, password, output_file_path):
    with open(file_path, 'r') as infile:
        lines = infile.readlines()

    encrypted_lines = []
    for i, line in enumerate(lines):
        if i % 2 == 1:
            # Encrypt even lines
            encrypted_line = encrypt(line.strip(), password)
            if encrypted_line:
                encrypted_lines.append(encrypted_line)
        else:
            encrypted_lines.append(line.strip())

    # Save the encrypted even lines to a new file
    with open(output_file_path, 'w') as outfile:
        for encrypted_line in encrypted_lines:
            outfile.write(encrypted_line + '\n')

# Example usage:
input_file_path = 'output.txt'
output_file_path = 'outputen.txt'
password = 'an4dlV9ju1ZM04R_o-2RDwl7fxX-nGZQRHYc5N5OchM='

encrypt_even_lines(input_file_path, password, output_file_path)
