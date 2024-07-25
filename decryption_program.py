import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def decrypt_data(encrypted_data, key):
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:16]
    encrypted_data_bytes = encrypted_data_bytes[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data_bytes) + decryptor.finalize()
    return decrypted_data.decode('utf-8')

def main():
    with open('config.json') as config_file:
        config = json.load(config_file)

    password = config['password'].encode()
    salt = None
    encrypted_data = []

    with open('encrypted_data.txt', 'r') as file:
        lines = file.readlines()
        if lines:
            # Retrieve salt from the first line
            salt = base64.b64decode(lines[0].strip().split(',')[2])

            # Derive the key from the password and salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password)

            for line in lines:
                encrypted_humidity, encrypted_temperature, _ = line.strip().split(',')
                decrypted_humidity = decrypt_data(encrypted_humidity, key)
                decrypted_temperature = decrypt_data(encrypted_temperature, key)
                print(f"Decrypted Humidity: {decrypted_humidity}")
                print(f"Decrypted Temperature: {decrypted_temperature}")

if __name__ == "__main__":
    main()
