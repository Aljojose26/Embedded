import os
import numpy as np
import time
import random
import base64
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


with open('config.json') as config_file:
    config = json.load(config_file)

password = config['password'].encode() 

# Derive a 256-bit (32-byte) key from the password
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 32 bytes = 256 bits
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def read_sensor():
    temperature = random.uniform(20, 30)
    humidity = random.uniform(40, 60)
    return humidity, temperature

def process_data(data):
    temperatures = np.array([entry[1] for entry in data])
    humidities = np.array([entry[0] for entry in data])
    avg_temp = np.mean(temperatures)
    avg_humid = np.mean(humidities)
    print(f"Average Temperature: {avg_temp:.2f} C")
    print(f"Average Humidity: {avg_humid:.2f} %")

    temp_anomalies = temperatures[(temperatures > avg_temp + 2) | (temperatures < avg_temp - 2)]
    humid_anomalies = humidities[(humidities > avg_humid + 10) | (humidities < avg_humid - 10)]
    print(f"Temperature Anomalies: {temp_anomalies}")
    print(f"Humidity Anomalies: {humid_anomalies}")

    if avg_temp > 25:
        send_email_notification(avg_temp)

def send_email_notification(temperature):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import ssl

    sender_email = "aljojose26@gmail.com"
    receiver_email = "aljojose26@gmail.com"
    email_password = config['email_password']

    subject = "Temperature Alert"
    body = f"The average room temperature is too high: {temperature:.2f} C. Please increase the cooling in the air conditioning."

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(sender_email, email_password)
            server.send_message(msg)
            print("Notification email sent.")
    except Exception as e:
        print(f"Failed to send email: {e}")

def calculate_checksum(data):
    data_str = ''.join(str(entry) for entry in data)
    checksum = hashlib.sha256(data_str.encode()).hexdigest()
    return checksum

def save_encrypted_data(encrypted_humidity, encrypted_temperature):
    with open('encrypted_data.txt', 'a') as file:
        file.write(f"{encrypted_humidity},{encrypted_temperature},{base64.b64encode(salt).decode('utf-8')}\n")

if __name__ == "__main__":
    data = []
    try:
        while True:
            humidity, temperature = read_sensor()
            encrypted_humidity = encrypt_data(f"{humidity:.2f}", key)
            encrypted_temperature = encrypt_data(f"{temperature:.2f}", key)
            print(f"Encrypted Humidity: {encrypted_humidity}")
            print(f"Encrypted Temperature: {encrypted_temperature}")
            
            # Save encrypted data to file
            save_encrypted_data(encrypted_humidity, encrypted_temperature)
            
            data.append((humidity, temperature))
            checksum = calculate_checksum(data)
            print(f"Data checksum: {checksum}")
            if len(data) > 10:
                process_data(data)
                data = []
            time.sleep(2)
    except KeyboardInterrupt:
        print("Program terminated")
