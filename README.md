

# Sensor Integration in Embedded Security

## Overview

This project demonstrates the integration of sensor data monitoring and security in an embedded system. The system simulates the collection of temperature and humidity data, encrypts and stores this data securely, processes the data for anomalies, and decrypts it for analysis. Additionally, it includes a feature to send email notifications when specific thresholds are exceeded, enhancing the system's security and responsiveness.

## Features

1. **Data Encryption and Storage:**
   - Utilizes AES encryption in CFB mode to secure sensor data.
   - Derives a 256-bit key using PBKDF2HMAC with SHA-256 and a randomly generated salt.

2. **Sensor Data Simulation:**
   - Simulates temperature and humidity readings using random data generation.

3. **Data Processing:**
   - Computes average temperature and humidity.
   - Identifies anomalies based on configurable thresholds.

4. **Email Notifications:**
   - Sends alerts via email if the average temperature exceeds 25°C.

5. **Data Decryption:**
   - Decrypts the stored encrypted data for review and analysis.

6. **Data Integrity Verification:**
   - Computes and prints a SHA-256 checksum for verifying data integrity.

## Requirements

- Python 3.x
- `cryptography` library for encryption and decryption
- `numpy` for data processing
- `smtplib` and `ssl` for sending email notifications

## Configuration

The project requires a configuration file named `config.json` with the following structure:

```json
{
    "password": "Hello_aljo",
    "email_password": "ndfs kqyw zekc rbqj"
}
```

- **password:** The password used to derive the encryption/decryption key.
- **email_password:** The password used for sending email notifications.

## Files

- **config.json:** Contains the password for encryption/decryption and email credentials.
- **encrypted_data.txt:** Stores the encrypted sensor data along with the salt.

## Usage

### Data Encryption and Processing

1. **Setup:**
   - Ensure that `config.json` is correctly configured with the necessary credentials.

2. **Running the Script:**
   - Start the script to begin data collection, encryption, and processing:

     ```sh
     python your_script.py
     ```

3. **Output:**
   - The encrypted data is saved in `encrypted_data.txt`.
   - The script prints the encrypted data and computed checksums.
   - An email notification is sent if the average temperature exceeds 25°C.

### Data Decryption

1. **Setup:**
   - Ensure the `config.json` file contains the correct password for decryption.
   - Ensure `encrypted_data.txt` is present and contains the encrypted data.

2. **Running the Decryption Script:**
   - Run the decryption script to read and decrypt the stored data:

     ```sh
     python decrypt_script.py
     ```

3. **Output:**
   - The script prints the decrypted humidity and temperature values.

## Decryption Process

1. **Load Configuration:**
   - The script reads the password from `config.json`.

2. **Reading Encrypted Data:**
   - Extracts the salt from `encrypted_data.txt`.
   - Derives the AES key using PBKDF2HMAC with the extracted salt and the provided password.

3. **Decrypt Data:**
   - Decrypts the data entries using the derived key and corresponding IV (initialization vector).

## Notes

- Ensure the password in `config.json` matches the one used during encryption.
- The salt and encrypted data format must be consistent with the encryption process.

## License

This project is open-source and available under the MIT License.

## Contact

For any inquiries or support, please contact aljojose26@gmail.com
---

This README combines the setup, usage, and details of the entire system including data encryption, processing, and decryption functionalities. 
