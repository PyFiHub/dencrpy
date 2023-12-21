"""
Simple File Encryption and Decryption App

This script allows users to encrypt and decrypt the contents of a file using the Fernet symmetric key encryption algorithm
with PBKDF2-HMAC-SHA256 key derivation. Users can generate a new encryption key, paste an existing key, set the file name,
and perform encryption or decryption operations. The app provides clear options and messages for user interaction.
"""

import base64
import os
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ENCRYPTION_KEY = ''
NAME_TXT_FILE = ''

def generate_salt():
    """Generate a random salt using the secrets module."""
    return secrets.token_bytes(16)

def generate_key():
    """Generate a new encryption key."""
    return secrets.token_urlsafe(32)

def get_key_from_user():
    """Prompt the user to enter an encryption key."""
    key = input("Enter your encryption key: ")
    return key

def get_file_name_from_user():
    """Prompt the user to enter the file name."""
    file_name = input("Enter the file name (without extension): ")
    return file_name

def show_encryption_key():
    """Show the saved encryption key."""
    global ENCRYPTION_KEY
    if ENCRYPTION_KEY:
        print(f"Saved Encryption Key: {ENCRYPTION_KEY}")
    else:
        print("Encryption key not set.")

def encrypt(password, file_path):
    """Encrypt the contents of a file using Fernet and PBKDF2."""
    global NAME_TXT_FILE

    if not NAME_TXT_FILE:
        print('Error: File name is not set. Set the file name using option 5.')
        return

    try:
        salt = generate_salt()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        with open(file_path, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)

        with open(file_path + '.encrypted', 'wb') as f:
            f.write(salt)
            f.write(encrypted_data)

        print('Encryption Completed')
    except Exception as e:
        print(f'Encryption Failed: {e}')

def decrypt(password, file_path):
    """Decrypt the contents of an encrypted file using Fernet and PBKDF2."""
    global NAME_TXT_FILE

    if not NAME_TXT_FILE:
        print('Error: File name is not set. Set the file name using option 5.')
        return

    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            encrypted_data = f.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)

        decrypted_file_path = file_path.replace('.encrypted', '.decrypted')

        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        print('Decryption Completed')
    except Exception as e:
        print(f'Decryption Failed: {e}')

def main():
    global ENCRYPTION_KEY
    global NAME_TXT_FILE

    print('Choose an option:')
    print('1 - Encrypt a file')
    print('2 - Decrypt a file')
    print('3 - Generate a new encryption key')
    print('4 - Paste an existing encryption key')
    print('5 - Set file name')
    print('6 - Show saved encryption key')
    print('7 - Exit')

    while True:
        action = input()

        if action == '1':
            print('Encrypting...')
            encrypt(ENCRYPTION_KEY, os.path.join(f'{NAME_TXT_FILE}.txt'))
        elif action == '2':
            print('Decrypting...')
            decrypt(ENCRYPTION_KEY, os.path.join(f'{NAME_TXT_FILE}.txt.encrypted'))
        elif action == '3':
            ENCRYPTION_KEY = generate_key()
            print(f'New encryption key generated: {ENCRYPTION_KEY}')
        elif action == '4':
            ENCRYPTION_KEY = get_key_from_user()
            print('Encryption key set successfully.')
        elif action == '5':
            NAME_TXT_FILE = get_file_name_from_user()
            print(f'File name set to: {NAME_TXT_FILE}')
        elif action == '6':
            show_encryption_key()
        elif action == '7':
            print('Exiting...')
            exit()
        else:
            print('Invalid option. Please enter a number between 1 and 7.')

if __name__ == "__main__":
    main()
