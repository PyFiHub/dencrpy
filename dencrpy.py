import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets


### Encrypt - Decrypt using  PBKDF2-HMAC-SHA256


## Option to create a new encryption_key

#encryption_key = secrets.token_urlsafe(16)
#print(encryption_key)


encryption_key = '5wF15A_QfE-phFd1bDcLwQ' 
name_txt_file = 'example' #name of text file without .txt

## Encrypt

def encrypt(password, file_path):
    # Generate a random salt
    salt = os.urandom(16)

    # Use PBKDF2 to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Read the contents of the file
    with open(file_path, 'rb') as f:
        data = f.read()

    # Encrypt the data using the key
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    # Write the encrypted data and salt to the output file
    with open(file_path + '.encrypted', 'wb') as f:
        f.write(salt)
        f.write(encrypted_data)


## Dencrypt

def decrypt(password, file_path):
    # Read the salt and encrypted data from the file
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        encrypted_data = f.read()

    # Use PBKDF2 to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Decrypt the data using the key
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Write the decrypted data to the output file
    with open(file_path + '.decrypted', 'wb') as f:
        f.write(decrypted_data)

## Simple Caller

print('type number for:')
print('1-encrypt  /  2-decrypt  /  3-exit')
action = input()

if action == '1':
    (print('encrypt'))
    encrypt(encryption_key, f'{name_txt_file}.txt') 
if action == '2':
    (print('decrypt'))
    decrypt(encryption_key, f'{name_txt_file}.txt.encrypted')
if action == '3':
    (print('exit'))
    exit()