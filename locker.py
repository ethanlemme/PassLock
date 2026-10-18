from getpass import getpass
import json
import argparse
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command", required=True)

create = subparsers.add_parser("create")
create.add_argument("filename")

list = subparsers.add_parser("list")
list.add_argument("filename")

view = subparsers.add_parser("view")
view.add_argument("filename")
view.add_argument("site")

add = subparsers.add_parser("add")
add.add_argument("filename")
add.add_argument("site")

def generate_key(salt, password):

    password_bytes = password.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )

    raw_key = kdf.derive(password_bytes)
    key = base64.urlsafe_b64encode(raw_key)
    return key

def encrypt_dictionary(salt, data, password):
    key = generate_key(salt, password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_dictionary(salt, encrypted_data, password):
    key = generate_key(salt, password)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    return decrypted_data.decode()

def write_file(filename, encrypted_data):
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def read_file(filename):
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    return encrypted_data

def create_vault(filename, password):
    salt = os.urandom(16)
    starter_data = json.dumps({})
    encrypted_data = encrypt_dictionary(salt, starter_data, password)
    with open(filename, "wb") as file:
        file.write(salt + encrypted_data)

def load_vault(filename, password):
    with open(filename, "rb") as file:
        blob = file.read()
        salt = blob[:16]
        encrypted_data = blob[16:]
    decrypted_data = decrypt_dictionary(salt, encrypted_data, password)
    data = json.loads(decrypted_data)
    return data

def save_vault(filename, password, data):
    with open (filename, "rb") as file:
        blob = file.read()
        salt = blob[:16]
        encrypted_data = blob[16:]
    decrypt_dictionary(salt, encrypted_data, password)
    encrypted_data = encrypt_dictionary(salt, json.dumps(data), password)
    with open (filename, "wb") as file:
        file.write(salt + encrypted_data)

args = parser.parse_args()
if args.command == "create":
    password = getpass("Enter your password: ")
    create_vault(args.filename, password)
elif args.command == "list":
    password = getpass("Enter your password: ")
    data = load_vault(args.filename, password)
    for site in data:
        print("\n"+site)
elif args.command == "view":
    password = getpass("Enter your password: ")
    data = load_vault(args.filename, password)
    for site, entry in data.items():
        print(f"Site: {site}")
        print(f"    Username: {entry['username']}")
        print(f"    Password: {entry['password']}")
elif args.command == "add":
    password = getpass("Enter your password: ")
    load_vault(args.filename, password)
    username = input("Username: ")
    site_password = getpass("Password: ")
    data = {args.site:{"username": username, "password": site_password}}
    save_vault(args.filename, password, data)