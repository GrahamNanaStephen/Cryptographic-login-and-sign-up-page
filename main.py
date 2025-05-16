# main.py

import json
import os
from auth import generate_key_pair, sign_challenge, verify_signature, create_challenge

# Simulated database file
DB_FILE = "db.json"

# Load or initialize user "database"
def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f)

# Convert PEM bytes to string (JSON safe)
def pem_to_str(pem):
    return pem.decode('utf-8')

def str_to_pem(pem_str):
    return pem_str.encode('utf-8')

# Sign up user
def signup(username):
    
    db = load_db()
    if username in db:
        print("User already exists.")
        return
    private_pem, public_pem = generate_key_pair()
    db[username] = {"public_key": pem_to_str(public_pem)}
    save_db(db)

    os.makedirs("keys", exist_ok=True)

    with open(f"keys/{username}_private.pem", "wb") as f:
        f.write(private_pem)
    print(f"User '{username}' registered. Private key saved to 'keys/{username}_private.pem'")

# Login user
def login(username):
    db = load_db()
    if username not in db:
        print("User not found.")
        return

    challenge = create_challenge()
    with open(f"keys/{username}_private.pem", "rb") as f:
        private_key = f.read()

    signature = sign_challenge(private_key, challenge)
    public_key_pem = str_to_pem(db[username]["public_key"])

    if verify_signature(public_key_pem, challenge, signature):
        print("[+] Login successful!")
    else:
        print("[-] Login failed.")

# Main menu
if __name__ == "__main__":
    if not os.path.exists("keys"):
        os.mkdir("keys")

    while True:
        choice = input("\nChoose an option:\n1. Sign Up\n2. Login\n3. Exit\n> ")
        if choice == "1":
            uname = input("Enter username: ")
            signup(uname)
        elif choice == "2":
            uname = input("Enter username: ")
            login(uname)
        elif choice == "3":
            break
        else:
            print("Invalid choice.")
