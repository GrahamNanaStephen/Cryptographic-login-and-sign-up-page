import os
import json
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DB_FILE = "db.json"

# --- Your existing key functions here ---

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)

def pem_to_str(pem_bytes):
    return pem_bytes.decode('utf-8')

def str_to_pem(pem_str):
    return pem_str.encode('utf-8')

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def signup(username):
    db = load_db()
    if username in db:
        messagebox.showerror("Error", "User already exists.")
        return

    private_pem, public_pem = generate_key_pair()
    db[username] = {"public_key": pem_to_str(public_pem)}
    save_db(db)

    os.makedirs("keys", exist_ok=True)
    with open(f"keys/{username}_private.pem", "wb") as f:
        f.write(private_pem)

    messagebox.showinfo("Success", f"User '{username}' registered. Private key saved locally.")

def login(username):
    db = load_db()
    if username not in db:
        messagebox.showerror("Error", "User does not exist.")
        return

    public_pem = str_to_pem(db[username]['public_key'])
    public_key = serialization.load_pem_public_key(public_pem)

    challenge = b"Sign this to prove you own the private key."

    private_key_path = f"keys/{username}_private.pem"
    if not os.path.exists(private_key_path):
        messagebox.showerror("Error", "Private key not found.")
        return

    with open(private_key_path, "rb") as f:
        private_pem = f.read()

    private_key = serialization.load_pem_private_key(private_pem, password=None)

    signature = private_key.sign(
        challenge,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    try:
        public_key.verify(
            signature,
            challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", f"User '{username}' logged in!")
    except:
        messagebox.showerror("Error", "Failed to verify signature.")

# --- GUI Setup ---

def run_gui():
    root = tk.Tk()
    root.title("Crypto Auth")

    tk.Label(root, text="Username:").grid(row=0, column=0, padx=10, pady=10)
    username_entry = tk.Entry(root)
    username_entry.grid(row=0, column=1, padx=10, pady=10)

    def on_signup():
        uname = username_entry.get().strip()
        if uname:
            signup(uname)
        else:
            messagebox.showerror("Error", "Enter a username")

    def on_login():
        uname = username_entry.get().strip()
        if uname:
            login(uname)
        else:
            messagebox.showerror("Error", "Enter a username")

    tk.Button(root, text="Sign Up", command=on_signup).grid(row=1, column=0, padx=10, pady=10)
    tk.Button(root, text="Login", command=on_login).grid(row=1, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    run_gui()
