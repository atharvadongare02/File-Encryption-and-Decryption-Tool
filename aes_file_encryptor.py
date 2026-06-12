import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Generate AES-256 Key from Password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,      # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())


# Encrypt File
def encrypt_file():
    filepath = filedialog.askopenfilename()

    if not filepath:
        return

    password = password_entry.get()

    if not password:
        messagebox.showerror("Error", "Enter Password")
        return

    try:
        with open(filepath, "rb") as file:
            data = file.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)

        key = generate_key(password, salt)

        aesgcm = AESGCM(key)

        encrypted_data = aesgcm.encrypt(
            nonce,
            data,
            None
        )

        output_file = filepath + ".enc"

        with open(output_file, "wb") as file:
            file.write(salt + nonce + encrypted_data)

        messagebox.showinfo(
            "Success",
            f"Encrypted File Saved:\n{output_file}"
        )

    except Exception as e:
        messagebox.showerror("Error", str(e))


# Decrypt File
def decrypt_file():
    filepath = filedialog.askopenfilename()

    if not filepath:
        return

    password = password_entry.get()

    if not password:
        messagebox.showerror("Error", "Enter Password")
        return

    try:
        with open(filepath, "rb") as file:
            file_data = file.read()

        salt = file_data[:16]
        nonce = file_data[16:28]
        encrypted_data = file_data[28:]

        key = generate_key(password, salt)

        aesgcm = AESGCM(key)

        decrypted_data = aesgcm.decrypt(
            nonce,
            encrypted_data,
            None
        )

        output_file = filepath.replace(".enc", "_decrypted")

        with open(output_file, "wb") as file:
            file.write(decrypted_data)

        messagebox.showinfo(
            "Success",
            f"Decrypted File Saved:\n{output_file}"
        )

    except Exception:
        messagebox.showerror(
            "Error",
            "Wrong Password or Corrupted File"
        )


# GUI
root = tk.Tk()
root.title("AES-256 File Encryption Tool")
root.geometry("400x250")

title = tk.Label(
    root,
    text="AES-256 File Encryptor",
    font=("Arial", 16, "bold")
)
title.pack(pady=20)

tk.Label(
    root,
    text="Enter Password"
).pack()

password_entry = tk.Entry(
    root,
    show="*",
    width=30
)
password_entry.pack(pady=10)

encrypt_btn = tk.Button(
    root,
    text="Encrypt File",
    width=20,
    command=encrypt_file
)
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(
    root,
    text="Decrypt File",
    width=20,
    command=decrypt_file
)
decrypt_btn.pack(pady=10)

root.mainloop()