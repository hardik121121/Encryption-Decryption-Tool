import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
from hashlib import sha256

def generate_AES_key(password):
    return sha256(password.encode()).digest()[:32]

def encrypt_AES(key, plaintext):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return b64encode(ciphertext).decode()

def decrypt_AES(key, ciphertext):
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(b64decode(ciphertext)) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return unpadded_data.decode()

def encrypt_decrypt():
    password = password_entry.get()
    input_text = input_entry.get("1.0", "end-1c")

    key = generate_AES_key(password)
    encrypted_text = encrypt_AES(key, input_text)
    decrypted_text = decrypt_AES(key, encrypted_text)

    encrypted_output_label.config(text="Encrypted Text: " + encrypted_text)
    decrypted_output_label.config(text="Decrypted Text: " + decrypted_text)

def clear_text():
    input_entry.delete("1.0", "end")
    password_entry.delete(0, "end")
    encrypted_output_label.config(text="Encrypted Text:")
    decrypted_output_label.config(text="Decrypted Text:")

# GUI setup
root = tk.Tk()
root.title("AES Encryption and Decryption")

input_label = ttk.Label(root, text="Enter Text:")
input_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

input_entry = tk.Text(root, height=5, width=50)
input_entry.grid(row=0, column=1, padx=5, pady=5)

password_label = ttk.Label(root, text="Enter Password:")
password_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

password_entry = ttk.Entry(root, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

encrypt_button = ttk.Button(root, text="Encrypt & Decrypt", command=encrypt_decrypt)
encrypt_button.grid(row=2, column=1, padx=5, pady=5)

clear_button = ttk.Button(root, text="Clear", command=clear_text)
clear_button.grid(row=3, column=1, padx=5, pady=5)

encrypted_output_label = ttk.Label(root, text="Encrypted Text:")
encrypted_output_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="w")

decrypted_output_label = ttk.Label(root, text="Decrypted Text:")
decrypted_output_label.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="w")
''
root.mainloop()