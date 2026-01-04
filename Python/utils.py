import tkinter as tk
import pyotp
import time
import pyperclip
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import keyring
import config

def load_otps_from_decrypted(decrypted_otps):
    return [(name.strip(), uri.strip()) for name, uri in decrypted_otps if "otpauth://" in uri]

def clean_uri(uri):
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    label = unquote(parsed.path.split('/')[-1])
    if ':' in label:
        label_issuer, username = label.split(':', 1)
    else:
        label_issuer = username = label
    query_issuer = query.get("issuer", [label_issuer])[0]
    if label_issuer != query_issuer:
        query['issuer'] = [label_issuer]
    parsed = parsed._replace(query=urlencode(query, doseq=True))
    return urlunparse(parsed), label_issuer, username

def copy_and_toast(var, root):
    pyperclip.copy(var.get())
    if config.toast_label: config.toast_label.destroy()
    config.toast_label = tk.Label(root, text="✅ Copied to clipboard", bg="#444", fg="white",
                           font=("Segoe UI", 10), padx=12, pady=6)
    config.toast_label.place(relx=0.5, rely=1.0, anchor='s')
    root.after(1500, config.toast_label.destroy)

def on_mousewheel(event):
    if config.canvas:
        config.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

def save_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    keyring.set_password(config.SERVICE_NAME, config.USERNAME, hashed)

def get_stored_password():
    return keyring.get_password(config.SERVICE_NAME, config.USERNAME)

def decrypt_aes256(ciphertext_b64, key_str):
    key = hashlib.sha256(key_str.encode()).digest()
    raw = base64.urlsafe_b64decode(ciphertext_b64)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()

def encrypt_aes256(plaintext, key_str):
    key = hashlib.sha256(key_str.encode()).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    ciphertext = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode()

def decode_encrypted_file():
    if not config.decrypt_key: return []
    decrypted_otps = []
    try:
        with open(config.ENCODED_FILE, 'r') as infile:
            for line in infile:
                if ',' not in line: continue
                platform, encrypted_url = map(str.strip, line.split(',', 1))
                try: decrypted_otps.append((platform, decrypt_aes256(encrypted_url, config.decrypt_key)))
                except Exception: continue
    except FileNotFoundError: pass
    return decrypted_otps

def bind_enter(root, button):
    root.unbind_all("<Return>")
    root.bind_all("<Return>", lambda event: button.invoke())
