import tkinter as tk
from tkinter import filedialog
import os
import time
import hashlib
import config
import utils
import aes

def add_credential(platform, qr_path, key):
    if not os.path.exists(qr_path):
        return False, "File not found"
    
    with open(qr_path, 'rb') as f:
        original_data = f.read()
    
    uri = utils.read_qr_from_bytes(original_data)
    if not uri:
        return False, "Could not read QR code from image"
    
    crypto = aes.Crypto(key)
    qr_folder = os.path.join(config.APP_FOLDER, "qrs")
    os.makedirs(qr_folder, exist_ok=True)
    
    enc_img_data = crypto.encrypt_bytes(original_data)
    safe_name = hashlib.md5(f"{platform}{time.time()}".encode()).hexdigest()
    enc_img_path = os.path.join(qr_folder, f"{safe_name}.enc")
    
    with open(enc_img_path, 'wb') as f:
        f.write(enc_img_data)
    
    line_to_encrypt = f"{platform}: {enc_img_path}"
    encrypted_line = crypto.encrypt_aes(line_to_encrypt)
    
    with open(config.ENCODED_FILE, 'a') as f:
        f.write(encrypted_line + "\n")
    
    return True, "Credential added successfully"

def edit_credentials_popup(parent, root, build_main_ui_callback):
    parent.resizable(False, False)
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both", padx=20, pady=20)
    
    tk.Label(frame, text="Add New Credential", font=("Segoe UI", 12, "bold"), bg="#1e1e1e", fg="white").pack(pady=(0, 15))
    
    tk.Label(frame, text="Platform Name:", bg="#1e1e1e", fg="white").pack(anchor="w")
    platform_entry = tk.Entry(frame, font=("Segoe UI", 10))
    platform_entry.pack(fill="x", pady=(0, 10))
    
    tk.Label(frame, text="QR Code Image:", bg="#1e1e1e", fg="white").pack(anchor="w")
    path_frame = tk.Frame(frame, bg="#1e1e1e")
    path_frame.pack(fill="x")
    
    path_entry = tk.Entry(path_frame, font=("Segoe UI", 10))
    path_entry.pack(side="left", fill="x", expand=True)
    
    def browse_file():
        filename = filedialog.askopenfilename(title="Select QR Code", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
        if filename:
            path_entry.delete(0, tk.END)
            path_entry.insert(0, filename)
            
    tk.Button(path_frame, text="Browse", command=browse_file, bg="#444", fg="white", relief="flat").pack(side="right", padx=(5, 0))
    
    error_label = tk.Label(frame, text="", bg="#1e1e1e", fg="red", font=("Segoe UI", 9))
    error_label.pack(pady=10)
    
    def save_cred():
        platform = platform_entry.get().strip()
        path = path_entry.get().strip()
        if not platform or not path:
            error_label.config(text="Please fill all fields")
            return
        
        success, msg = add_credential(platform, path, config.decrypt_key)
        if success:
            parent.destroy()
            new_entries = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
            build_main_ui_callback(root, new_entries)
        else:
            error_label.config(text=msg)
            
    tk.Button(frame, text="Save Credential", command=save_cred, bg="#444", fg="white", relief="flat", font=("Segoe UI", 10, "bold")).pack(pady=10)
