import tkinter as tk
import hashlib
import os
import config
import utils
import aes

def reencrypt_all_data(old_key, new_key):
    if not os.path.exists(config.ENCODED_FILE):
        return True
    
    old_crypto = aes.Crypto(old_key)
    new_crypto = aes.Crypto(new_key)
    new_lines = []
    
    try:
        with open(config.ENCODED_FILE, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line: continue
            
            decrypted_line = old_crypto.decrypt_aes(line)
            if ': ' not in decrypted_line: continue
            platform, enc_img_path = decrypted_line.split(': ', 1)
            
            if os.path.exists(enc_img_path):
                with open(enc_img_path, 'rb') as img_f:
                    old_enc_data = img_f.read()
                
                raw_img_data = old_crypto.decrypt_bytes(old_enc_data)
                new_enc_data = new_crypto.encrypt_bytes(raw_img_data)
                
                with open(enc_img_path, 'wb') as img_f:
                    img_f.write(new_enc_data)
            
            new_line = new_crypto.encrypt_aes(f"{platform}: {enc_img_path}")
            new_lines.append(new_line)
            
        with open(config.ENCODED_FILE, 'w') as f:
            for nl in new_lines:
                f.write(nl + "\n")
        return True
    except Exception as e:
        print(f"Re-encryption failed: {e}")
        return False

def reset_password_popup(parent, root):
    parent.resizable(False, False)
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")

    def create_entry(label_text):
        tk.Label(frame, text=label_text, bg="#1e1e1e", fg="white", font=("Segoe UI", 12, "bold")).pack(pady=(15, 5))
        entry = tk.Entry(frame, show="*", font=("Segoe UI", 12), justify="center", width=25)
        entry.pack(ipady=3)
        return entry

    current_entry = create_entry("Enter current password:")
    current_entry.focus_set()
    new_entry = create_entry("New password:")
    confirm_entry = create_entry("Confirm new password:")

    error_label = tk.Label(frame, text="", bg="#1e1e1e", fg="red", font=("Segoe UI", 10))
    error_label.pack(pady=(15, 0))

    def perform_reset():
        stored_hash = utils.get_stored_password()
        current_pwd = current_entry.get()
        current_hash = hashlib.sha256(current_pwd.encode()).hexdigest()
        if current_hash != stored_hash:
            error_label.config(text="Incorrect current password")
        elif new_entry.get() != confirm_entry.get():
            error_label.config(text="New passwords do not match")
        elif len(new_entry.get()) < 4:
            error_label.config(text="Password too short (min 4 chars)")
        else:
            new_pwd = new_entry.get()
            if reencrypt_all_data(current_pwd, new_pwd):
                utils.save_password(new_pwd)
                config.decrypt_key = new_pwd
                parent.destroy()
            else:
                error_label.config(text="Failed to re-encrypt data")

    reset_btn = tk.Button(frame, text="Reset Password", command=perform_reset,
                          font=("Segoe UI", 12, "bold"), bg="#444", fg="white", 
                          relief="flat", activebackground="#666", padx=20, pady=5)
    reset_btn.pack(pady=20)
    utils.bind_enter(root, reset_btn)
