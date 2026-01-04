import os
import csv
from tkinter import messagebox
import config
import utils

def export_to_csv():
    otps = utils.decode_encrypted_file()
    if not otps:
        return False, "No data to export"
    
    try:
        desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
        filepath = os.path.join(desktop, "TOTP_Backup.csv")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Platform", "TOTP URL"])
            for platform, uri, _ in otps:
                writer.writerow([platform, uri])
                
        return True, f"Exported to {filepath}"
    except Exception as e:
        return False, str(e)

def handle_download():
    success, msg = export_to_csv()
    if success:
        messagebox.showinfo("Export Successful", msg)
    else:
        messagebox.showerror("Export Failed", msg)
