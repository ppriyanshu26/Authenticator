import os
import sys
import getpass

# ------------------- Base Directory -------------------

if sys.platform == "win32":
    BASE_APP_DIR = os.getenv("APPDATA")  # Windows
elif sys.platform == "darwin":
    BASE_APP_DIR = os.path.expanduser("~/Library/Application Support")  # macOS
elif sys.platform.startswith("linux"):
    BASE_APP_DIR = os.path.expanduser("~/.local/share")  # Linux
else:
    BASE_APP_DIR = os.getcwd()  # Fallback for unknown platforms

# Create a folder for your app
APP_FOLDER = os.path.join(BASE_APP_DIR, "TOTP Authenticator")
os.makedirs(APP_FOLDER, exist_ok=True)

# File paths
ENCODED_FILE = os.path.join(APP_FOLDER, "creds.txt")

SERVICE_NAME = "TOTP Authenticator"
USERNAME = getpass.getuser()

# Global state variables
decrypt_key = None
toast_label = None
canvas = None
inner_frame = None
popup_window = None
frames = []
