import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_salt():
    """Generates a random salt."""
    return os.urandom(16)

def derive_key_from_password(password, salt):
    """Derives a secure key from a password using PBKDF2HMAC."""
    password_bytes = password.encode('utf-8') # Encode password to bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes for AES-256 key
        salt=salt,
        iterations=480000, # Recommended iterations for security
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes)) # Derive key and encode to base64
    return key

def encrypt_file(file_path, password):
    """Encrypts a file using AES-256 encryption with a password."""
    salt = generate_salt() # Generate a unique salt for this encryption
    key = derive_key_from_password(password, salt) # Derive key from password and salt
    f = Fernet(key) # Initialize Fernet cipher object with derived key

    try:
        with open(file_path, 'rb') as file: # Open the file in binary read mode ('rb')
            file_data = file.read() # Read all file data
        encrypted_data = f.encrypt(file_data) # Encrypt the file data

        # Save the encrypted file with ".enc" extension, and prepend salt
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as encrypted_file: # Open encrypted file in binary write mode ('wb')
            encrypted_file.write(salt) # Write the salt to the beginning of the file (needed for decryption)
            encrypted_file.write(encrypted_data) # Write the encrypted data

        return encrypted_file_path # Return path to the encrypted file

    except FileNotFoundError:
        messagebox.showerror("Error", f"File not found at path: {file_path}")
        return None
    except Exception as e: # Catch other potential errors during encryption
        messagebox.showerror("Encryption Error", f"Encryption error: {e}")
        return None

def decrypt_file(encrypted_file_path, password):
    """Decrypts an encrypted file using AES-256 encryption and a password."""
    try:
        with open(encrypted_file_path, 'rb') as encrypted_file: # Open encrypted file in binary read mode
            salt = encrypted_file.read(16) # Read the first 16 bytes - which is the salt we prepended
            encrypted_data = encrypted_file.read() # Read the rest of the file - the encrypted data

        key = derive_key_from_password(password, salt) # Re-derive the key using the password and the salt from the file
        f = Fernet(key) # Initialize Fernet cipher object with derived key
        decrypted_data = f.decrypt(encrypted_data) # Decrypt the data

        # Save the decrypted file by removing ".enc" extension
        original_file_path = encrypted_file_path[:-4] if encrypted_file_path.endswith('.enc') else encrypted_file_path + '.decrypted' # Remove .enc or add .decrypted if no .enc
        with open(original_file_path, 'wb') as decrypted_file: # Open decrypted file in binary write mode
            decrypted_file.write(decrypted_data) # Write decrypted data

        return original_file_path # Return path to the decrypted file

    except FileNotFoundError:
        messagebox.showerror("Error", f"Encrypted file not found at path: {encrypted_file_path}")
        return None
    except Exception as e: # Catch potential decryption errors (like incorrect password, corrupted file)
        messagebox.showerror("Decryption Error", f"Decryption error: {e}")
        return None

def browse_file():
    """Opens a file dialog to select a file and updates the file path entry."""
    filename = filedialog.askopenfilename()
    file_path_entry.delete(0, tk.END) # Clear previous entry
    file_path_entry.insert(0, filename) # Insert selected file path

def encrypt_gui():
    """Handles encryption when the 'Encrypt File' button is clicked in GUI."""
    file_path = file_path_entry.get()
    password = password_entry.get()

    if not file_path:
        messagebox.showerror("Error", "Please select a file to encrypt.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    encrypted_file_path = encrypt_file(file_path, password)
    if encrypted_file_path:
        messagebox.showinfo("Success", f"File encrypted successfully!\nEncrypted file saved at:\n{encrypted_file_path}")

def decrypt_gui():
    """Handles decryption when the 'Decrypt File' button is clicked in GUI."""
    file_path = file_path_entry.get()
    password = password_entry.get()

    if not file_path:
        messagebox.showerror("Error", "Please select a file to decrypt.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    decrypted_file_path = decrypt_file(file_path, password)
    if decrypted_file_path:
        messagebox.showinfo("Success", f"File decrypted successfully!\nDecrypted file saved at:\n{decrypted_file_path}")

# --- GUI Setup ---
root = tk.Tk()
root.title("Advanced Encryption Tool")

# File Path Selection
file_path_label = tk.Label(root, text="File Path:")
file_path_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
file_path_entry = tk.Entry(root, width=50)
file_path_entry.grid(row=0, column=1, padx=10, pady=10, sticky="we")
browse_button = tk.Button(root, text="Browse", command=browse_file)
browse_button.grid(row=0, column=2, padx=10, pady=10)

# Password Input
password_label = tk.Label(root, text="Password:")
password_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
password_entry = tk.Entry(root, width=50, show="*") # show="*" hides password characters
password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="we")

# Action Buttons
encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_gui)
encrypt_button.grid(row=2, column=1, padx=10, pady=20, sticky="w")
decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_gui)
decrypt_button.grid(row=2, column=1, padx=10, pady=20, sticky="e")

root.columnconfigure(1, weight=1) # Make column 1 (entry fields) expandable

root.mainloop()