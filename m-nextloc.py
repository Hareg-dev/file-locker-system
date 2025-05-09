import os
import sys
import tkinter as tk
import logging
import asyncio
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logging.basicConfig(
    filename='file_locker.log',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def resource_path(relative_path):
    """
    Get the absolute path to a resource, works for development and PyInstaller.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except AttributeError:
        # Fallback to the current directory during development
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

async def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the password using PBKDF2."""
    await asyncio.sleep(0)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

async def overwrite_file(file_path: str):
    """Overwrite the file with random data before deleting it."""
    await asyncio.sleep(0)
    try:
        with open(file_path, 'r+b') as f:
            length = os.path.getsize(file_path)
            logging.info(f.write(os.urandom(length)))
    except Exception as e:
        logging.warning(f"Error overwriting file: {e}")

async def encrypt_file(file_path: str, password: str) -> bool:
    """Encrypt a file with the given password."""
    try:
        # Generate a random salt
        salt = os.urandom(16)
        await asyncio.sleep(0)
        key = await derive_key(password, salt)
        fernet = Fernet(key)
        with open(file_path, 'rb') as f:
            data = f.read()
        # Encrypt the data
        encrypted_data = fernet.encrypt(data)
        # Save the encrypted file with salt prepended
        encrypted_file_path = file_path + '.locked'
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt + encrypted_data)
        # Overwrite and delete the original file
        await overwrite_file(file_path)
        os.remove(file_path)
        logging.info(f"File encrypted: {file_path}")
        return True
    except Exception as e:
        logging.warning(f"Encryption error: {e}")
        return False

async def decrypt_file(file_path: str, password: str) -> bool:
    """Decrypt a file with the given password and replace the encrypted file."""
    await asyncio.sleep(0)
    try:
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            data = f.read()
        # Extract salt and encrypted data
        salt = data[:16]
        encrypted_data = data[16:]
        key = await derive_key(password, salt)
        fernet = Fernet(key)
        # Decrypt data
        decrypted_data = fernet.decrypt(encrypted_data)
        # Save the decrypted data back to the original file name
        original_file_path = file_path.replace('.locked', '')
        with open(original_file_path, 'wb') as f:
            f.write(decrypted_data)
        # Overwrite and delete the encrypted file
        await overwrite_file(file_path)
        os.remove(file_path)
        logging.info(f"File decrypted: {file_path}")
        return True
    except Exception as e:
        logging.warning(f"Decryption error: {e}")
        return False

class PasswordPrompt(tk.Tk):
    """GUI for password input."""
    def __init__(self, file_path: str, mode: str):
        super().__init__()
        self.title("File Locker")
        self.file_path = file_path
        self.mode = mode 
        self.geometry("300x150")
        self.resizable(False, False)

        tk.Label(self, text="Enter Password:").pack(pady=10)
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack(pady=5)
        self.password_entry.focus_set()

        tk.Button(self, text="Submit", command=self.submit).pack(pady=10)

        # Bind Enter key to submit
        self.bind('<Return>', lambda event: self.submit())

    def submit(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return

        if self.mode == 'encrypt':
            asyncio.run(encrypt_file(self.file_path, password))
            messagebox.showinfo("Success", "File encrypted successfully!")
            self.destroy()
        else:  # decrypt
            asyncio.run(decrypt_file(self.file_path, password))
            messagebox.showinfo("Success", "File decrypted successfully!")
            self.destroy()

class FileLockerApp(tk.Tk):
    """Main GUI for selecting files and encrypting/decrypting."""
    def __init__(self):
        super().__init__()
        self.title("File Locker")
        self.geometry("400x200")
        self.resizable(False, False)

        tk.Label(self, text="File Locker", font=("Arial", 16)).pack(pady=10)

        tk.Button(self, text="Select File to Encrypt", command=self.encrypt_file).pack(pady=10)
        tk.Button(self, text="Open Encrypted File", command=self.open_encrypted_file).pack(pady=10)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if file_path:
            PasswordPrompt(file_path, mode='encrypt').mainloop()

    def open_encrypted_file(self):
        file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Locked Files", "*.locked")])
        if file_path:
            PasswordPrompt(file_path, mode='decrypt').mainloop()

def main():
    app = FileLockerApp()
    app.mainloop()

if __name__ == "__main__":
    main()