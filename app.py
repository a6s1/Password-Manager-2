import os
import random
import string
import json
import hashlib
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, filedialog
import pyperclip
from cryptography.fernet import Fernet, InvalidToken

class PasswordManager:
    def __init__(self):
        self.keys = {}
        self.current_key_id = None
        self.file_path = 'passwords.json'
        self.passwords = {}
    
    def set_key(self, key, key_id):
        """Set the encryption key with a given key ID."""
        self.keys[key_id] = self.generate_fernet_key(key)
        self.current_key_id = key_id
        self.passwords = self.load_passwords()

    def generate_fernet_key(self, user_key):
        """Generate a valid Fernet key from the user-provided key."""
        digest = hashlib.sha256(user_key.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    def encrypt_password(self, password, key_id):
        """Encrypt a password with the key identified by key_id."""
        cipher = Fernet(self.keys[key_id])
        return cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password, key_id):
        """Decrypt a password with the key identified by key_id."""
        try:
            cipher = Fernet(self.keys[key_id])
            return cipher.decrypt(encrypted_password.encode()).decode()
        except (InvalidToken, ValueError, TypeError):
            return "Decryption failed"

    def load_passwords(self):
        """Load and decrypt passwords from the file."""
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as file:
                encrypted_passwords = json.load(file)
                decrypted_passwords = {}
                for account, data in encrypted_passwords.items():
                    key_id = data['key_id']
                    encrypted_pwd = data['password']
                    if key_id in self.keys:
                        decrypted_passwords[account] = {
                            'password': self.decrypt_password(encrypted_pwd, key_id),
                            'key_id': key_id
                        }
                    else:
                        decrypted_passwords[account] = {
                            'password': "Key not found",
                            'key_id': key_id
                        }
                return decrypted_passwords
        return {}
    
    def save_passwords(self):
        """Encrypt and save passwords to the file."""
        encrypted_passwords = {
            account: {
                'password': self.encrypt_password(data['password'], data['key_id']),
                'key_id': data['key_id']
            }
            for account, data in self.passwords.items()
        }
        with open(self.file_path, 'w') as file:
            json.dump(encrypted_passwords, file)
    
    def generate_password(self, length=16):
        """Generate a random password with a minimum length of 16 characters."""
        if length < 16:
            raise ValueError("Password length should be at least 16 characters")
        
        characters = string.ascii_letters + string.digits + string.punctuation
        password = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ]
        password += random.choices(characters, k=length-4)
        random.shuffle(password)
        return ''.join(password)
    
    def add_password(self, account, password=None, length=16):
        """Add a password for an account."""
        if account in self.passwords:
            return "Account already exists"
        if not password:
            password = self.generate_password(length)
        self.passwords[account] = {'password': password, 'key_id': self.current_key_id}
        self.save_passwords()
        return password
    
    def get_password(self, account):
        """Retrieve the password for an account."""
        return self.passwords.get(account, {"password": "Account not found"})['password']
    
    def update_password(self, account, password=None, length=16):
        """Update the password for an account."""
        if account not in self.passwords:
            return "Account not found"
        if not password:
            password = self.generate_password(length)
        self.passwords[account]['password'] = password
        self.save_passwords()
        return password
    
    def delete_password(self, account):
        """Delete the password for an account."""
        if account in self.passwords:
            del self.passwords[account]
            self.save_passwords()
            return "Password deleted"
        else:
            return "Account not found"
    
    def list_accounts(self):
        """List all account names."""
        return list(self.passwords.keys())
    
    def import_passwords(self, filepath):
        """Import passwords from a JSON file."""
        with open(filepath, 'r') as file:
            imported_passwords = json.load(file)
            for account, data in imported_passwords.items():
                key_id = data['key_id']
                encrypted_pwd = data['password']
                if key_id in self.keys:
                    self.passwords[account] = {
                        'password': self.decrypt_password(encrypted_pwd, key_id),
                        'key_id': key_id
                    }
            self.save_passwords()
    
    def export_passwords(self, filepath):
        """Export passwords to a JSON file."""
        encrypted_passwords = {
            account: {
                'password': self.encrypt_password(data['password'], data['key_id']),
                'key_id': data['key_id']
            }
            for account, data in self.passwords.items()
        }
        with open(filepath, 'w') as file:
            json.dump(encrypted_passwords, file)

class CustomDialog(tk.Toplevel):
    def __init__(self, parent, title=None, prompt=None, initial_value=""):
        super().__init__(parent)
        self.transient(parent)
        self.title(title)

        self.configure(bg="#f0f0f0")
        
        self.result = None

        label = tk.Label(self, text=prompt, font=("Helvetica", 12), bg="#f0f0f0")
        label.pack(padx=20, pady=10)

        self.entry = ttk.Entry(self, font=("Helvetica", 12))
        self.entry.pack(padx=20, pady=10)
        self.entry.focus_set()
        self.entry.insert(0, initial_value)

        button_frame = tk.Frame(self, bg="#f0f0f0")
        button_frame.pack(pady=10)

        ok_button = ttk.Button(button_frame, text="OK", command=self.ok, style="TButton")
        ok_button.pack(side=tk.LEFT, padx=5)
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.cancel, style="TButton")
        cancel_button.pack(side=tk.LEFT, padx=5)

        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)

        self.geometry("300x150")

    def ok(self, event=None):
        self.result = self.entry.get()
        self.destroy()

    def cancel(self, event=None):
        self.destroy()

class PasswordManagerGUI(tk.Tk):
    def __init__(self, pm):
        super().__init__()
        self.pm = pm
        self.title("Password Manager")
        self.geometry("800x600")
        self.configure(bg="#f0f0f0")

        self.style = ttk.Style(self)
        self.style.configure("TButton", font=("Helvetica", 12), padding=10)
        
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)  # Handle window close event

    def create_widgets(self):
        # Sidebar
        sidebar = tk.Frame(self, bg="#2C3E50", width=200, height=600)
        sidebar.pack(side="left", fill="y")
        
        tk.Label(sidebar, text="Password Manager", bg="#2C3E50", fg="white", font=("Helvetica", 16, "bold")).pack(pady=20)

        self.key_button = ttk.Button(sidebar, text="Enter Encryption Key", command=self.set_encryption_key, style="TButton")
        self.key_button.pack(fill="x", pady=5, padx=10)

        self.buttons_frame = tk.Frame(sidebar, bg="#2C3E50")
        self.buttons_frame.pack(fill="both", expand=True)

        buttons = [
            ("Add Password", self.add_password),
            ("Get Password", self.get_password),
            ("Update Password", self.update_password),
            ("Delete Password", self.delete_password),
            ("List Accounts", self.list_accounts),
            ("Import Passwords", self.import_passwords),
            ("Export Passwords", self.export_passwords)
        ]

        for text, command in buttons:
            btn = ttk.Button(self.buttons_frame, text=text, command=command, style="TButton")
            btn.pack(fill="x", pady=5, padx=10)
        
        # Main area
        self.main_frame = tk.Frame(self, bg="#f0f0f0")
        self.main_frame.pack(side="right", fill="both", expand=True)

    def set_encryption_key(self):
        key = self.show_dialog("Enter Encryption Key", "Encryption Key:")
        key_id = self.show_dialog("Enter Key ID", "Key ID:")
        if key and key_id:
            self.pm.set_key(key, key_id)
            self.update_password_list()

    def update_password_list(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        passwords = self.pm.list_accounts()
        for i, account in enumerate(passwords):
            row, col = divmod(i, 4)
            frame = tk.Frame(self.main_frame, bg="white", bd=1, relief="solid")
            frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

            tk.Label(frame, text=account, font=("Helvetica", 12, "bold"), bg="white").pack(pady=5, padx=5)
            password = self.pm.get_password(account)
            masked_password = "*" * len(password)
            password_label = tk.Label(frame, text=masked_password, font=("Helvetica", 10), bg="white")
            password_label.pack(pady=5, padx=5)
            
            reveal_button = ttk.Button(frame, text="Show", command=lambda l=password_label, p=password: self.reveal_password(l, p))
            reveal_button.pack(side="left", padx=5, pady=5)

            copy_button = ttk.Button(frame, text="Copy", command=lambda p=password: pyperclip.copy(p))
            copy_button.pack(side="right", padx=5, pady=5)

    def reveal_password(self, label, password):
        label.config(text=password)
        self.after(3000, lambda: label.config(text="*" * len(password)))

    def add_password(self):
        if not self.pm.current_key_id:
            messagebox.showerror("Error", "Please enter the encryption key first.")
            return
        account = self.show_dialog("Add Password", "Account Name:")
        if account:
            if self.pm.get_password(account) != "Account not found":
                messagebox.showerror("Error", f"Account '{account}' already exists.")
                return
            length = self.show_integer_dialog("Add Password", "Password Length:", 16)
            if length:
                if length < 16:
                    messagebox.showwarning("Invalid Length", "Password length should be at least 16 characters.")
                    return
                password = self.pm.add_password(account, length=length)
                if password == "Account already exists":
                    messagebox.showerror("Error", f"Account '{account}' already exists.")
                else:
                    pyperclip.copy(password)
                    messagebox.showinfo("Password Added", f"Password for {account}: {password}\n(Copied to clipboard)")
                self.update_password_list()

    def get_password(self):
        if not self.pm.current_key_id:
            messagebox.showerror("Error", "Please enter the encryption key first.")
            return
        account = self.show_dialog("Get Password", "Account Name:")
        if account:
            password = self.pm.get_password(account)
            pyperclip.copy(password)
            messagebox.showinfo("Password Retrieved", f"Password for {account}: {password}\n(Copied to clipboard)")

    def update_password(self):
        if not self.pm.current_key_id:
            messagebox.showerror("Error", "Please enter the encryption key first.")
            return
        account = self.show_dialog("Update Password", "Account Name:")
        if account:
            if self.pm.get_password(account) == "Account not found":
                messagebox.showerror("Error", f"Account '{account}' not found.")
                return
            if messagebox.askyesno("Update Confirmation", f"Are you sure you want to update the password for '{account}'?"):
                length = self.show_integer_dialog("Update Password", "Password Length:", 16)
                if length:
                    if length < 16:
                        messagebox.showwarning("Invalid Length", "Password length should be at least 16 characters.")
                        return
                    password = self.pm.update_password(account, length=length)
                    pyperclip.copy(password)
                    messagebox.showinfo("Password Updated", f"Updated password for {account}: {password}\n(Copied to clipboard)")
                    self.update_password_list()

    def delete_password(self):
        if not self.pm.current_key_id:
            messagebox.showerror("Error", "Please enter the encryption key first.")
            return
        account = self.show_dialog("Delete Password", "Account Name:")
        if account:
            if messagebox.askyesno("Delete Confirmation", f"Are you sure you want to delete the password for '{account}'?"):
                result = self.pm.delete_password(account)
                messagebox.showinfo("Password Deleted", result)
                self.update_password_list()

    def list_accounts(self):
        if not self.pm.current_key_id:
            messagebox.showerror("Error", "Please enter the encryption key first.")
            return
        accounts = self.pm.list_accounts()
        if not accounts:
            messagebox.showinfo("No Accounts", "No accounts found.")
        else:
            accounts_str = "\n".join(accounts)
            self.show_accounts_dialog("List of Accounts", accounts_str)

    def import_passwords(self):
        if not self.pm.current_key_id:
            messagebox.showerror("Error", "Please enter the encryption key first.")
            return
        file_path = filedialog.askopenfilename(title="Import Passwords", filetypes=[("JSON Files", "*.json")])
        if file_path:
            self.pm.import_passwords(file_path)
            messagebox.showinfo("Import Successful", "Passwords imported successfully.")
            self.update_password_list()

    def export_passwords(self):
        if not self.pm.current_key_id:
            messagebox.showerror("Error", "Please enter the encryption key first.")
            return
        file_path = filedialog.asksaveasfilename(title="Export Passwords", defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if file_path:
            self.pm.export_passwords(file_path)
            messagebox.showinfo("Export Successful", "Passwords exported successfully.")

    def show_dialog(self, title, prompt):
        dialog = CustomDialog(self, title=title, prompt=prompt)
        self.wait_window(dialog)
        return dialog.result

    def show_integer_dialog(self, title, prompt, initialvalue):
        dialog = CustomDialog(self, title=title, prompt=prompt, initial_value=str(initialvalue))
        self.wait_window(dialog)
        try:
            return int(dialog.result)
        except (ValueError, TypeError):
            return None

    def show_accounts_dialog(self, title, accounts):
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("300x300")
        dialog.configure(bg="#f0f0f0")

        label = tk.Label(dialog, text="Accounts:", font=("Helvetica", 12), bg="#f0f0f0")
        label.pack(padx=20, pady=10)

        accounts_text = tk.Text(dialog, wrap=tk.WORD, font=("Helvetica", 12))
        accounts_text.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
        accounts_text.insert(tk.END, accounts)
        accounts_text.configure(state='disabled')

        ok_button = ttk.Button(dialog, text="OK", command=dialog.destroy, style="TButton")
        ok_button.pack(pady=10)

    def on_closing(self):
        self.destroy()

def main():
    pm = PasswordManager()
    app = PasswordManagerGUI(pm)
    app.mainloop()

if __name__ == "__main__":
    main()
