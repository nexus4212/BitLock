import os
import json
import base64
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
import time
import threading
import random
import string
from PIL import Image, ImageTk

class BitLock:
    def __init__(self, master_password=None):
        self.salt = os.urandom(32)  # 32 bytes salt for PBKDF2
        self.master_password = master_password
        self.passwords = {}
        self.key = None
        
        # Create data directory if it doesn't exist
        if not os.path.exists('data'):
            os.makedirs('data')
            
        # Load existing passwords if available
        if os.path.exists('data/passwords.enc'):
            self.load_passwords()
    
    def derive_key(self, password):
        """Derive a 512-bit key from the master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,  # 512 bits = 64 bytes
            salt=self.salt,
            iterations=310000,  # NIST recommendation for PBKDF2
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key
    
    def encrypt_data(self, data):
        """Encrypt data using AES-256-GCM for authenticated encryption"""
        if not self.key:
            raise ValueError("No key available. Please set master password first.")
            
        # Use first 32 bytes for AES key, next 12 for nonce
        aes_key = self.key[:32]
        nonce = self.key[32:44]
        
        # Create cipher with GCM mode for authenticated encryption
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Ensure data is bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Encrypt with authentication
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Combine encrypted data with authentication tag
        return encrypted_data + encryptor.tag
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using AES-256-GCM with authentication verification"""
        if not self.key:
            raise ValueError("No key available. Please set master password first.")
            
        # Use first 32 bytes for AES key, next 12 for nonce
        aes_key = self.key[:32]
        nonce = self.key[32:44]
        
        # Extract authentication tag (last 16 bytes)
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[:-16]
        
        # Create cipher with GCM mode
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt with authentication verification
        try:
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Try to decode as UTF-8, but handle errors gracefully
            try:
                return decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                # If decoding fails, return the raw bytes
                return decrypted_data
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def set_master_password(self, password):
        """Set the master password and derive the encryption key"""
        self.master_password = password
        self.key = self.derive_key(password)
        
    def add_password(self, service, username, password):
        """Add a new password entry"""
        self.passwords[service] = {
            'username': username,
            'password': password
        }
        self.save_passwords()
        
    def get_password(self, service):
        """Retrieve a password entry"""
        if service in self.passwords:
            return self.passwords[service]
        return None
        
    def list_services(self):
        """List all stored services"""
        return list(self.passwords.keys())
        
    def save_passwords(self):
        """Save encrypted passwords to file"""
        if not self.key:
            raise ValueError("No key available. Please set master password first.")
            
        # Convert passwords to JSON and encode
        try:
            data = json.dumps(self.passwords).encode('utf-8')
        except (TypeError, UnicodeEncodeError) as e:
            raise ValueError(f"Error encoding passwords: {str(e)}")
        
        # Encrypt data
        encrypted_data = self.encrypt_data(data)
        
        # Save salt and encrypted data
        with open('data/salt.bin', 'wb') as f:
            f.write(self.salt)
            
        with open('data/passwords.enc', 'wb') as f:
            f.write(encrypted_data)
            
    def load_passwords(self):
        """Load encrypted passwords from file"""
        if not os.path.exists('data/salt.bin') or not os.path.exists('data/passwords.enc'):
            return
            
        # Load salt
        with open('data/salt.bin', 'rb') as f:
            self.salt = f.read()
            
        # Load encrypted data
        with open('data/passwords.enc', 'rb') as f:
            encrypted_data = f.read()
            
        # If master password is set, decrypt data
        if self.master_password:
            self.key = self.derive_key(self.master_password)
            try:
                decrypted_data = self.decrypt_data(encrypted_data)
                
                # Handle both string and bytes return types
                if isinstance(decrypted_data, bytes):
                    try:
                        # Try to decode with strict UTF-8
                        decrypted_data = decrypted_data.decode('utf-8')
                    except UnicodeDecodeError:
                        # If that fails, the data is likely corrupted
                        print("Error: Password data appears to be corrupted or encrypted with a different key")
                        self.passwords = {}
                        return
                
                # Validate that the decrypted data is valid JSON
                try:
                    self.passwords = json.loads(decrypted_data)
                except json.JSONDecodeError:
                    print("Error: Decrypted data is not valid JSON")
                    self.passwords = {}
            except Exception as e:
                print(f"Error decrypting passwords: {e}")
                self.passwords = {}

    @staticmethod
    def erase_all_data():
        """Erase all data files and reset the password manager"""
        import shutil
        
        # Check if data directory exists
        if os.path.exists('data'):
            # Remove all files in the data directory
            for file in os.listdir('data'):
                file_path = os.path.join('data', file)
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            
            # Optionally remove the data directory itself
            # os.rmdir('data')
            
            return True
        return False

class BitLockGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BitLock Password Manager")
        self.root.geometry("600x400")
        self.root.resizable(True, True)
        
        # Set minimum window size
        self.root.minsize(975, 720)
        
        # Set theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Remove focus outline from buttons
        self.style.configure('TButton', focuscolor='none')
        self.style.map('TButton', focuscolor=[('active', 'none')])
        
        # Initialize BitLock
        self.bitlock = BitLock()
        self.is_authenticated = False
        
        # Session timeout variables (10 minutes = 600 seconds)
        self.session_timeout = 600
        self.last_activity_time = time.time()
        self.session_timer = None
        
        # Load logo
        self.logo = None
        self.load_logo()
        
        # Set window icon if logo is available
        if self.logo:
            self.root.iconphoto(True, self.logo)
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Check if master password is already set
        if os.path.exists('data/salt.bin') and os.path.exists('data/passwords.enc'):
            self.show_login_frame()
        else:
            self.show_setup_frame()
    
    def load_logo(self):
        """Load the logo image"""
        try:
            # Check if logo.png exists in the current directory
            if os.path.exists('logo.png'):
                # Load and resize the logo
                img = Image.open('logo.png')
                # Resize to a reasonable size
                img = img.resize((150, 150), Image.LANCZOS)
                self.logo = ImageTk.PhotoImage(img)
            else:
                print("Logo file not found. Using text title instead.")
        except Exception as e:
            print(f"Error loading logo: {e}")
    
    def update_last_activity(self):
        """Update the last activity timestamp"""
        self.last_activity_time = time.time()
    
    def check_session_timeout(self):
        """Check if the session has timed out"""
        if self.is_authenticated:
            current_time = time.time()
            elapsed_time = current_time - self.last_activity_time
            
            if elapsed_time >= self.session_timeout:
                # Session has timed out, log out the user
                messagebox.showinfo("Session Expired", "Your session has expired. Please log in again.")
                self.logout()
            else:
                # Schedule the next check
                self.session_timer = self.root.after(1000, self.check_session_timeout)
    
    def start_session_timer(self):
        """Start the session timer"""
        self.update_last_activity()
        if self.session_timer:
            self.root.after_cancel(self.session_timer)
        self.session_timer = self.root.after(1000, self.check_session_timeout)
    
    def stop_session_timer(self):
        """Stop the session timer"""
        if self.session_timer:
            self.root.after_cancel(self.session_timer)
            self.session_timer = None
    
    def show_login_frame(self):
        """Show login frame for existing users"""
        self.clear_frame()
        self.stop_session_timer()
        
        # Create login widgets
        if self.logo:
            # Display logo
            logo_label = ttk.Label(self.main_frame, image=self.logo)
            logo_label.pack(pady=10)
        else:
            # Fallback to text title
            ttk.Label(self.main_frame, text="BitLock Password Manager", font=("Arial", 16, "bold")).pack(pady=20)
        
        ttk.Label(self.main_frame, text="Enter your master password to continue").pack(pady=10)
        
        # Password entry
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.main_frame, textvariable=self.password_var, show="*")
        self.password_entry.pack(pady=10, padx=50, fill=tk.X)
        
        # Login button
        ttk.Button(self.main_frame, text="Login", command=self.login).pack(pady=20)
        
        # Separator
        ttk.Separator(self.main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=50, pady=10)
        
        # Reset button
        ttk.Button(self.main_frame, text="Reset All Data", command=self.reset_all_data).pack(pady=10)
        
        # Focus on password entry
        self.password_entry.focus()
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.login())
    
    def show_setup_frame(self):
        """Show setup frame for new users"""
        self.clear_frame()
        self.stop_session_timer()
        
        # Create setup widgets
        if self.logo:
            # Display logo
            logo_label = ttk.Label(self.main_frame, image=self.logo)
            logo_label.pack(pady=10)
        else:
            # Fallback to text title
            ttk.Label(self.main_frame, text="BitLock Password Manager", font=("Arial", 16, "bold")).pack(pady=20)
        
        ttk.Label(self.main_frame, text="Set up your master password").pack(pady=10)
        
        # Password entry
        ttk.Label(self.main_frame, text="Master Password:").pack(pady=(20, 5))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.main_frame, textvariable=self.password_var, show="*")
        self.password_entry.pack(pady=5, padx=50, fill=tk.X)
        
        # Confirm password entry
        ttk.Label(self.main_frame, text="Confirm Master Password:").pack(pady=(20, 5))
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ttk.Entry(self.main_frame, textvariable=self.confirm_password_var, show="*")
        self.confirm_password_entry.pack(pady=5, padx=50, fill=tk.X)
        
        # Setup button
        ttk.Button(self.main_frame, text="Set Up", command=self.setup).pack(pady=20)
        
        # Focus on password entry
        self.password_entry.focus()
        
        # Bind Enter key to setup
        self.root.bind('<Return>', lambda event: self.setup())
    
    def show_main_frame(self):
        """Show main application frame after login"""
        self.clear_frame()
        self.is_authenticated = True
        
        # Start session timer
        self.start_session_timer()
        
        # Bind activity events to update last activity time
        self.root.bind('<Key>', lambda event: self.update_last_activity())
        self.root.bind('<Button-1>', lambda event: self.update_last_activity())
        self.root.bind('<Motion>', lambda event: self.update_last_activity())
        
        # Create main application widgets
        ttk.Label(self.main_frame, text="BitLock Password Manager", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        self.passwords_frame = ttk.Frame(self.notebook)
        self.add_password_frame = ttk.Frame(self.notebook)
        self.password_generator_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.passwords_frame, text="Passwords")
        self.notebook.add(self.add_password_frame, text="Add Password")
        self.notebook.add(self.password_generator_frame, text="Password Generator")
        
        # Setup passwords tab
        self.setup_passwords_tab()
        
        # Setup add password tab
        self.setup_add_password_tab()
        
        # Setup password generator tab
        self.setup_password_generator_tab()
        
        # Button frame for logout
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Logout button
        ttk.Button(button_frame, text="Logout", command=self.logout).pack(side=tk.LEFT, padx=5)
    
    def setup_passwords_tab(self):
        """Setup the passwords tab"""
        # Create search frame
        search_frame = ttk.Frame(self.passwords_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Search label
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Search entry
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_passwords)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Create treeview for passwords
        columns = ("Service", "Username", "Password")
        self.tree = ttk.Treeview(self.passwords_frame, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.passwords_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        # Pack widgets
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Add buttons in a vertical layout
        button_frame = ttk.Frame(self.passwords_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_passwords).pack(fill=tk.X, pady=2)
        ttk.Button(button_frame, text="View Password", command=self.view_password).pack(fill=tk.X, pady=2)
        ttk.Button(button_frame, text="Change Password", command=self.change_password).pack(fill=tk.X, pady=2)
        ttk.Button(button_frame, text="Delete", command=self.delete_password).pack(fill=tk.X, pady=2)
        
        # Populate treeview
        self.refresh_passwords()
    
    def filter_passwords(self, *args):
        """Filter passwords based on search term"""
        search_term = self.search_var.get().lower()
        
        # Clear treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add filtered passwords to treeview
        for service in self.bitlock.list_services():
            if search_term in service.lower():
                entry = self.bitlock.get_password(service)
                self.tree.insert("", tk.END, values=(service, entry['username'], "********"))
    
    def setup_add_password_tab(self):
        """Setup the add password tab"""
        # Create form
        form_frame = ttk.Frame(self.add_password_frame, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Service
        ttk.Label(form_frame, text="Service:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.service_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.service_var, width=40).grid(row=0, column=1, sticky=tk.W, pady=10)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.username_var = tk.StringVar()
        ttk.Entry(form_frame, textvariable=self.username_var, width=40).grid(row=1, column=1, sticky=tk.W, pady=10)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.new_password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form_frame, textvariable=self.new_password_var, show="*", width=40)
        self.password_entry.grid(row=2, column=1, sticky=tk.W, pady=10)
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(form_frame, text="Show Password", variable=self.show_password_var, 
                        command=self.toggle_password_visibility).grid(row=3, column=1, sticky=tk.W, pady=10)
        
        # Add button
        ttk.Button(form_frame, text="Add Password", command=self.add_password).grid(row=4, column=0, columnspan=2, pady=20)
    
    def setup_password_generator_tab(self):
        """Setup the password generator tab"""
        # Create form
        form_frame = ttk.Frame(self.password_generator_frame, padding=20)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(form_frame, text="Password Generator", font=("Arial", 12, "bold")).pack(pady=(0, 20))
        
        # Length frame
        length_frame = ttk.Frame(form_frame)
        length_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT, padx=(0, 10))
        
        # Length slider
        self.length_var = tk.IntVar(value=16)
        length_slider = ttk.Scale(length_frame, from_=8, to=32, variable=self.length_var, orient=tk.HORIZONTAL)
        length_slider.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Length value label
        self.length_label = ttk.Label(length_frame, text="16")
        self.length_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Update length label when slider changes
        self.length_var.trace_add("write", self.update_length_label)
        
        # Character options frame
        options_frame = ttk.LabelFrame(form_frame, text="Character Options")
        options_frame.pack(fill=tk.X, pady=10)
        
        # Uppercase letters
        self.uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uppercase Letters (A-Z)", variable=self.uppercase_var).pack(anchor=tk.W, pady=5)
        
        # Lowercase letters
        self.lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Lowercase Letters (a-z)", variable=self.lowercase_var).pack(anchor=tk.W, pady=5)
        
        # Numbers
        self.numbers_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Numbers (0-9)", variable=self.numbers_var).pack(anchor=tk.W, pady=5)
        
        # Special characters
        self.special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Special Characters (!@#$%^&*)", variable=self.special_var).pack(anchor=tk.W, pady=5)
        
        # Generate button
        ttk.Button(form_frame, text="Generate Password", command=self.generate_password).pack(pady=20)
        
        # Generated password frame
        result_frame = ttk.LabelFrame(form_frame, text="Generated Password")
        result_frame.pack(fill=tk.X, pady=10)
        
        # Generated password entry
        self.generated_password_var = tk.StringVar()
        self.generated_password_entry = ttk.Entry(result_frame, textvariable=self.generated_password_var, font=("Courier", 12))
        self.generated_password_entry.pack(fill=tk.X, padx=10, pady=10)
        
        # Copy button
        ttk.Button(result_frame, text="Copy to Clipboard", command=self.copy_generated_password).pack(pady=10)
    
    def update_length_label(self, *args):
        """Update the length label when the slider changes"""
        self.length_label.config(text=str(self.length_var.get()))
    
    def generate_password(self):
        """Generate a password based on selected options"""
        length = self.length_var.get()
        use_uppercase = self.uppercase_var.get()
        use_lowercase = self.lowercase_var.get()
        use_numbers = self.numbers_var.get()
        use_special = self.special_var.get()
        
        # Define character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        numbers = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Build character pool based on selected options
        chars = ""
        if use_uppercase:
            chars += uppercase
        if use_lowercase:
            chars += lowercase
        if use_numbers:
            chars += numbers
        if use_special:
            chars += special
        
        # Ensure at least one character from each selected type
        password = ""
        if use_uppercase and chars:
            password += random.choice(uppercase)
        if use_lowercase and chars:
            password += random.choice(lowercase)
        if use_numbers and chars:
            password += random.choice(numbers)
        if use_special and chars:
            password += random.choice(special)
        
        # Fill the rest of the password
        remaining_length = length - len(password)
        if remaining_length > 0 and chars:
            password += ''.join(random.choice(chars) for _ in range(remaining_length))
        
        # Shuffle the password
        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)
        
        # Set the generated password
        self.generated_password_var.set(password)
    
    def copy_generated_password(self):
        """Copy the generated password to clipboard"""
        password = self.generated_password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            
            # Change button text to "Copied!" temporarily
            copy_button = self.generated_password_entry.master.winfo_children()[-1]  # Get the copy button
            original_text = copy_button.cget("text")
            copy_button.config(text="Copied!")
            
            # Reset button text after 2 seconds
            self.root.after(2000, lambda: copy_button.config(text=original_text))
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def clear_frame(self):
        """Clear all widgets from the main frame"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def login(self):
        """Handle login"""
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return
        
        try:
            self.bitlock.set_master_password(password)
            self.bitlock.load_passwords()
            self.show_main_frame()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to login: {str(e)}")
            self.password_var.set("")
            self.password_entry.focus()
    
    def setup(self):
        """Handle setup for new users"""
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            self.confirm_password_var.set("")
            self.confirm_password_entry.focus()
            return
        
        try:
            self.bitlock.set_master_password(password)
            # Save an empty password database to create the necessary files
            self.bitlock.save_passwords()
            self.show_main_frame()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set up: {str(e)}")
    
    def logout(self):
        """Handle logout"""
        self.is_authenticated = False
        self.stop_session_timer()
        self.bitlock = BitLock()
        self.show_login_frame()
    
    def refresh_passwords(self):
        """Refresh the passwords list"""
        # Clear treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add passwords to treeview
        for service in self.bitlock.list_services():
            entry = self.bitlock.get_password(service)
            self.tree.insert("", tk.END, values=(service, entry['username'], "********"))
    
    def add_password(self):
        """Add a new password"""
        service = self.service_var.get()
        username = self.username_var.get()
        password = self.new_password_var.get()
        
        if not service or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        try:
            self.bitlock.add_password(service, username, password)
            messagebox.showinfo("Success", f"Password for {service} added successfully!")
            
            # Clear form
            self.service_var.set("")
            self.username_var.set("")
            self.new_password_var.set("")
            
            # Refresh passwords list
            self.refresh_passwords()
            
            # Switch to passwords tab
            self.notebook.select(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add password: {str(e)}")
    
    def copy_username(self):
        """Copy username to clipboard"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a password entry")
            return
        
        service = self.tree.item(selected_item[0])['values'][0]
        entry = self.bitlock.get_password(service)
        
        self.root.clipboard_clear()
        self.root.clipboard_append(entry['username'])
        messagebox.showinfo("Success", "Username copied to clipboard")
    
    def copy_password(self):
        """Copy password to clipboard"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a password entry")
            return
        
        service = self.tree.item(selected_item[0])['values'][0]
        entry = self.bitlock.get_password(service)
        
        self.root.clipboard_clear()
        self.root.clipboard_append(entry['password'])
        messagebox.showinfo("Success", "Password copied to clipboard")
    
    def delete_password(self):
        """Delete a password entry"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a password entry")
            return
        
        service = self.tree.item(selected_item[0])['values'][0]
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete the password for {service}?"):
            del self.bitlock.passwords[service]
            self.bitlock.save_passwords()
            self.refresh_passwords()
            messagebox.showinfo("Success", f"Password for {service} deleted successfully!")
    
    def reset_all_data(self):
        """Reset all data and start fresh"""
        if messagebox.askyesno("Confirm Reset", 
                              "Are you sure you want to erase ALL data and start fresh?\n\n"
                              "This will delete all your stored passwords and require you to set up a new master password.\n"
                              "This action cannot be undone!"):
            if BitLock.erase_all_data():
                messagebox.showinfo("Success", "All data has been erased. The application will now close.")
                # Close the application window
                self.root.destroy()
            else:
                messagebox.showerror("Error", "Failed to erase data.")
    
    def view_password(self):
        """View password in a popup dialog"""
        try:
            selected_item = self.tree.selection()
            if not selected_item:
                messagebox.showinfo("Info", "Please select a password entry")
                return
            
            service = self.tree.item(selected_item[0])['values'][0]
            entry = self.bitlock.get_password(service)
            
            if not entry:
                messagebox.showerror("Error", f"Could not retrieve password for {service}")
                return
            
            # Create a popup dialog
            dialog = tk.Toplevel(self.root)
            dialog.title(f"Password for {service}")
            dialog.geometry("400x200")
            dialog.resizable(False, False)
            dialog.transient(self.root)  # Make dialog modal
            dialog.grab_set()  # Make dialog modal
            
            # Set window icon if logo is available
            if self.logo:
                dialog.iconphoto(True, self.logo)
            
            # Make dialog appear on top
            dialog.lift()
            dialog.focus_force()
            
            # Add content with better styling
            main_frame = ttk.Frame(dialog, padding=20)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Service name
            ttk.Label(main_frame, text=service, font=("Arial", 12, "bold")).pack(pady=(0, 10))
            
            # Password display as text
            ttk.Label(main_frame, text="Password:", font=("Arial", 10)).pack(anchor=tk.W)
            ttk.Label(main_frame, text=entry['password'], font=("Courier", 12)).pack(fill=tk.X, padx=5, pady=5)
            
            # Button frame
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=20)
            
            # Copy password button with temporary text change
            copy_button = ttk.Button(button_frame, text="Copy Password")
            copy_button.pack(side=tk.LEFT, padx=5)
            
            def copy_with_feedback():
                # Copy to clipboard
                self.root.clipboard_clear()
                self.root.clipboard_append(entry['password'])
                
                # Change button text
                copy_button.config(text="Copied!")
                
                # Reset button text after 2 seconds
                dialog.after(2000, lambda: copy_button.config(text="Copy Password"))
            
            copy_button.config(command=copy_with_feedback)
            
            # Close button
            ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
            
            # Center the dialog on the main window
            dialog.update_idletasks()
            x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
            y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
            dialog.geometry(f"+{x}+{y}")
            
            # Bind Escape key to close dialog
            dialog.bind("<Escape>", lambda event: dialog.destroy())
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard without showing confirmation"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
    
    def change_password(self):
        """Change password for a selected service"""
        try:
            selected_item = self.tree.selection()
            if not selected_item:
                messagebox.showinfo("Info", "Please select a password entry")
                return
            
            service = self.tree.item(selected_item[0])['values'][0]
            entry = self.bitlock.get_password(service)
            
            if not entry:
                messagebox.showerror("Error", f"Could not retrieve password for {service}")
                return
            
            # Create a popup dialog
            dialog = tk.Toplevel(self.root)
            dialog.title(f"Change Password for {service}")
            dialog.geometry("400x280")
            dialog.resizable(False, False)
            dialog.transient(self.root)  # Make dialog modal
            dialog.grab_set()  # Make dialog modal
            
            # Set window icon if logo is available
            if self.logo:
                dialog.iconphoto(True, self.logo)
            
            # Make dialog appear on top
            dialog.lift()
            dialog.focus_force()
            
            # Add content
            main_frame = ttk.Frame(dialog, padding=20)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Service name
            ttk.Label(main_frame, text=service, font=("Arial", 12, "bold")).pack(pady=(0, 15))
            
            # New password entry
            ttk.Label(main_frame, text="New Password:").pack(anchor=tk.W)
            new_password_var = tk.StringVar()
            new_password_entry = ttk.Entry(main_frame, textvariable=new_password_var, show="*", width=40)
            new_password_entry.pack(fill=tk.X, padx=5, pady=5)
            
            # Confirm new password
            ttk.Label(main_frame, text="Confirm New Password:").pack(anchor=tk.W, pady=(10, 0))
            confirm_password_var = tk.StringVar()
            confirm_password_entry = ttk.Entry(main_frame, textvariable=confirm_password_var, show="*", width=40)
            confirm_password_entry.pack(fill=tk.X, padx=5, pady=5)
            
            # Button frame with more space
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=20)
            
            # Save button
            def save_new_password():
                new_password = new_password_var.get()
                confirm_password = confirm_password_var.get()
                
                if not new_password:
                    messagebox.showerror("Error", "Please enter a new password")
                    return
                
                if new_password != confirm_password:
                    messagebox.showerror("Error", "Passwords do not match")
                    return
                
                # Update password
                self.bitlock.add_password(service, entry['username'], new_password)
                messagebox.showinfo("Success", f"Password for {service} updated successfully")
                dialog.destroy()
                self.refresh_passwords()
            
            # Create style for taller buttons
            button_style = ttk.Style()
            button_style.configure("Tall.TButton", padding=10)
            
            # Save button with taller style
            save_button = ttk.Button(button_frame, text="Save", command=save_new_password, style="Tall.TButton")
            save_button.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            # Cancel button with taller style
            cancel_button = ttk.Button(button_frame, text="Cancel", command=dialog.destroy, style="Tall.TButton")
            cancel_button.pack(side=tk.RIGHT, padx=5, fill=tk.X, expand=True)
            
            # Center the dialog on the main window
            dialog.update_idletasks()
            x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
            y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
            dialog.geometry(f"+{x}+{y}")
            
            # Focus on new password entry
            new_password_entry.focus()
            
            # Bind Enter key to save
            dialog.bind("<Return>", lambda event: save_new_password())
            
            # Bind Escape key to close dialog
            dialog.bind("<Escape>", lambda event: dialog.destroy())
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

def run_gui():
    """Run the graphical user interface"""
    root = tk.Tk()
    app = BitLockGUI(root)
    root.mainloop()

def main():
    """Main function to run the application"""
    run_gui()

if __name__ == "__main__":
    main()
