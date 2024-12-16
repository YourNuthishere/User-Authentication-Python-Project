import tkinter as tk
from tkinter import messagebox
import string
import bcrypt
import json
import os
import random

class UserManagement:
    USER_DATA_FILE = 'users.json'
    FORGOTTEN_PASSWORD_FILE = 'users_data.txt'

    def __init__(self):
        self.ensure_files_exist()

    @staticmethod
    def ensure_files_exist():
        if not os.path.exists(UserManagement.USER_DATA_FILE):
            with open(UserManagement.USER_DATA_FILE, 'w') as file:
                json.dump({}, file)
        else:
            with open(UserManagement.USER_DATA_FILE, 'r+') as file:
                content = file.read().strip()
                if not content:
                    file.seek(0)
                    json.dump({}, file)
                    file.truncate()

        if not os.path.exists(UserManagement.FORGOTTEN_PASSWORD_FILE):
            with open(UserManagement.FORGOTTEN_PASSWORD_FILE, 'w') as file:
                pass

    @staticmethod
    def load_user_data():
        try:
            with open(UserManagement.USER_DATA_FILE, 'r') as file:
                content = file.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError):
            with open(UserManagement.USER_DATA_FILE, 'w') as file:
                json.dump({}, file)
            return {}

    @staticmethod
    def save_user_data(user_data):
        with open(UserManagement.USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file, indent=4)

    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def update_unencrypted_data(self, username, new_password):
        # Read the entire file
        with open(self.FORGOTTEN_PASSWORD_FILE, 'r') as file:
            lines = file.readlines()

        # Update the specific user's password
        updated_lines = []
        user_found = False
        for line in lines:
            if line.startswith(f"{username}|"):
                updated_lines.append(f"{username}|{new_password}\n")
                user_found = True
            else:
                updated_lines.append(line)

        # If user not found, append new entry
        if not user_found:
            updated_lines.append(f"{username}|{new_password}\n")

        # Write back to the file
        with open(self.FORGOTTEN_PASSWORD_FILE, 'w') as file:
            file.writelines(updated_lines)

class Dashboard(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#e8f5e9")
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Welcome to Dashboard", bg="#388e3c", fg="white", 
                font=("Arial", 16, "bold"), pady=15).pack(fill=tk.X)
        
        tk.Label(self, text="You have successfully logged in!", bg="#e8f5e9",
                font=("Arial", 12), pady=20).pack()
        
        tk.Button(self, text="Logout", command=lambda: self.controller.show_frame("LoginPage"),
                 bg="#757575", fg="white", font=("Arial", 12), width=20, pady=5).pack(pady=20)

class Registration(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#e8f5e9")
        self.controller = controller
        self.user_manager = UserManagement()
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Create Your Account", bg="#388e3c", fg="white", 
                font=("Arial", 16, "bold"), pady=15).pack(fill=tk.X)

        self.entry_username = self.create_input_field("Username:")
        self.entry_password = self.create_input_field("Password:", show="*")
        self.entry_confirm_password = self.create_input_field("Confirm Password:", show="*")

        tk.Button(self, text="Register", command=self.handle_register,
                 bg="#4CAF50", fg="white", font=("Arial", 12, "bold"),
                 width=20, pady=5).pack(pady=(30, 10))
        tk.Button(self, text="Back to Login",
                 command=lambda: self.controller.show_frame("LoginPage"),
                 bg="#757575", fg="white", font=("Arial", 12),
                 width=20, pady=5).pack(pady=(10, 20))

    def create_input_field(self, label_text, **kwargs):
        tk.Label(self, text=label_text, bg="#e8f5e9",
                font=("Arial", 12)).pack(pady=(10, 5))
        entry = tk.Entry(self, font=("Arial", 12), bd=2, relief="groove", **kwargs)
        entry.pack(pady=5, ipadx=5, ipady=3)
        return entry

    def handle_register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        confirm_password = self.entry_confirm_password.get()

        if not username or not password or not confirm_password:
            messagebox.showwarning("Input Error", "All fields are required.")
            return

        if len(username) < 5 or not username.isalnum():
            messagebox.showwarning("Username Error",
                                 "Username must be at least 5 characters and alphanumeric.")
            return

        if len(password) < 8 or not any(char.isdigit() for char in password) or \
           not any(char.isupper() for char in password) or \
           not any(char.islower() for char in password) or \
           not any(char in string.punctuation for char in password) or \
           username in password:
            messagebox.showerror("Password Error",
                                "Password must meet all security requirements.")
            return

        if password != confirm_password:
            messagebox.showerror("Password Error", "Passwords do not match.")
            return

        user_data = self.user_manager.load_user_data()
        if username in user_data:
            messagebox.showerror("Error", "Username already exists.")
            return

        hashed_password = self.user_manager.hash_password(password)
        user_data[username] = hashed_password
        self.user_manager.save_user_data(user_data)
        self.user_manager.update_unencrypted_data(username, password)

        messagebox.showinfo("Success", "Account registered successfully!")
        self.controller.show_frame("LoginPage")

class Login(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#e8f5e9")
        self.controller = controller
        self.user_manager = UserManagement()
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Login", bg="#388e3c", fg="white",
                font=("Arial", 16, "bold"), pady=15).pack(fill=tk.X)

        self.entry_username = self.create_input_field("Username:")
        self.entry_password = self.create_input_field("Password:", show="*")

        tk.Button(self, text="Login", command=self.handle_login,
                 bg="#4CAF50", fg="white", font=("Arial", 12, "bold"),
                 width=20, pady=5).pack(pady=(30, 10))
        tk.Button(self, text="Forgot Password", command=self.handle_forgot_password,
                 bg="#757575", fg="white", font=("Arial", 12),
                 width=20, pady=5).pack(pady=(10, 10))
        tk.Button(self, text="Register",
                 command=lambda: self.controller.show_frame("RegistrationPage"),
                 bg="#4CAF50", fg="white", font=("Arial", 12),
                 width=20, pady=5).pack(pady=(10, 20))

    def create_input_field(self, label_text, **kwargs):
        tk.Label(self, text=label_text, bg="#e8f5e9",
                font=("Arial", 12)).pack(pady=(10, 5))
        entry = tk.Entry(self, font=("Arial", 12), bd=2, relief="groove", **kwargs)
        entry.pack(pady=5, ipadx=5, ipady=3)
        return entry

    def handle_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill in both fields.")
            return

        user_data = self.user_manager.load_user_data()
        if username not in user_data:
            messagebox.showerror("Error", "Username not found.")
            return

        if bcrypt.checkpw(password.encode(), user_data[username].encode()):
            messagebox.showinfo("Success", "Login successful!")
            self.controller.show_frame("DashboardPage")
        else:
            messagebox.showerror("Error", "Incorrect password.")

    def handle_forgot_password(self):
        username = self.entry_username.get()

        if not username:
            messagebox.showwarning("Input Error", "Please enter your username.")
            return

        user_data = self.user_manager.load_user_data()
        if username not in user_data:
            messagebox.showerror("Error", "Username not found.")
            return

        new_password = self.generate_random_password()
        messagebox.showinfo("New Password", f"Your new password is: {new_password}")
        
        # Update encrypted user data
        user_data[username] = self.user_manager.hash_password(new_password)
        self.user_manager.save_user_data(user_data)
        
        # Update unencrypted user data
        self.user_manager.update_unencrypted_data(username, new_password)

    @staticmethod
    def generate_random_password():
        characters = string.ascii_letters + string.digits + "@#$%^&*"
        return ''.join(random.choice(characters) for _ in range(12))

class UserAuthApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("User Authentication System")
        self.geometry("400x500")
        self.frames = {}
        self.show_frame("LoginPage")

    def show_frame(self, page_name):
        if page_name not in self.frames:
            frame = None
            if page_name == "LoginPage":
                frame = Login(self, self)
            elif page_name == "RegistrationPage":
                frame = Registration(self, self)
            elif page_name == "DashboardPage":
                frame = Dashboard(self, self)
            self.frames[page_name] = frame
            frame.pack(fill=tk.BOTH, expand=True)
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[page_name].pack(fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    app = UserAuthApp()
    app.mainloop()
