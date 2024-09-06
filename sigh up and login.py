import hashlib
import os
import re
import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog

# Function to hash the password for added security
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to validate password complexity
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must contain at least one special character."
    return None

# Function to register a new user
def register_user(username, password, filename="users.txt"):
    hashed_password = hash_password(password)
    
    with open(filename, "a") as file:
        file.write(f"{username}:{hashed_password}\n")
    messagebox.showinfo("Success", f"User '{username}' registered successfully!")

# Function to check if a user already exists
def check_user_exists(username, filename="users.txt"):
    if not os.path.exists(filename):
        return False
    
    with open(filename, "r") as file:
        for line in file:
            saved_username = line.split(":")[0]
            if saved_username == username:
                return True
    return False

# Function to log in a user
def login_user(username, password, filename="users.txt"):
    hashed_password = hash_password(password)
    
    if not os.path.exists(filename):
        return False
    
    with open(filename, "r") as file:
        for line in file:
            saved_username, saved_hashed_password = line.strip().split(":")
            if saved_username == username and saved_hashed_password == hashed_password:
                return True
    return False

# Function to save user-specific data to a file
def save_user_data(username, data):
    user_file = f"{username}_data.txt"
    with open(user_file, "a") as file:
        file.write(data + "\n")
    messagebox.showinfo("Success", f"Data saved to {user_file}")

# Function to handle registration
def handle_registration():
    username = username_entry.get()
    password = password_entry.get()
    
    if check_user_exists(username):
        messagebox.showerror("Error", f"Username '{username}' already exists.")
    else:
        password_error = validate_password(password)
        if password_error:
            messagebox.showerror("Error", password_error)
        else:
            register_user(username, password)

# Function to handle login and data saving
def handle_login():
    username = username_entry.get()
    password = password_entry.get()
    
    if login_user(username, password):
        while True:
            data = simpledialog.askstring("Data Entry", f"Enter data to save in {username}'s file (or type 'exit' to logout):")
            if data is None or data.lower() == 'exit':
                break
            if data:
                save_user_data(username, data)
        messagebox.showinfo("Info", "Logged out successfully.")
    else:
        messagebox.showerror("Error", "Invalid username or password.")

# Create the main application window
def create_main_window():
    global username_entry, password_entry

    root = tk.Tk()
    root.title("User Registration and Login")

    tk.Label(root, text="Username:").grid(row=0, column=0, padx=10, pady=10)
    tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)

    username_entry = tk.Entry(root)
    username_entry.grid(row=0, column=1, padx=10, pady=10)

    password_entry = tk.Entry(root, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Button(root, text="Register", command=handle_registration).grid(row=2, column=0, padx=10, pady=10)
    tk.Button(root, text="Login", command=handle_login).grid(row=2, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_main_window()
