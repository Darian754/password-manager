import os
import json
import hashlib
import secrets
import string
from cryptography.fernet import Fernet
import PySimpleGUI as sg


#                Master Password Functionality               


# This function uses PBKDF2 (with 100,000 iterations) to hash the master password.
def hash_master_password(password: str, salt: bytes) -> str:
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hashed.hex()

# This function is called when no master password exists.
# It opens a setup window for the user to set and confirm a master password.
def set_master_password():
    layout = [
        [sg.Text("Set a Master Password:")],
        [sg.InputText(key="MASTER1", password_char="*")],
        [sg.Text("Confirm Master Password:")],
        [sg.InputText(key="MASTER2", password_char="*")],
        [sg.Button("Submit")]
    ]
    window = sg.Window("Set Master Password", layout)
    while True:
        event, values = window.read()
        if event in (sg.WINDOW_CLOSED, "Exit"):
            window.close()
            exit()  # Exit if the user closes the window.
        if event == "Submit":
            pwd1 = values["MASTER1"]
            pwd2 = values["MASTER2"]
            if not pwd1 or not pwd2:
                sg.popup("Please fill in both fields.")
            elif pwd1 != pwd2:
                sg.popup("Passwords do not match, try again.")
            else:
                # Generate a random salt and compute the hash.
                salt = os.urandom(16)
                master_hash = hash_master_password(pwd1, salt)
                # Save the salt (in hex) and hash in a JSON file.
                master_data = {"salt": salt.hex(), "hash": master_hash}
                with open("master.json", "w") as f:
                    json.dump(master_data, f)
                sg.popup("Master password set successfully!")
                window.close()
                break

# This function verifies the entered master password.
def verify_master_password(max_attempts=3):
    try:
        with open("master.json", "r") as f:
            master_data = json.load(f)
        salt = bytes.fromhex(master_data["salt"])
        expected_hash = master_data["hash"]
    except Exception as e:
        sg.popup("Error reading master password file. Exiting.")
        exit()
        
    attempts = 0
    layout = [
        [sg.Text("Enter Master Password:"), sg.InputText(key="MASTER", password_char="*")],
        [sg.Button("Login")]
    ]
    window = sg.Window("Login", layout)
    verified = False
    while attempts < max_attempts:
        event, values = window.read()
        if event in (sg.WINDOW_CLOSED, "Exit"):
            window.close()
            exit()
        if event == "Login":
            entered = values["MASTER"]
            if not entered:
                sg.popup("Please enter a master password.")
            else:
                user_hash = hash_master_password(entered, salt)
                if user_hash == expected_hash:
                    verified = True
                    sg.popup("Login Successful!")
                    break
                else:
                    attempts += 1
                    sg.popup(f"Incorrect password. Attempts left: {max_attempts - attempts}")
    window.close()
    if not verified:
        sg.popup("Maximum attempts exceeded. Exiting.")
        exit()

# If the master password file doesn't exist, run the setup.
if not os.path.exists("master.json"):
    set_master_password()

# Prompt for the master password on each launch.
verify_master_password()


#                Password Manager Core Code                  


# ---------- Step 1: Load/Generate Encryption Key ----------

def load_key(filename="secret.key"):
    """
    If a secret key exists, loads it; otherwise, generates a new key.
    """
    if os.path.exists(filename):
        with open(filename, "rb") as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(filename, "wb") as key_file:
            key_file.write(key)
    return key

key = load_key()
cipher_suite = Fernet(key)

def encrypt_password(password: str) -> bytes:
    """Encrypts the plaintext password."""
    return cipher_suite.encrypt(password.encode())

def decrypt_password(token: bytes) -> str:
    """Decrypts the encrypted password token."""
    return cipher_suite.decrypt(token).decode()


#              Additional Feature: Password Generation       


def generate_password(length=12):
    """
    Generates a strong random password using letters, digits, and punctuation.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))


#                    Data Storage Functions                  


DATA_FILENAME = "passwords.json"
password_data = []  # In-memory list to store entries

def load_data():
    """Loads saved password entries from a JSON file into memory."""
    global password_data
    if os.path.exists(DATA_FILENAME):
        with open(DATA_FILENAME, "r") as f:
            try:
                password_data = json.load(f)
            except Exception:
                password_data = []
    else:
        password_data = []

def save_data():
    """Persists the current password entries in a JSON file."""
    with open(DATA_FILENAME, "w") as f:
        json.dump(password_data, f)

load_data()


#                         GUI Layout                         


layout = [
    [sg.Text("Website/Service:"), sg.InputText(key="WEBSITE", size=(30, 1))],
    [sg.Text("Username:"), sg.InputText(key="USERNAME", size=(30, 1))],
    [sg.Text("Password:"), 
     sg.InputText(key="PASSWORD", size=(30, 1), password_char="*"),
     sg.Button("Generate")],
    [sg.Button("Add Entry"), sg.Button("Update Entry"), sg.Button("Delete Entry")],
    [sg.Button("Decrypt"), sg.Button("Exit")],
    [sg.Table(values=[], headings=["Website", "Username", "Password"],
              key="TABLE", enable_events=True, select_mode=sg.TABLE_SELECT_MODE_BROWSE,
              auto_size_columns=True, num_rows=10)]
]

window = sg.Window("Password Manager", layout, finalize=True)

def update_table(window):
    """
    Refreshes the table view with stored entries while masking the password.
    """
    table_data = [
        [entry["website"], entry["username"], "********"]
        for entry in password_data
    ]
    window["TABLE"].update(values=table_data)

update_table(window)

selected_index = None


#                      GUI Event Loop                        


while True:
    event, values = window.read()
    
    if event in (sg.WINDOW_CLOSED, "Exit"):
        break

    # ----- Generate a Random Password -----
    if event == "Generate":
        new_password = generate_password()
        window["PASSWORD"].update(new_password)
        sg.popup("Generated Password:", new_password)

    # ----- Add Entry -----
    elif event == "Add Entry":
        website = values["WEBSITE"]
        username = values["USERNAME"]
        password = values["PASSWORD"]
        if website and username and password:
            encrypted = encrypt_password(password)
            entry = {
                "website": website,
                "username": username,
                "password": encrypted.decode()  # Store encrypted password as string.
            }
            password_data.append(entry)
            save_data()
            update_table(window)
            sg.popup("Entry added successfully!")
        else:
            sg.popup("Please fill in all fields.")

    # ----- Table Selection: Populate Fields (except Password) -----
    elif event == "TABLE":
        if values["TABLE"]:
            selected_index = values["TABLE"][0]
            selected_entry = password_data[selected_index]
            window["WEBSITE"].update(selected_entry["website"])
            window["USERNAME"].update(selected_entry["username"])
            window["PASSWORD"].update("")  # Leave password blank for security.

    # ----- Update Entry -----
    elif event == "Update Entry":
        if selected_index is None:
            sg.popup("Please select an entry from the table first.")
        else:
            website = values["WEBSITE"]
            username = values["USERNAME"]
            password = values["PASSWORD"]
            if website and username and password:
                encrypted = encrypt_password(password)
                password_data[selected_index] = {
                    "website": website,
                    "username": username,
                    "password": encrypted.decode()
                }
                save_data()
                update_table(window)
                sg.popup("Entry updated successfully!")
            else:
                sg.popup("Please fill in all fields.")

    # ----- Delete Entry -----
    elif event == "Delete Entry":
        if selected_index is None:
            sg.popup("Please select an entry from the table first.")
        else:
            confirm = sg.popup_yes_no("Are you sure you want to delete the selected entry?")
            if confirm == "Yes":
                del password_data[selected_index]
                save_data()
                update_table(window)
                sg.popup("Entry deleted.")
                selected_index = None

    # ----- Decrypt Password -----
    elif event == "Decrypt":
        if selected_index is None:
            sg.popup("Please select an entry from the table first.")
        else:
            try:
                encrypted_str = password_data[selected_index]["password"]
                decrypted = decrypt_password(encrypted_str.encode())
                sg.popup("Decrypted Password:", decrypted)
            except Exception:
                sg.popup("Error during decryption.")

window.close()
