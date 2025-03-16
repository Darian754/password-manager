import os
import json
from cryptography.fernet import Fernet
import PySimpleGUI as sg

# ---------- Step 1: Setup and Initialization ----------

# Function to load or generate a secret key
def load_key(filename="secret.key"):
    """
    Checks if the key file exists; if not, generates a new key and saves it.
    """
    if os.path.exists(filename):
        with open(filename, "rb") as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(filename, "wb") as key_file:
            key_file.write(key)
    return key

# Load the key and create a Fernet cipher suite
key = load_key()
cipher_suite = Fernet(key)

# Encryption and decryption functions
def encrypt_password(password: str) -> bytes:
    """Encrypt a plaintext password."""
    return cipher_suite.encrypt(password.encode())

def decrypt_password(token: bytes) -> str:
    """Decrypt an encrypted password token."""
    return cipher_suite.decrypt(token).decode()

# ---------- Step 2: Data Storage Setup ----------

# Data file name and in-memory list for storing multiple entries.
DATA_FILENAME = "passwords.json"
password_data = []  # List to hold entries

def load_data():
    """Load saved password entries from a JSON file."""
    global password_data
    if os.path.exists(DATA_FILENAME):
        with open(DATA_FILENAME, "r") as f:
            try:
                password_data = json.load(f)
            except Exception as e:
                password_data = []
    else:
        password_data = []

def save_data():
    """Save the current password entries to a JSON file."""
    with open(DATA_FILENAME, "w") as f:
        json.dump(password_data, f)

# Load any existing data at startup
load_data()

# ---------- Step 3: GUI Layout ----------

# The GUI now has fields for Website, Username, and Password
layout = [
    [sg.Text("Website/Service:"), sg.InputText(key="WEBSITE", size=(30,1))],
    [sg.Text("Username:"),      sg.InputText(key="USERNAME", size=(30,1))],
    [sg.Text("Password:"),      sg.InputText(key="PASSWORD", size=(30,1), password_char="*")],
    [sg.Button("Add Entry"), sg.Button("Update Entry"), sg.Button("Delete Entry")],
    [sg.Button("Decrypt"), sg.Button("Exit")],
    [sg.Table(values=[], headings=["Website", "Username", "Password"],
              key="TABLE", enable_events=True, 
              select_mode=sg.TABLE_SELECT_MODE_BROWSE, 
              auto_size_columns=True, num_rows=10)]
]

window = sg.Window("Password Manager", layout, finalize=True)

# Function to update the table view whenever data changes
def update_table(window):
    table_data = [
        [entry["website"], entry["username"], "********"] 
        for entry in password_data
    ]
    window["TABLE"].update(values=table_data)

update_table(window)

# Variable to keep track of the selected entry in the table.
selected_index = None

# ---------- Step 4: GUI Event Loop and Click-by-Click Walkthrough ----------

while True:
    event, values = window.read()

    # "Exit" or window closed: end the application.
    if event == sg.WINDOW_CLOSED or event == "Exit":
        break

    # ----- Click 1: Add Entry -----
    if event == "Add Entry":
        website = values["WEBSITE"]
        username = values["USERNAME"]
        password = values["PASSWORD"]
        if website and username and password:
            # Encrypt the password for secure storage.
            encrypted = encrypt_password(password)
            # Create a new entry dictionary.
            entry = {
                "website": website,
                "username": username,
                "password": encrypted.decode()  # store as a string
            }
            # Append to our in-memory list and persist to disk.
            password_data.append(entry)
            save_data()
            update_table(window)
            sg.popup("Entry added successfully!")
        else:
            sg.popup("Please fill in all fields.")

    # ----- Click 2: Table Selection -----
    elif event == "TABLE":
        # When an entry is clicked in the table, record its index.
        if values["TABLE"]:
            selected_index = values["TABLE"][0]
            selected_entry = password_data[selected_index]
            # Populate the text fields with the selected data (except the decrypted password)
            window["WEBSITE"].update(selected_entry["website"])
            window["USERNAME"].update(selected_entry["username"])
            window["PASSWORD"].update("")  # For security, don't auto-display the password

    # ----- Click 3: Update Entry -----
    elif event == "Update Entry":
        if selected_index is None:
            sg.popup("Please select an entry from the table first.")
        else:
            website = values["WEBSITE"]
            username = values["USERNAME"]
            password = values["PASSWORD"]
            if website and username and password:
                encrypted = encrypt_password(password)
                # Update the selected entry with new data.
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

    # ----- Click 4: Delete Entry -----
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
                selected_index = None  # reset selection

    # ----- Click 5: Decrypt -----
    elif event == "Decrypt":
        if selected_index is None:
            sg.popup("Please select an entry from the table first.")
        else:
            try:
                # Retrieve encrypted password from the selected entry.
                encrypted_str = password_data[selected_index]["password"]
                decrypted = decrypt_password(encrypted_str.encode())
                sg.popup("Decrypted Password:", decrypted)
            except Exception as e:
                sg.popup("Error during decryption.")

window.close()
