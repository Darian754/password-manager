import os
from cryptography.fernet import Fernet
import PySimpleGUI as sg

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

# Define the GUI layout using PySimpleGUI
layout = [
    [sg.Text("Enter Password:"), sg.InputText(key="PASSWORD", size=(30,1))],
    [sg.Button("Encrypt"), sg.Button("Decrypt"), sg.Button("Exit")],
    [sg.Text("Output:"), sg.Multiline(key="OUTPUT", size=(50, 5))]
]

# Create the window
window = sg.Window("Password Manager", layout)

# Event loop for the GUI
while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == "Exit":
        break
    elif event == "Encrypt":
        pwd = values["PASSWORD"]
        if pwd:
            try:
                encrypted = encrypt_password(pwd)
                # Displaying encrypted text as a decoded string
                window["OUTPUT"].update(encrypted.decode())
            except Exception as e:
                sg.popup("Error encrypting password.")
        else:
            sg.popup("Please enter a password.")
    elif event == "Decrypt":
        output_text = values["OUTPUT"]
        if output_text:
            try:
                decrypted = decrypt_password(output_text.encode())
                sg.popup("Decrypted Password:", decrypted)
            except Exception as e:
                sg.popup("Error: Invalid data for decryption.")
        else:
            sg.popup("No data to decrypt.")

window.close()
