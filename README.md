# Secure Password Manager

## Overview
Secure Password Manager is a robust application built with Python that enables secure storage and management of sensitive passwords. It leverages the Cryptography library for strong encryption (using Fernet) and implements master password authentication using PBKDF2 hashing. The project features a user-friendly interface designed with PySimpleGUI.

## Features
- **Encryption:** Utilizes Fernet for encrypting passwords securely.
- **Authentication:** Implements master password verification with PBKDF2.
- **User Interface:** Intuitive GUI built with PySimpleGUI for ease of use.
- **CRUD Operations:** Create, read, update, and delete password entries.

## Installation
1. **Clone the repository:**
    ```bash
    git clone https://github.com/Darian754/secure-password-manager.git
    ```
2. **Navigate to the project directory:**
    ```bash
    cd secure-password-manager
    ```
3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4. **Run the application:**
    ```bash
    python main.py
    ```

## Usage
Open the application to access your secure password vault. Sign in using your master password to manage your encrypted password entries.

## What I Learned
- **Cryptography Practices:** Mastered the Cryptography library and Fernet for secure data encryption.
- **GUI Development:** Improved my skills in building interactive user interfaces with PySimpleGUI.
- **Security Implementation:** Gained hands-on experience implementing secure authentication mechanisms using PBKDF2.
- **Handling Edge Cases:** Developed robust error handling and validation strategies to ensure application security.
