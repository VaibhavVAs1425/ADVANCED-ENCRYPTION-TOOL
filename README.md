# ADVANCED ENCRYPTION TOOL

**Company:** CODTECH IT Solutions

**Intern Name:** Vaibhav Kumar Sahu

**Intern ID:** CT08VYD

**Domain:** Cybersecurity & Ethical Hacking

**Duration:** 4 Weeks

**Mentor:** Neela Santosh

## PROJECT DESCRIPTION

The **Advanced Encryption Tool** is a Python-based application designed to provide user-friendly file encryption and decryption capabilities. This application utilizes robust cryptographic algorithms, specifically AES-256, to ensure the confidentiality and integrity of sensitive data.  The tool is designed with a graphical user interface (GUI) to make secure file encryption accessible to users with varying levels of technical expertise.

Data security is paramount in today's digital landscape. This project aims to create a practical and easy-to-use application that individuals and small businesses can use to protect their files from unauthorized access. By leveraging the power of Python and established cryptography libraries, this tool offers a straightforward solution for securing digital information.

## TASK DETAILS

**Task Objective:** Develop a Python-based application with a graphical user interface (GUI) that allows users to encrypt and decrypt files using AES-256 encryption.

**Key Functionalities:**

*   **File Encryption:** Securely encrypt files using AES-256 encryption with a user-provided password.
*   **File Decryption:** Decrypt files previously encrypted with this tool using the correct password.
*   **User-Friendly GUI:** Provide an intuitive graphical interface for easy file selection, password input, and operation execution.

**Algorithms Used:**

*   **AES-256 (via Fernet Library):**  For symmetric file encryption, providing strong confidentiality.
*   **PBKDF2HMAC:** For secure key derivation from user-provided passwords, enhancing password-based security.

**Tools & Technologies Used:**

*   **Python 3.x:** The primary programming language used for building the application.
*   **cryptography Library:** A powerful Python library for implementing cryptographic operations securely. Specifically using the `Fernet` module for AES-256 encryption and `PBKDF2HMAC` for key derivation.
*   **tkinter Library:** Python's standard GUI library used to create the user-friendly graphical interface.
*   **Text Editor/IDE:** (e.g., VS Code, Sublime Text, PyCharm) for code development and editing.
*   **Command Prompt / Terminal:** For running the Python application and installing libraries.

**Editor/Platform Used:**

*   VS Code (or IntelliJ IDEA / Eclipse / Sublime Text / Thonny) for development.
*   Command Prompt / PowerShell / Terminal for running the application.

## Features

1.  **File Encryption Module:**
    *   **Functionality:** Encrypts user-selected files using AES-256 encryption.  Employs a unique random salt and PBKDF2HMAC to derive a strong encryption key from the user's password.
    *   **Process:** Reads the content of the selected file, encrypts it using the derived key, prepends the salt to the encrypted data, and saves the encrypted file with a `.enc` extension.

2.  **File Decryption Module:**
    *   **Functionality:** Decrypts files encrypted by this application, using AES-256 decryption.
    *   **Process:** Reads the salt from the beginning of the encrypted file, re-derives the encryption key using the user-provided password and the retrieved salt, and then decrypts the remaining file data. Saves the decrypted content to a new file with the `.enc` extension removed (or appends `.decrypted` if no `.enc` was present).

3.  **Graphical User Interface (GUI):**
    *   **File Selection:**  A "Browse" button and file dialog to easily select files for encryption or decryption. Displays the selected file path in a text field.
    *   **Password Input:**  A text entry field for users to securely input their password. Password characters are hidden for security.
    *   **Action Buttons:** "Encrypt File" and "Decrypt File" buttons to initiate the respective operations.
    *   **Status and Feedback:**  Pop-up message boxes to provide feedback on the success or failure of encryption/decryption operations, including error messages and paths to created files.

**Exit Option:**

The application runs until the user closes the GUI window. Encryption and decryption processes complete and provide feedback before returning control to the user interface, allowing for subsequent operations or application closure.

## Applicability

*   **Data Security for Individuals and Small Businesses:** Provides a simple tool for securing sensitive documents, personal files, and business data.
*   **Cybersecurity Education:** Serves as an educational tool to demonstrate practical file encryption using strong cryptographic algorithms and GUI application development.
*   **Foundation for Security Applications:**  Offers a basic framework that can be expanded upon to create more sophisticated security applications with advanced features.
*   **GUI Application Development in Python:**  Demonstrates how to build user-friendly desktop applications with Python for security-related tasks.

## How to Run the Program

1.  **Ensure Python 3.x is installed** on your system. You can verify by running:
    ```bash
    python --version
    ```
    If Python is not installed, download it from [https://www.python.org/downloads/](https://www.python.org/downloads/).

2.  **Install the `cryptography` library.** Open a terminal or command prompt and run:
    ```bash
    pip install cryptography
    ```
    or
    ```bash
    pip3 install cryptography
    ```

3.  **Save the Python file.** Save the provided Python code as `encryption_tool_gui.py`.

4.  **Run the application.** Open a terminal or command prompt, navigate to the directory where you saved `encryption_tool_gui.py`, and run:
    ```bash
    python encryption_tool_gui.py
    ```
    This will launch the graphical user interface of the Advanced Encryption Tool.

5.  **Using the GUI Application:**
    *   **Select a File:** Click the "Browse" button to open a file dialog and select the file you wish to encrypt or decrypt.
    *   **Enter Password:** Type your desired password into the "Password" field.
    *   **Choose Action:** Click either "Encrypt File" to encrypt the selected file or "Decrypt File" to decrypt an encrypted file.
    *   **View Feedback:**  A message box will appear to indicate the success or failure of the operation. Success messages will display the location of the output file.

## Future Enhancements

*   **Password Confirmation:** Add a password confirmation field to minimize password entry errors during encryption.
*   **Progress Indicator:** Implement a progress bar to provide visual feedback to the user when encrypting or decrypting large files.
*   **Enhanced Error Handling:** Improve error handling to provide more specific and user-friendly error messages for various scenarios.
*   **Standalone Executable:** Package the application as a standalone executable for easier distribution and use on systems without Python installed, using tools like PyInstaller.
*   **Advanced Key Management (Optional):** Explore more sophisticated key management techniques for enhanced security in advanced versions, if required.

## Conclusion

The Advanced Encryption Tool provides a user-friendly and robust solution for file encryption and decryption, leveraging the strength of AES-256 cryptography. This project serves as a practical demonstration of applying cryptographic principles and GUI development in Python to create a useful security application. It offers a valuable starting point for individuals interested in data security, cryptography, and building secure desktop applications.