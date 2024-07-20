
```markdown
# Password Manager

A secure and user-friendly password manager with a graphical user interface (GUI) built using Python and `tkinter`. This application allows users to generate, store, retrieve, update, and delete passwords securely using encryption provided by the `cryptography` library.

## Features

- **Encryption**: All passwords are encrypted using Fernet symmetric encryption.
- **Password Generation**: Generate strong, random passwords with a minimum length of 16 characters.
- **Password Management**: Add, retrieve, update, and delete passwords for different accounts.
- **Import/Export**: Import and export passwords to/from a JSON file.
- **Clipboard**: Copy passwords to the clipboard for easy use.
- **Masked Passwords**: Passwords are masked by default and can be revealed temporarily.

## Requirements

- Python 3.x
- `cryptography` library
- `pyperclip` library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/a6s1/Password-Manager-2.git
   cd password-manager-own-key
   ```

2. Install the required libraries:
   ```bash
   pip install cryptography pyperclip
   ```
### Creating the Executable

You can create an executable file using PyInstaller:

1. Install PyInstaller:

    ```sh
    pip install pyinstaller
    ```

2. Generate the executable:

    ```sh
    pyinstaller --onefile --noconsole app.py
    ```

3. The executable file will be created in the `dist` directory.

## Usage

1. Run the application:
   ```bash
   python app.py
   ```

2. Enter the encryption key to unlock your passwords.

3. Use the sidebar to:
   - Add a new password
   - Retrieve a password
   - Update an existing password
   - Delete a password
   - List all accounts
   - Import passwords from a file
   - Export passwords to a file


```
