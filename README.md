# SecureNotepad

## Description
During third year, as part of the Cryptography module, we were assigned a project that involved working with pre-written code provided by our lecturer.
This covered the basic functionality and GUI of a typical text editor, similar to Windows Notepad. While this project facilitated understanding of the crypographic implemented, I felt it important to try and 
attempt this project from scratch myself.
I redesigned the SecureNotepad independtly, in order to help apply my learnings in a more "hands-on" manner.
The SecureNotepad is a Java-based application which extends `JFrame` and provides encrypted text editing capabilitiy. 
It's designed to offer a more secure alternative to traditional text editing by allowing users to encrypt notepad files before saving and requiring decryption upon opening. 


## Features
- **GUI Design**: Built with a Swing interface that looks like the Windows notepad look and feel.
- **Encryption and Decryption**: Utilises  AES encryption in order to secure files.
- **Print Functionality**: Integrated support for printing documents directly from the application.
- **Dynamic UI Components**: Includes menus for file operations and a text area for document editing.

## Key Components
- `JMenuBar` for menu options including File and Info.
- `JTextArea` for the main text editing area.
- `JScrollPane` to enable scrolling within the text area.
- `JFileChooser` for handling file operations like open and save.
- Security features using `BouncyCastleProvider` for cryptographic operations.

## Main Functions
### Menu Options
- **File Operations**: New, Open, Save, Print, and Exit.
- **View Options**: Toggle Word Wrap.
- **Info**: Display software and developer information.

### Encryption & Decryption
- **EncryptText**: Encrypts the text using AES/CTR/NoPadding.
- **DecryptData**: Decrypts the text assuming it was encrypted with the corresponding "encryptText" method.

### Additional Utilities
- **GenerateSalt and GenerateIV**: Generate cryptographic salts and initialisation vectors.
- **SaveFile and OpenFile**: Manage file I/O operations with encryption and decryption included into the process.

## Usage
1. **Open the Application**: Run the SecureNotepad class which will initialise the GUI window.
2. **Edit Text**: Type or paste text into the text area.
3. **Save a File**: Choose "Save" from the File menu, encrypt the text with a password, and save it securely.
4. **Open a File**: Open an encrypted file, which will require the password used during encryption.

## Cryptographic Details
- **AES Encryption**: Uses AES in CTR mode for encryption.
- **Password-Based Encryption**: Employs a password-derived key using PBKDF2 with HMAC SHA-256 for key..



