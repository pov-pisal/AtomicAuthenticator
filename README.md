# 🛡️ Atomic Authenticator

A secure, lightweight browser extension for managing TOTP (Time-based One-Time Password) authentication codes with encrypted storage and PIN protection.

## ✨ Features

- **🔐 Encrypted Vault** - All TOTP secrets are encrypted with AES-256-GCM using your PIN
- **📱 TOTP Generation** - Generate time-based one-time passwords for two-factor authentication
- **🔑 PIN Protection** - Secure your vault with a personal identification number
- **💾 Backup & Restore** - Export your accounts for backup (PIN is not included)
- **🎨 Dark/Light Theme** - Choose your preferred color scheme
- **🔒 Auto-lock** - Automatically lock vault after inactivity
- **📂 Account Management** - Add, edit, and delete TOTP accounts
- **🔍 Search** - Quickly find accounts by issuer or label
- **📊 Customizable Sorting** - Sort accounts by date, issuer, or label

## 🚀 Installation

### From Source (Development)

1. Clone the repository:

```bash
git clone https://github.com/pov-pisal/AtomicAuthenticator.git
cd AtomicAuthenticator
```

2. Open Chrome/Brave/Edge and navigate to:

```
chrome://extensions/
```

3. Enable "Developer mode" (top right toggle)

4. Click "Load unpacked" and select the project folder

## 📖 Usage

### First Time Setup

1. Click the Atomic Authenticator extension icon
2. Create a PIN (minimum 6 digits) and confirm it
3. Start adding your TOTP accounts

### Adding an Account

1. Click the "Add account" button
2. Enter the TOTP secret (base32 encoded)
3. Optionally add the issuer name and label
4. Click "Save account"

**Tip:** You can paste `otpauth://` URLs directly - the extension will parse them automatically!

### Generating Codes

- Your TOTP codes refresh every 30 seconds
- Click on an account to copy the code
- Codes are automatically removed from clipboard after a short delay

### Backing Up Your Data

1. Go to Settings → Backup
2. Click "Export" tab
3. Click "Copy to Clipboard" or "Download" to save your backup
4. **Note:** Backups include only your accounts, not your PIN for security

### Restoring from Backup

1. Go to Settings → Backup
2. Click "Import" tab
3. Paste your backup JSON
4. Click "Import Backup" to restore accounts

## 🏗️ Project Structure

```
├── manifest.json          # Chrome extension manifest
├── popup.html            # Main UI
├── popup.css             # Styling
├── popup.js              # Main logic & event handlers
├── crypto.js             # Encryption/decryption functions
├── totp.js               # TOTP generation & parsing
├── storage.js            # Browser storage interface
├── contentScript.js      # Content script for autofill
├── import.html           # Import page
├── import.js             # Import page logic
└── icons/                # Extension icons (16x16, 32x32, 48x48, 128x128)
```

## 🔒 Security

- **End-to-End Encrypted** - TOTP secrets encrypted with AES-256-GCM
- **PIN-Protected** - Your PIN never leaves your device
- **No Server Communication** - Completely offline, no cloud sync
- **Secure Storage** - Uses Chrome's `chrome.storage.sync` for encrypted local storage
- **Auto-lock** - Configurable timeout to automatically lock the vault

### Encryption Details

- **Algorithm:** AES-256-GCM (NIST approved)
- **Key Derivation:** PBKDF2 with SHA-256
- **Iterations:** 100,000
- **IV:** Random 12-byte nonce

## 🛠️ Technical Stack

- **Language:** Vanilla JavaScript (ES6+)
- **Storage:** Chrome Storage API
- **Encryption:** Web Crypto API
- **UI Framework:** None (vanilla HTML/CSS)
- **Build Tool:** None required (load as unpacked extension)

## 📚 Dependencies

None! This extension has zero external dependencies. It uses only:

- Chrome APIs
- Web Crypto API
- Browser Storage API

## ⚙️ Settings

- **Auto-lock after:** Set how long before vault auto-locks (1 min - Never)
- **Theme:** Choose between Dark and Light modes
- **Sort Accounts:** Order by Newest, Oldest, Issuer (A-Z/Z-A), or Label (A-Z/Z-A)
- **Change PIN:** Update your vault PIN anytime

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is open source and available under the MIT License.

## ⚠️ Disclaimer

This extension is provided as-is. While security best practices have been implemented:

- Always keep your PIN secure and memorable (it cannot be recovered if lost)
- Back up your accounts regularly
- Test restore functionality with non-critical accounts first

## 🐛 Bug Reports

Found a bug? Please open an issue on GitHub with:

- Steps to reproduce
- Expected behavior
- Actual behavior
- Browser version

## 📞 Support

For questions or issues, please open a GitHub issue.

---

Made with ❤️ for secure authentication
