# Capstone-The-Lock-Box

# Cloud Vault Core Tools

Backend scaffold for your Windows desktop password vault (no UI yet).
Includes:
- **Argon2id** KDF (argon2-cffi) to derive a master key from password
- **AES-GCM** for authenticated encryption (cryptography)
- **SQLite** schema + safe PRAGMAs
- CRUD for entries (title/url/username/password/notes)
- Simple CLI demo to init/open vault and add/list entries
- Unit tests (pytest)


## Setup
```bash
# on Windows
python -m venv .venv
.venv\Scripts\activate  
pip install -r requirements.txt

#on macOS 
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python login.py
```
## Project Overview
Desktop UI (PyQt6)

- Master login screen to create or unlock a vault

Main vault window with:

- searchable table of entries

- Add/Edit dialogs with password reveal toggle

- Password Generator (length + symbol options)

- “Copy Password” action with auto-clear clipboard timer

- “Lock” to return to the login screen

- Import Tools

- CSV Import with preview (supports common export formats)

- Options to skip empty passwords and deduplicate entries

- Cloud Sync (File-Based)

- Optional “cloud sync” by copying the vault database into a chosen sync folder (Dropbox/Google Drive/etc.)

Important: this is file-based sync, not a server-based system, and should not be opened on two devices simultaneously.
```
## Notes
- The vault stores a random **vault_key** encrypted ("wrapped") by a master key derived with Argon2id.
- Each sensitive field is encrypted with **fresh nonces** using AES-GCM.
- **No plaintext** is written to disk by this code beyond what you pass on the command line (avoid using `--pw` in real use; supply via prompt).
- Add the Qt UI in Week 5–6 and call these functions from your slots.
- REMINDER login.py and main_window.py are 1 level up in the file tree from the other files, those 2 files sit in the CAPTONE folder and not the cloud_vault
