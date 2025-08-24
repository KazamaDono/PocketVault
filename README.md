# PocketVault — Portable, multi-factor file locker
A fast, USB-friendly GUI tool for encrypting and decrypting your own files.
Combines a static passcode + ephemeral session/auth code + a Fernet secret.key to ensure only authorized users can decrypt.
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/629a4318-51b4-43ee-aad8-a52146a5cab3" />


## What PocketVault is
PocketVault is a user-focused, portable file locker. It provides:
  - A cross-platform GUI (Tkinter) to encrypt / decrypt folders.
  - A three-factor decryption requirement:
      - Static password (configurable in the app)
      - Auth file (authcode.txt) generated at encryption time
      - secret.key (Fernet key) generated & saved during encryption
  - Progress bar, status updates, and a Complete button to finalize runs.
  - Portable-friendly behavior: keys and auth files are saved next to the executable (works well when run from a USB drive).
  - Safe defaults and explicit confirmations to prevent accidental or unauthorized use.
  > ⚠️ Important: PocketVault is intended for your files only. Never use this tool on systems or files you don't own or have explicit permission to test. Loss of the static password, authcode.txt, or secret.key will make encrypted files unrecoverable.

---

## What PocketVault can do
  - Recursively encrypt every file in a chosen directory (skips secret.key, authcode.txt, and files already encrypted).
  - Recursively decrypt .enc files in a target directory when all three authentication factors are provided.
  - Optionally delete originals after encryption (explicit checkbox—use with care).
  - Save secret.key and authcode.txt to a chosen folder (defaults to locker_keys next to the executable).
  - Run as a standalone executable built with PyInstaller for USB portability.

---

## Quick Demo
1. User chooses Target directory (the folder to encrypt / decrypt).
2. Choose Key save directory (e.g., a folder on your USB) or select an existing secret.key when decrypting.
3. Click Start → authenticate: session code + static password (for encryption) or static password + auth string file + secret.key (for decryption).
4. PocketVault runs in a background thread, shows a progress bar, logs status lines, and enables Complete when finished.
5. Keep secret.key + authcode.txt safe. Without them (or the static password), files are unrecoverable.


https://github.com/user-attachments/assets/719d7e9f-368a-4a46-b3fb-658b2aebecd0

https://github.com/user-attachments/assets/e421a1c1-3402-4ef7-aa5c-0b4eb2f77f8c

---

## Requirements
```bash
cryptography>=41.0.0
pyinstaller>=5.0
```
---

# Thank you for you support!
If there are any bugs or errors, feel free to reach out to me.
