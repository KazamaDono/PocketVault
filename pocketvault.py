import os
import sys
import threading
import random
import string
from tkinter import Tk, StringVar, BooleanVar, filedialog, messagebox
import tkinter.simpledialog as simpledialog
from tkinter import Label, Button, Entry, Checkbutton
from tkinter.ttk import Progressbar, Frame
from cryptography.fernet import Fernet

# -------------------------------
# Config / Constants
# -------------------------------
STATIC_PASSWORD = "1234"   # change this if you want a different static password
SESSION_CODE_LEN = 6       # for encryption session code
AUTHCODE_LEN = 10          # auth string saved in authcode.txt for decryption
# -------------------------------

# -------------------------------
# Helper: locate base dir (for portability)
# -------------------------------
def get_app_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_app_base_dir()
DEFAULT_KEY_FOLDER = os.path.join(BASE_DIR, "locker_keys")
os.makedirs(DEFAULT_KEY_FOLDER, exist_ok=True)

# -------------------------------
# Utility functions (safe)
# -------------------------------
def generate_key_bytes():
    return Fernet.generate_key()

def save_key_to_path(key_bytes, dest_folder):
    os.makedirs(dest_folder, exist_ok=True)
    key_path = os.path.join(dest_folder, "secret.key")
    with open(key_path, "wb") as f:
        f.write(key_bytes)
    return key_path

def load_key_from_file(key_file_path):
    with open(key_file_path, "rb") as f:
        return f.read()

def generate_authcode(save_dir):
    os.makedirs(save_dir, exist_ok=True)
    auth_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=AUTHCODE_LEN))
    auth_path = os.path.join(save_dir, "authcode.txt")
    with open(auth_path, "w") as f:
        f.write(auth_str)
    return auth_str, auth_path

def load_authcode(auth_path):
    if not os.path.isfile(auth_path):
        raise FileNotFoundError("authcode.txt not found")
    with open(auth_path, "r") as f:
        return f.read().strip()

def files_to_encrypt(target_dir):
    items = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            if fname == "secret.key" or fname == "authcode.txt" or fname.endswith(".enc"):
                continue
            items.append(os.path.join(root, fname))
    return items

def files_to_decrypt(target_dir):
    items = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            if fname.endswith(".enc"):
                items.append(os.path.join(root, fname))
    return items

# -------------------------------
# Worker functions (run in thread)
# Each accepts a finish_callback to notify GUI when done.
# -------------------------------
def encrypt_worker(target_dir, save_key_dir, delete_original, progress_callback, status_callback, finish_callback):
    try:
        # generate key and save
        key = generate_key_bytes()
        key_path = save_key_to_path(key, save_key_dir)
        fernet = Fernet(key)

        status_callback(f"Key saved to: {key_path}")

        items = files_to_encrypt(target_dir)
        total = len(items)
        if total == 0:
            status_callback("No files to encrypt in selected directory.")
            progress_callback(0, 0)
            return

        status_callback(f"Encrypting {total} files...")
        for i, filepath in enumerate(items, start=1):
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                enc = fernet.encrypt(data)
                enc_path = filepath + ".enc"
                with open(enc_path, "wb") as ef:
                    ef.write(enc)
                if delete_original:
                    try:
                        os.remove(filepath)
                    except Exception as e:
                        status_callback(f"Warning: couldn't remove original: {filepath} ({e})")
                status_callback(f"Encrypted: {os.path.basename(filepath)}")
            except Exception as e:
                status_callback(f"Failed: {os.path.basename(filepath)} — {e}")
            progress_callback(i, total)

        status_callback("Encryption complete.")
    except Exception as e:
        status_callback(f"Error during encryption: {e}")
        progress_callback(0, 0)
    finally:
        try:
            finish_callback()
        except Exception:
            pass

def decrypt_worker(target_dir, key_path, progress_callback, status_callback, finish_callback):
    try:
        key = load_key_from_file(key_path)
        fernet = Fernet(key)

        items = files_to_decrypt(target_dir)
        total = len(items)
        if total == 0:
            status_callback("No .enc files found to decrypt.")
            progress_callback(0, 0)
            return

        status_callback(f"Decrypting {total} files...")
        for i, enc_path in enumerate(items, start=1):
            try:
                with open(enc_path, "rb") as ef:
                    data = ef.read()
                dec = fernet.decrypt(data)
                orig = enc_path[:-4]  # remove .enc
                with open(orig, "wb") as of:
                    of.write(dec)
                try:
                    os.remove(enc_path)
                except Exception as e:
                    status_callback(f"Warning: couldn't remove {enc_path} ({e})")
                status_callback(f"Decrypted: {os.path.basename(orig)}")
            except Exception as e:
                status_callback(f"Failed to decrypt {os.path.basename(enc_path)} — {e}")
            progress_callback(i, total)

        status_callback("Decryption complete.")
    except Exception as e:
        status_callback(f"Error during decryption: {e}")
        progress_callback(0, 0)
    finally:
        try:
            finish_callback()
        except Exception:
            pass

# -------------------------------
# GUI
# -------------------------------
class FileLockerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Pocket Vault - Personal File Locker")
        root.geometry("600x380")
        root.resizable(False, False)

        # Variables
        self.mode = StringVar(value="encrypt")  # "encrypt" or "decrypt"
        self.target_dir = StringVar()
        self.key_save_dir = StringVar(value=DEFAULT_KEY_FOLDER)
        self.key_file = StringVar()
        self.delete_original = BooleanVar(value=False)
        self._worker_thread = None

        # Layout
        Label(root, text="Target directory:").pack(anchor="w", padx=12, pady=(12,0))
        self.target_entry = Entry(root, textvariable=self.target_dir, width=80)
        self.target_entry.pack(anchor="w", padx=12)
        Button(root, text="Choose Folder", command=self.choose_target).pack(anchor="w", padx=12, pady=(6,8))

        Label(root, text="Mode:").pack(anchor="w", padx=12)
        frame = Frame(root)
        frame.pack(anchor="w", padx=12)
        Button(frame, text="Encrypt", command=lambda: self.set_mode("encrypt")).grid(row=0, column=0, padx=6)
        Button(frame, text="Decrypt", command=lambda: self.set_mode("decrypt")).grid(row=0, column=1)

        Label(root, text="Key save directory / Key file:").pack(anchor="w", padx=12, pady=(8,0))
        self.key_entry = Entry(root, textvariable=self.key_save_dir, width=80)
        self.key_entry.pack(anchor="w", padx=12)
        Button(root, text="Choose Key Folder / File", command=self.choose_key_path).pack(anchor="w", padx=12, pady=(6,8))

        self.delete_chk = Checkbutton(root, text="Delete originals after encrypting (use with caution)", variable=self.delete_original)
        self.delete_chk.pack(anchor="w", padx=12)

        # Progress and status
        self.progress = Progressbar(root, orient="horizontal", length=560, mode="determinate")
        self.progress.pack(padx=12, pady=(10,4))
        self.status_label = Label(root, text="Ready.", anchor="w")
        self.status_label.pack(fill="x", padx=12)

        # Action buttons
        btn_frame = Frame(root)
        btn_frame.pack(pady=10)

        self.start_button = Button(btn_frame, text="Start", command=self.start_action, width=12)
        self.start_button.grid(row=0, column=0, padx=6)

        self.complete_btn = Button(btn_frame, text="Complete", command=self.complete_action, width=12, state="disabled")
        self.complete_btn.grid(row=0, column=1, padx=6)

        self.exit_button = Button(btn_frame, text="Stop (exit)", command=root.quit, width=12)
        self.exit_button.grid(row=0, column=2, padx=6)

    def set_mode(self, m):
        self.mode.set(m)
        self.status_label.config(text=f"Mode set to: {m}")

    def choose_target(self):
        d = filedialog.askdirectory()
        if d:
            self.target_dir.set(d)

    def choose_key_path(self):
        # choose a directory for encryption key or a file for decryption
        if self.mode.get() == "encrypt":
            d = filedialog.askdirectory(title="Choose folder to save secret.key (e.g. on your USB)")
            if d:
                self.key_save_dir.set(d)
        else:
            f = filedialog.askopenfilename(title="Select secret.key file", filetypes=[("Key files", "secret.key"), ("All files","*.*")])
            if f:
                self.key_save_dir.set(os.path.dirname(f))
                self.key_file.set(f)

    def progress_callback(self, current, total):
        def _update():
            if total == 0:
                self.progress['value'] = 0
                return
            pct = (current / total) * 100
            self.progress['value'] = pct
        self.root.after(0, _update)

    def status_callback(self, text):
        def _update():
            self.status_label.config(text=text)
        self.root.after(0, _update)

    def on_worker_finish(self):
        def _enable_complete():
            self.complete_btn.config(state="normal")
            self.start_button.config(state="normal")
            self.status_label.config(text="Operation finished. Click 'Complete' to finalize.")
        self.root.after(0, _enable_complete)

    # Authentication helpers (main thread)
    def prompt_session_and_static(self):
        # For encryption: session code + static password
        session_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=SESSION_CODE_LEN))
        messagebox.showinfo("Session Code", f"Your session code is:\n\n{session_code}\n\nYou must enter this to continue.")
        user_code = simpledialog.askstring("Enter Session Code", "Enter the session code shown above:")
        user_pass = simpledialog.askstring("Enter Password", "Enter the static password:", show="*")
        if user_code == session_code and user_pass == STATIC_PASSWORD:
            return True
        else:
            messagebox.showerror("Authentication Failed", "Incorrect session code or password. Operation cancelled.")
            return False

    def prompt_static_and_authfile(self, key_path):
        # For decryption: static password + auth string read from authcode.txt
        user_pass = simpledialog.askstring("Enter Password", "Enter the static password:", show="*")
        if user_pass != STATIC_PASSWORD:
            messagebox.showerror("Authentication Failed", "Incorrect static password. Operation cancelled.")
            return False

        auth_path = os.path.join(os.path.dirname(key_path), "authcode.txt")
        try:
            required_auth = load_authcode(auth_path)
        except Exception as e:
            messagebox.showerror("Authentication Failed", f"Auth file error: {e}")
            return False

        user_auth = simpledialog.askstring("Enter Auth String", "Enter the auth string from authcode.txt:")
        if user_auth != required_auth:
            messagebox.showerror("Authentication Failed", "Incorrect auth string. Operation cancelled.")
            return False

        # both checks passed
        return True

    def start_action(self):
        target = self.target_dir.get().strip()
        if not target or not os.path.isdir(target):
            messagebox.showerror("Invalid target", "Please select a valid target directory.")
            return

        self.start_button.config(state="disabled")
        self.complete_btn.config(state="disabled")

        if self.mode.get() == "encrypt":
            save_dir = self.key_save_dir.get().strip()
            if not save_dir:
                save_dir = DEFAULT_KEY_FOLDER
                self.key_save_dir.set(save_dir)
            if not os.path.isdir(save_dir):
                try:
                    os.makedirs(save_dir, exist_ok=True)
                except Exception:
                    messagebox.showerror("Invalid key location", "Please choose a valid folder to save the secret.key (e.g. folder on your USB).")
                    self.start_button.config(state="normal")
                    return

            # Ask session code + static password before proceeding
            if not self.prompt_session_and_static():
                self.start_button.config(state="normal")
                return

            # Generate authcode (saved in same folder as secret.key will be)
            auth_str, auth_path = generate_authcode(save_dir)
            messagebox.showinfo("Auth String Generated", f"An auth string has been created and saved to:\n\n{auth_path}\n\nAuth string:\n\n{auth_str}\n\nKeep this file and the secret.key to allow decryption later.")
            self.status_callback(f"Auth saved to: {auth_path}")

            # Confirm encryption
            confirm = messagebox.askyesno(
                "Confirm encryption",
                "Encryption will process all files inside the chosen folder (recursively).\n"
                "You will lose access to files unless you keep both the secret.key and authcode.txt and remember the static password.\n\n"
                "Proceed only if these are your files or you have permission.\n\n"
                "Are you sure you want to continue?"
            )
            if not confirm:
                # cleanup: remove auth file that was just created to avoid confusion
                try:
                    os.remove(auth_path)
                except Exception:
                    pass
                self.start_button.config(state="normal")
                return

            delete_original = self.delete_original.get()
            # start encryption worker
            self._worker_thread = threading.Thread(
                target=encrypt_worker,
                args=(target, save_dir, delete_original, self.progress_callback, self.status_callback, self.on_worker_finish),
                daemon=True
            )
            self._worker_thread.start()

        else:  # decrypt
            key_file = self.key_file.get().strip()
            if not key_file:
                folder = self.key_save_dir.get().strip()
                if folder and os.path.isfile(os.path.join(folder, "secret.key")):
                    key_file = os.path.join(folder, "secret.key")
                else:
                    messagebox.showerror("Key file missing", "Please select the secret.key file used to encrypt these files.")
                    self.start_button.config(state="normal")
                    return

            if not os.path.isfile(key_file):
                messagebox.showerror("Key file missing", "Selected key file does not exist.")
                self.start_button.config(state="normal")
                return

            # Run the 3-factor auth checks (static password + auth string file)
            if not self.prompt_static_and_authfile(key_file):
                self.start_button.config(state="normal")
                return

            confirm = messagebox.askyesno(
                "Confirm decryption",
                "Decryption will restore files encrypted with the matching secret.key.\n\nProceed?"
            )
            if not confirm:
                self.start_button.config(state="normal")
                return

            # start decryption worker
            self._worker_thread = threading.Thread(
                target=decrypt_worker,
                args=(target, key_file, self.progress_callback, self.status_callback, self.on_worker_finish),
                daemon=True
            )
            self._worker_thread.start()

    def complete_action(self):
        messagebox.showinfo("Complete", "Operation finalized. You can now choose another folder or exit.")
        self.progress['value'] = 0
        self.complete_btn.config(state="disabled")
        self.status_label.config(text="Ready.")
        # optionally clear fields:
        # self.target_dir.set("")
        # self.key_save_dir.set(DEFAULT_KEY_FOLDER)
        # self.key_file.set("")

if __name__ == "__main__":
    root = Tk()
    app = FileLockerGUI(root)
    root.mainloop()
