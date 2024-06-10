import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, scrolledtext, Listbox, MULTIPLE
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import os
import matlab.engine
import random

# Function to generate seed using MATLAB script
def generate_seed_with_matlab(folder_path):
    eng = matlab.engine.start_matlab()
    seed = eng.generate_seed(folder_path)
    eng.quit()
    return int(seed)

# Function to generate a new pair of RSA keys (private and public) using a seed
def generate_keys_with_seed(seed):
    random.seed(seed)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save the private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

# Function to load RSA keys from files or generate new ones using MATLAB
def load_keys():
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return private_key, public_key
    else:
        # If keys do not exist, generate new keys using MATLAB
        seed = generate_seed_with_matlab('daisy')  # Change 'daisy' to your folder path
        return generate_keys_with_seed(seed)

# Function to add selected files to the listbox
def add_files():
    file_paths = filedialog.askopenfilenames()  # Allow multiple file selection
    for file_path in file_paths:
        file_listbox.insert(tk.END, file_path)

# Function to remove selected files from the listbox
def remove_selected_files():
    selected_indices = file_listbox.curselection()
    for index in reversed(selected_indices):
        file_listbox.delete(index)

# Function to sign selected files with the private key
def sign_files(private_key):
    selected_files = file_listbox.get(0, tk.END)
    if not selected_files:
        messagebox.showerror("Error", "No files selected.")
        return

    for file_path in selected_files:
        with open(file_path, 'rb') as f:
            file_data = f.read()

        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(file_data)
        hash_data = digest.finalize()

        signature = private_key.sign(
            hash_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA3_256()
        )

        signature_hex = signature.hex()
        signature_filename = file_path + '.sig'
        with open(signature_filename, 'w') as f:  # Save as hex
            f.write(signature_hex)

        signature_info.set("Signature saved as: " + signature_filename)
        signature_display.delete('1.0', tk.END)
        signature_display.insert(tk.END, signature_hex)
    
    messagebox.showinfo("Success", "Files signed successfully.")

# Function to verify the signature of any file with the public key
def verify_file_signature(public_key):
    file_path = filedialog.askopenfilename()  # Allow file selection
    if not file_path:
        return

    signature_path = file_path + '.sig'
    if not os.path.exists(signature_path):
        messagebox.showerror("Error", "Signature file not found.")
        verification_info.set("Signature file not found.")
        return

    with open(file_path, 'rb') as f:
        file_data = f.read()

    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(file_data)
    hash_data = digest.finalize()

    with open(signature_path, 'r') as f:
        signature_hex = f.read()

    verify_signature_display.delete('1.0', tk.END)
    verify_signature_display.insert(tk.END, signature_hex)

    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        messagebox.showerror("Verification", "Signature format is invalid.")
        verification_info.set("Signature format is invalid.")
        return

    try:
        public_key.verify(
            signature,
            hash_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA3_256()
        )
        messagebox.showinfo("Verification", "Signature is valid.")
        verification_info.set("Signature is valid.")
    except Exception as e:
        messagebox.showerror("Verification", "Signature is invalid.")
        verification_info.set("Signature is invalid.")

# GUI Setup
root = tk.Tk()
root.title("Digital Signature Tool")

private_key, public_key = load_keys()

tab_control = ttk.Notebook(root)
tab1 = ttk.Frame(tab_control)
tab2 = ttk.Frame(tab_control)

tab_control.add(tab1, text='Sign File')
tab_control.add(tab2, text='Verify Signature')
tab_control.pack(expand=1, fill='both')

# Tab 1: Sign File
sign_instructions = tk.Label(tab1, text="Select files to sign:")
sign_instructions.pack(pady=10)

add_files_button = tk.Button(tab1, text="Add Files", command=add_files)
add_files_button.pack(pady=5)

file_listbox = Listbox(tab1, selectmode=MULTIPLE)
file_listbox.pack(pady=5, fill=tk.BOTH, expand=True)

remove_files_button = tk.Button(tab1, text="Remove Selected Files", command=remove_selected_files)
remove_files_button.pack(pady=5)

sign_files_button = tk.Button(tab1, text="Sign Files", command=lambda: sign_files(private_key))
sign_files_button.pack(pady=5)

signature_info = tk.StringVar()
signature_info_label = tk.Label(tab1, textvariable=signature_info)
signature_info_label.pack(pady=10)

key_preview_label = tk.Label(tab1, text="Podgląd Klucza:")
key_preview_label.pack(pady=5)

signature_display = scrolledtext.ScrolledText(tab1, height=10, width=50)
signature_display.pack(pady=10)

# Tab 2: Verify Signature
verify_instructions = tk.Label(tab2, text="Select a file to verify:")
verify_instructions.pack(pady=10)

select_verify_file_button = tk.Button(tab2, text="Select File", command=lambda: verify_file_signature(public_key))
select_verify_file_button.pack(pady=5)

verification_info = tk.StringVar()
verification_info_label = tk.Label(tab2, textvariable=verification_info)
verification_info_label.pack(pady=10)

signature_preview_label = tk.Label(tab2, text="Podgląd Podpisu:")
signature_preview_label.pack(pady=5)

verify_signature_display = scrolledtext.ScrolledText(tab2, height=10, width=50)
verify_signature_display.pack(pady=10)

root.mainloop()
