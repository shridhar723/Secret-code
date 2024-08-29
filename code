import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from tkinter import filedialog
import pyperclip
import string
import random
import sqlite3
import cv2
from tkinter import ttk  # Import themed widgets
import qrcode


# Declare root as a global variable
text_box = None
password_box = None
mode_var = None
status_label = None
output_text_box = None


def pad_text(text):
    # Pad the text to be a multiple of 16 bytes using PKCS#7 padding
    pad_length = 16 - (len(text) % 16)
    return text + bytes([pad_length]) * pad_length

def unpad_text(padded_text):
    # Remove PKCS#7 padding
    pad_length = padded_text[-1]
    return padded_text[:-pad_length]

def encrypt_text():
    status_label.config(text="")
    text = text_box.get("1.0", tk.END).strip()
    password = password_box.get().strip()
    mode = mode_var.get()

    if not text or not password:
        status_label.config(text="Please enter text and password.", fg="red")
        return

    try:
        # Encode the text using UTF-8 and pad it
        padded_text = pad(text.encode('utf-8'), AES.block_size)

        # Derive a 32-byte key using PBKDF2 and the provided password
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

        if mode == "CBC":
            # Generate a random IV for CBC mode
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            # Encrypt the text with IV
            encrypted_text = cipher.encrypt(padded_text)
            # Display the IV and encrypted text in the output text box
            output_text_box.delete("1.0", tk.END)
            output_text_box.insert("1.0", (salt + iv + encrypted_text).hex())
        else:
            # Use ECB mode
            cipher = AES.new(key, AES.MODE_ECB)
            # Encrypt the text
            encrypted_text = cipher.encrypt(padded_text)
            # Display the encrypted text in the output text box
            output_text_box.delete("1.0", tk.END)
            output_text_box.insert("1.0", encrypted_text.hex())

        status_label.config(text="Encryption successful. Mode: " + mode, fg="green")

        # Insert encrypted text and password into the database
        conn = sqlite3.connect("encrypted_texts.db")
        conn.execute("INSERT INTO encrypted_texts (encrypted_text, password) VALUES (?, ?)",
                     (encrypted_text.hex(), password))
        conn.commit()
        conn.close()

    except Exception as e:
        status_label.config(text="Encryption failed: " + str(e), fg="red")

def decrypt_text():
    status_label.config(text="")
    encrypted_text = text_box.get("1.0", tk.END).strip()
    password = password_box.get().strip()
    mode = mode_var.get()

    if not encrypted_text or not password:
        status_label.config(text="Please enter encrypted text and password.", fg="red")
        return

    try:
        # Convert the hexadecimal input to bytes
        encrypted_bytes = bytes.fromhex(encrypted_text)

        # Extract the salt, IV, and encrypted text from the input
        salt = encrypted_bytes[:16]
        if mode == "CBC":
            iv = encrypted_bytes[16:32]
            ciphertext = encrypted_bytes[32:]
        else:
            iv = None
            ciphertext = encrypted_bytes

        # Derive a 32-byte key using PBKDF2 and the provided password with the same salt used during encryption
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

        if mode == "CBC":
            # Use AES in CBC mode with the provided IV
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            # Use AES in ECB mode
            cipher = AES.new(key, AES.MODE_ECB)

        # Decrypt the text and remove padding
        decrypted_text = unpad_text(cipher.decrypt(ciphertext))

        # Decode the decrypted text and display it in the output text box
        output_text_box.delete("1.0", tk.END)
        output_text_box.insert("1.0", decrypted_text.decode('utf-8'))

        status_label.config(text="Decryption successful. Mode: " + mode, fg="green")
    except ValueError:
        status_label.config(text="Incorrect password or invalid input. Decryption failed.", fg="red")
        output_text_box.delete("1.0", tk.END)  # Clear the output text box on decryption failure
    except Exception as e:
        status_label.config(text="Decryption failed: " + str(e), fg="red")



def reset_text():
    text_box.delete("1.0", tk.END)
    password_box.delete(0, tk.END)
    output_text_box.delete("1.0", tk.END)
    status_label.config(text="")
    strength_label.config(text="")

def save_text_to_file():
    text = output_text_box.get("1.0", tk.END).strip()
    if not text:
        status_label.config(text="No text to save.", fg="red")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if not file_path:
        return

    try:
        with open(file_path, "w") as file:
            file.write(text)
        status_label.config(text="Text saved to file successfully.", fg="green")
    except Exception as e:
        status_label.config(text="Error while saving the file: " + str(e), fg="red")

def show_saved_texts():
    conn = sqlite3.connect("encrypted_texts.db")
    cursor = conn.execute("SELECT encrypted_text, password FROM encrypted_texts")

    saved_texts = []
    for row in cursor:
        saved_texts.append(f"Encrypted Text: {row[0]}\nPassword: {row[1]}\n{'=' * 30}")

    conn.close()

    saved_text = "\n".join(saved_texts)
    output_text_box.delete("1.0", tk.END)
    output_text_box.insert("1.0", saved_text)

def create_database_table():
    # Connect to the database or create one if it doesn't exist
    conn = sqlite3.connect("encrypted_texts.db")

    # Create a table to store encrypted texts and their passwords
    conn.execute('''CREATE TABLE IF NOT EXISTS encrypted_texts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      encrypted_text TEXT NOT NULL,
                      password TEXT NOT NULL)''')

    # Commit changes and close the connection
    conn.commit()
    conn.close()

def encrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if not file_path:
        return

    password = password_box.get().strip()
    mode = mode_var.get()

    try:
        with open(file_path, "rb") as file:
            plaintext = file.read()

        padded_text = pad(plaintext, AES.block_size)
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

        if mode == "CBC":
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_text = cipher.encrypt(padded_text)
            output_path = file_path + ".encrypted"
        else:
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_text = cipher.encrypt(padded_text)
            output_path = file_path + ".ecb_encrypted"

        with open(output_path, "wb") as output_file:
            output_file.write(salt)
            if mode == "CBC":
                output_file.write(iv)
            output_file.write(encrypted_text)

        status_label.config(text="File encrypted successfully.", fg="green")
    except Exception as e:
        status_label.config(text="Encryption failed: " + str(e), fg="red")

def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.encrypted"), ("ECB Encrypted Files", "*.ecb_encrypted")])
    if not file_path:
        return

    password = password_box.get().strip()
    mode = mode_var.get()

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        salt = encrypted_data[:16]
        if mode == "CBC":
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
        else:
            iv = None
            ciphertext = encrypted_data[16:]

        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

        if mode == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            cipher = AES.new(key, AES.MODE_ECB)

        decrypted_text = unpad_text(cipher.decrypt(ciphertext))

        output_path = file_path + ".decrypted"
        with open(output_path, "wb") as output_file:
            output_file.write(decrypted_text)

        status_label.config(text="File decrypted successfully.", fg="green")
    except ValueError:
        status_label.config(text="Incorrect password or invalid input. Decryption failed.", fg="red")
    except Exception as e:
        status_label.config(text="Decryption failed: " + str(e), fg="red")

def encrypt_image():
    status_label.config(text="")
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg *.png *.bmp")])
    if not file_path:
        return

    password = password_box.get().strip()
    mode = mode_var.get()

    try:
        with open(file_path, "rb") as file:
            image_data = file.read()

        padded_data = pad(image_data, AES.block_size)
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

        if mode == "CBC":
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_data = cipher.encrypt(padded_data)
            output_path = file_path + ".enc"
        else:
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_data = cipher.encrypt(padded_data)
            output_path = file_path + ".ecb_enc"

        with open(output_path, "wb") as output_file:
            output_file.write(salt)
            if mode == "CBC":
                output_file.write(iv)
            output_file.write(encrypted_data)

        status_label.config(text="Image encrypted successfully.", fg="green")
    except Exception as e:
        status_label.config(text="Encryption failed: " + str(e), fg="red")

def decrypt_image():
    status_label.config(text="")
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Image Files", "*.enc *.ecb_enc")])
    if not file_path:
        return

    password = password_box.get().strip()
    mode = mode_var.get()

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        salt = encrypted_data[:16]
        if mode == "CBC":
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
        else:
            iv = None
            ciphertext = encrypted_data[16:]

        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

        if mode == "CBC":
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            cipher = AES.new(key, AES.MODE_ECB)

        decrypted_data = unpad_text(cipher.decrypt(ciphertext))

        output_path = file_path.replace(".enc", "").replace(".ecb_enc", "") + ".decrypted.jpg"
        with open(output_path, "wb") as output_file:
            output_file.write(decrypted_data)

        status_label.config(text="Image decrypted successfully.", fg="green")
    except Exception as e:
        status_label.config(text="Decryption failed: " + str(e), fg="red")
        



def generate_qr_code():
    encrypted_text = output_text_box.get("1.0", tk.END).strip()
    if not encrypted_text:
        status_label.config(text="No encrypted text to generate QR code.", fg="red")
        return

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(encrypted_text)
    qr.make(fit=True)

    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_image.show()

def scan_qr_code():
    capture = cv2.VideoCapture(0)
    ret, frame = capture.read()

    if ret:
        detector = cv2.QRCodeDetector()
        data, points, qr_code = detector.detectAndDecodeMulti(frame)

        if data:
            output_text_box.delete("1.0", tk.END)
            output_text_box.insert("1.0", data)
            status_label.config(text="QR code scanned successfully.", fg="green")
        else:
            status_label.config(text="No QR code detected.", fg="red")

    capture.release()
    cv2.destroyAllWindows()

def create_widgets():
    root = tk.Tk()
    root.title("Text Encryption & Decryption")
    root.geometry("800x600")
    root.configure(bg="#F0F0F0")  # Set background color


    # Create frames
    input_frame = tk.Frame(root, bg="#EFEFEF")
    input_frame.pack(padx=20, pady=20)

    button_frame = tk.Frame(root, bg="#EFEFEF")
    button_frame.pack(padx=20, pady=(0, 20))

    output_frame = tk.Frame(root, bg="#EFEFEF")
    output_frame.pack(padx=20, pady=20)
    
    # Create labels
    label1 = tk.Label(input_frame, text="Enter Text", font=("Helvetica", 14), bg="#EFEFEF")
    label1.grid(row=0, column=0, sticky="w")

    label2 = tk.Label(input_frame, text="Enter Secret Key", font=("Helvetica", 14), bg="#EFEFEF")
    label2.grid(row=1, column=0, sticky="w", pady=(30, 0))

    label3 = tk.Label(input_frame, text="Encryption Mode", font=("Helvetica", 14), bg="#EFEFEF")
    label3.grid(row=2, column=0, sticky="w", pady=(10, 0))

    label4 = tk.Label(output_frame, text="Output", font=("Helvetica", 14), bg="#EFEFEF")
    label4.grid(row=1, column=0, sticky="w", pady=(10, 0))


    # Create text boxes
    text_box = tk.Text(input_frame, height=6, width=40, font=("Courier New", 12))
    text_box.grid(row=0, column=1, columnspan=2, padx=(10, 0))

    password_box = tk.Entry(input_frame, show="*", width=40, font=("Courier New", 12))
    password_box.grid(row=1, column=1, columnspan=2, padx=(10, 0))

    mode_var = tk.StringVar()
    mode_var.set("CBC")
    cbc_radio = ttk.Radiobutton(input_frame, text="CBC", variable=mode_var, value="CBC")
    cbc_radio.grid(row=2, column=1, sticky="w")
    
    # Create buttons with different colors
    encrypt_button = tk.Button(button_frame, text="Encrypt", font=("Helvetica", 12), command=encrypt_text, bg="#4CAF50", fg="white")
    decrypt_button = tk.Button(button_frame, text="Decrypt", font=("Helvetica", 12), command=decrypt_text, bg="#FF5722", fg="white")
    reset_button = tk.Button(button_frame, text="Reset", font=("Helvetica", 12), command=reset_text, bg="#607D8B", fg="white")
    save_button = tk.Button(button_frame, text="Save to File", font=("Helvetica", 12), command=save_text_to_file, bg="#2196F3", fg="white")

    show_saved_button = tk.Button(button_frame, text="Show Saved Texts", font=("Helvetica", 12), command=show_saved_texts, bg="#795548", fg="white")
    encrypt_file_button = tk.Button(button_frame, text="Encrypt File", font=("Helvetica", 12), command=encrypt_file, bg="#E91E63", fg="white")
    decrypt_file_button = tk.Button(button_frame, text="Decrypt File", font=("Helvetica", 12), command=decrypt_file, bg="#3F51B5", fg="white")
    generate_qr_button = tk.Button(button_frame, text="Generate QR Code", font=("Helvetica", 12), command=generate_qr_code, bg="#009688", fg="white")
    scan_qr_button = tk.Button(button_frame, text="Scan QR Code", font=("Helvetica", 12), command=scan_qr_code, bg="#FFC107", fg="white")
    encrypt_image_button = tk.Button(button_frame, text="Encrypt Image", font=("Helvetica", 12), command=encrypt_image, bg="#673AB7", fg="white")
    decrypt_image_button = tk.Button(button_frame, text="Decrypt Image", font=("Helvetica", 12), command=decrypt_image, bg="#00BCD4", fg="white")
    
    
    # Pack buttons
    encrypt_button.pack(side="left", padx=5)
    decrypt_button.pack(side="left", padx=5)
    reset_button.pack(side="left", padx=5)
    save_button.pack(side="left", padx=5)
    show_saved_button.pack(side="left", padx=5)
    encrypt_file_button.pack(side="left", padx=5)
    decrypt_file_button.pack(side="left", padx=5)
    generate_qr_button.pack(side="left", padx=5)
    scan_qr_button.pack(side="left", padx=5)
    encrypt_image_button.pack(side="left", padx=5)
    decrypt_image_button.pack(side="left", padx=5)
   

     # Create a status label
    status_label = tk.Label(button_frame, text="", font=("Helvetica", 12), fg="red", bg="#EFEFEF")
    status_label.pack(anchor="w")

    # Create an output text box
    output_text_box = tk.Text(output_frame, height=8, width=40, font=("Courier New", 12))
    output_text_box.grid(row=0, column=1, columnspan=2, padx=(10, 0))
    

    return (
        root, text_box, password_box, mode_var, status_label, output_text_box, 
    )
    

if __name__ == "__main__":
    create_database_table()

    root, text_box, password_box, mode_var, status_label, output_text_box = create_widgets()
    root.mainloop()
