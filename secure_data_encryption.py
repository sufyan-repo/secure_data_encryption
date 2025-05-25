import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
import base64
from hashlib import pbkdf2_hmac

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT = 60

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return base64.urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

st.title("Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome")
    st.markdown("A secure data encryption and decryption system built with Streamlit.")

elif choice == "Register":
    st.subheader("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("Registration successful.")
        else:
            st.error("All fields are required.")

elif choice == "Login":
    st.subheader("Login")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome {username}")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"Invalid credentials. Attempts left: {remaining}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT
                st.error("Too many failed attempts.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Data")
        passkey = st.text_input("Passkey", type="password")
        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data saved.")
            else:
                st.error("All fields are required.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        if not user_data:
            st.info("No data found.")
        else:
            for i, item in enumerate(user_data):
                st.code(item)

        encrypted_input = st.text_area("Encrypted Text")
        decrypt_passkey = st.text_input("Passkey", type="password")
        if st.button("Decrypt"):
            result = decrypt_text(encrypted_input, decrypt_passkey)
            if result:
                st.success(f"Decrypted: {result}")
            else:
                st.error("Incorrect passkey or invalid data.")
