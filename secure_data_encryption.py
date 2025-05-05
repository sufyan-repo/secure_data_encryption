import streamlit as st
import hashlib 
import json
import os
import time
from cryptography.fernet import Fernet
import base64
from hashlib import pbkdf2_hmac

DATA_FILE = "secure_data.json"
SALT = "secure_salt_value"
LOCKOUT = 60
 
 
# === section login details ===
if "authenticated_user" not in st.session_state: st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state: st.session_state. failed_attempts = 0
if "lockout_time" not in st.session_state: st.session_state.lockout_time=0


#=== if data is load ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f: 
            return json.load(f)
    return {}

def save_data(data):
    with open (DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac ('sha256', passkey.encode(), SALT, 100000) 
    return base64.urlsafe_b64encode(key)

def hash_password (password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex() 

    
#=== cryptography.fernet used === 
def encrypt_text(text, key):
        cipher = Fernet(generate_key (key))
        return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
     try:
        cipher = Fernet(generate_key (key))
        return cipher.decrypt (encrypt_text.encode()).decode() 
     except:
        return None
     
stored_data = load_data()

    
#===navigation bar ===
st.title("Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome To My Data Encryption System Using Streamlit !")
    st.markdown("Develop a Streamlit-based secure data storage and retrieval system where: Users store data with a unique passkey. Users decrypt data by providing the correct passkey. Multiple failed attempts result in a forced reauthorization (login page). The system operates entirely in memory without external databases.")

elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("A User already exists.")
            else:
                stored_data[username] ={
                    "password": hash_password(password),
                    "data":[]
                }
                save_data(stored_data)
                st.success("user register sucessfully!")
            
        else:
            st.error("both fields are required.")
    elif choice == "login":
        st.subheader("user login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f" To many failed  attempts. please wait {remaining} seconds.")
        st.stop()

    username = st.text_iput("username")
    password = st.text_input("password", type="password")



    
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password): 
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f" Welcome {username}!")
    else:
        st.session_state.failed_attempts += 1
        remaining=3-st.session_state.failed_attempts
        st.error(f" X Invalid Credentials! Attempts left: {remaining}") 
        if st.session_state.failed_attempts >= 3:
            st.session_state.lockout_time = time.time() + LOCKOUT
            st.error(" TO many failed attempts. lockout for 60 seconds")
            st.stop()

            # === data store section === 
elif choice == "Store Data":
    if not st.session_state.authenticated_user: 
        st.warning("Please login first.")
    else:
        st.subheader("|Store Encrypted Data")
    data = st.text_area ("Enter data to encrpty")
    passkey = st.text_input("Encryption key (passphrase)", type="password")

    if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and save sucessfully!")

            else:
                st.error("All fields are required to fill")

    # === data retieve data section === 
    elif choice == "Retieve Data":
        if not st.session_state.authenticated_user: 
            st.warning("Please login first")
    else:
        st.subheader("Retieve data")
    user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
    if not user_data:
        st.info("No Data Found!")
    else:
        st.write("Encryted Data Enteries:")
        for i, item in enumerate(user_data):
            st.code(item,language="text")   
    

    encrypted_input = st.text_area("Enter Encrypted text")
    passkey = st.text_input("Enter passkey T Decrypt" , passkey)


    if st.button("Decrypt"):
        result = decrypt_text(encrypted_input , passkey)
        if result:
            st.success(f"Decrypted : {result}")
        else:
            st.error("Incorrect passkey or corrupted data")