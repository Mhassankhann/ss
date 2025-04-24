import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken

def derive_key(passkey: str) -> bytes:
    sha_hash = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(sha_hash)

def encrypt_text(plain_text: str, passkey: str) -> str:
    key = derive_key(passkey)
    f = Fernet(key)
    encrypted = f.encrypt(plain_text.encode())
    return encrypted.decode()

def decrypt_text(cipher_text: str, passkey: str) -> str:
    key = derive_key(passkey)
    f = Fernet(key)
    decrypted = f.decrypt(cipher_text.encode())
    return decrypted.decode()

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def home_page():
    st.title("Secure Data Storage & Retrieval System")
    st.markdown("""
    - **Insert Data:** Store your data securely with a passkey.
    - **Retrieve Data:** Decrypt your data by providing the correct passkey.
    - **Login:** Reauthorize if you have multiple failed attempts.
    """)
    st.write("Failed decryption attempts:", st.session_state.failed_attempts)
    st.write("Stored data keys:", list(st.session_state.stored_data.keys()))

def insert_data_page():
    st.title("Insert Data")
    data_key = st.text_input("Data Key (unique identifier):")
    plain_text = st.text_area("Text to Store:")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Store Data"):
        if not data_key or not plain_text or not passkey:
            st.error("Please fill in all fields.")
        elif data_key in st.session_state.stored_data:
            st.error("That data key already exists. Choose another one.")
        else:
            try:
                encrypted_text = encrypt_text(plain_text, passkey)
                hashed = hash_passkey(passkey)
                st.session_state.stored_data[data_key] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed
                }
                st.success(f"Data stored successfully under key: {data_key}")
            except Exception as e:
                st.error("Encryption error: " + str(e))

def retrieve_data_page():
    st.title("Retrieve Data")
    if st.session_state.failed_attempts >= 3 and not st.session_state.logged_in:
        st.error("Too many failed attempts. Please reauthorize via the Login page.")
        return

    data_key = st.text_input("Enter Data Key to retrieve:")
    passkey = st.text_input("Enter your Passkey", type="password")

    if st.button("Retrieve Data"):
        if not data_key or not passkey:
            st.error("Please provide both the data key and passkey.")
        elif data_key not in st.session_state.stored_data:
            st.error("Data key not found.")
        else:
            record = st.session_state.stored_data[data_key]
            if hash_passkey(passkey) == record["passkey"]:
                try:
                    decrypted_text = decrypt_text(record["encrypted_text"], passkey)
                    st.success("Data retrieved successfully!")
                    st.write("Decrypted Data:", decrypted_text)
                    reset_failed_attempts()
                except InvalidToken:
                    st.error("Decryption failed. Invalid token.")
                    st.session_state.failed_attempts += 1
            else:
                st.error("Incorrect passkey!")
                st.session_state.failed_attempts += 1
                st.write("Failed attempts:", st.session_state.failed_attempts)
            if st.session_state.failed_attempts >= 3:
                st.error("Three failed attempts. Please reauthorize using the Login page.")

def login_page():
    st.title("Reauthorization / Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin":
            st.session_state.logged_in = True
            reset_failed_attempts()
            st.success("Login successful! You may now retrieve your data.")
        else:
            st.error("Invalid login credentials. Please try again.")

page = st.sidebar.radio("Navigation", ["Home", "Insert Data", "Retrieve Data", "Login"])

if page == "Home":
    home_page()
elif page == "Insert Data":
    insert_data_page()
elif page == "Retrieve Data":
    retrieve_data_page()
elif page == "Login":
    login_page()
