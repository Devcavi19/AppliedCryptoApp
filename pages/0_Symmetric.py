"""
Symmetric Encryption Page
Implements Caesar Cipher, Vigenère Cipher, and Vernam Cipher (One-Time Pad)
"""

import streamlit as st

# Must be the first Streamlit command
st.set_page_config(
    page_title="Symmetric Encryption",
    page_icon="https://img.icons8.com/?size=100&id=WMWP1MqUZRiS&format=png&color=000000",
)

import os
import sys
import base64

# Add the parent directory to sys.path to allow importing from crypto_algorithms
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the symmetric encryption algorithms
from crypto_algorithms.symmetric import caesar_cipher, vigenere_cipher, vernam_cipher

st.markdown("<h1 style='color: #00ffa2ff;'>Welcome To Symmetric Encryption</h1>", unsafe_allow_html=True)

encryption_type = st.selectbox("Select Encryption Algorithm", ["Caesar Cipher", "Vigenère Cipher", "Vernam Cipher (One-Time Pad)"])

if encryption_type == "Caesar Cipher":
    st.sidebar.subheader(":blue[Description]")
    if st.sidebar.checkbox("Show Description"):
        st.sidebar.write("""
        ### Caesar Cipher:
        The Caesar cipher is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.
        """)
    
    st.sidebar.subheader(":blue[Process]")
    if st.sidebar.checkbox("Show Process"):
        st.sidebar.write("""
        #### Process:
        1. Convert each character of the plaintext to its ASCII value.
        2. Shift the ASCII value by the given key value.
        3. If the ASCII value goes beyond the printable ASCII range, wrap around.
        4. Convert the new ASCII value back to its corresponding character.
        """)

    def encrypt_decrypt_text(text, shift_keys, ifdecrypt):

        result = ""
        
        for n, char in enumerate(text):
            if isinstance(char, int):
                result += chr(char)
            else:
                shift_key = shift_keys[n % len(shift_keys)] 
                if 32 <= ord(char) <= 126:
                    if ifdecrypt:
                        new_char = chr((ord(char) - shift_key - 32 ) % 94 + 32)
                    else:
                        new_char = chr((ord(char) + shift_key - 32 ) % 94 + 32 )
                    result += new_char
                
                else:
                    result += char
        return result

    def encrypt_decrypt_file(file, shift_keys, ifdecrypt):
        result = ""
        file_contents = file.read()
        result = encrypt_decrypt_text(file_contents, shift_keys, ifdecrypt)
        return result

    st.write("## Welcome To Caesar Cipher🔒")
    option = st.radio("Choose what you want to encrypt:", ("Text", "File"))
    text = ""
    file = ""
    if option == "Text":
        text = st.text_area("Plaintext:")
        shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
        if st.button("Encrypt"):
            encrypt = encrypt_decrypt_text(text, shift_keys, ifdecrypt=False)
            decrypt = encrypt_decrypt_text(encrypt, shift_keys, ifdecrypt=True)
            st.write("Encrypted Text:", encrypt)
            st.write("Decrypted text:", decrypt)


    elif option == "File":
        upfile = st.file_uploader("Upload a file")
        if upfile is not None:
            filetype = os.path.splitext(upfile.name)[-1][1:]
            if filetype == "enc":  # If uploaded file is encrypted
                shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
                if st.button("Decrypt"):
                    decrypted_file_contents = encrypt_decrypt_file(upfile, shift_keys, ifdecrypt=True)
                    st.write("File Decrypted")
                    
                    # Get the original file extension
                    original_filename = upfile.name[:-4]
                    st.download_button(
                        label="Download Decrypted File",
                        data=bytes(decrypted_file_contents.encode()),  # No need to convert to bytes
                        file_name=original_filename,
                        mime="application/octet-stream"
                    )
            else:
                shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
                if st.button("Encrypt"):
                    encrypted_file_contents = encrypt_decrypt_file(upfile, shift_keys, ifdecrypt=False)
                    st.write("File Encrypted")
                    
                    # Get the original file extension
                    
                    st.download_button(
                        label="Download Encrypted File",
                        data=bytes(encrypted_file_contents.encode()),
                        file_name=f"{upfile.name}.enc",
                        mime="application/octet-stream"
                    )

elif encryption_type == "Vigenère Cipher":
    st.sidebar.subheader("📘 Vigenère Cipher Description")
    if st.sidebar.checkbox("Show Description"):
        st.sidebar.write("""
        ### Vigenère Cipher:
        The Vigenère cipher is a method of encrypting alphabetic text by using a simple form of 
        polyalphabetic substitution. It uses a keyword to determine different shift values for 
        each position in the text, making it more secure than simple substitution ciphers.
        
        **Security Level:** Low-Medium (stronger than Caesar but still breakable)
        """)
    
    st.sidebar.subheader("🔍 Process")
    if st.sidebar.checkbox("Show Process"):
        st.sidebar.write("""
        #### How It Works:
        1. Choose a keyword.
        2. Repeat the keyword to match the length of the plaintext.
        3. For each letter in the plaintext and its corresponding letter in the repeated keyword:
           - Convert both to their positions in the alphabet (A=0, B=1, etc.)
           - For encryption: add the positions and convert back to a letter.
           - For decryption: subtract the keyword position from the ciphertext position.
           - Apply modular arithmetic to handle wrap-around.
        4. Non-alphabetic characters remain unchanged.
        """)

    st.write("## Vigenère Cipher 🔒")
    option = st.radio("Choose Input Type:", ("Text", "File"), key="vigenere_input_type")

    if option == "Text":
        plaintext = st.text_area("Enter plaintext:", "", key="vigenere_plaintext")
        key = st.text_input("Enter keyword (alphabetic characters only):", "KEY", key="vigenere_key")
        
        if st.button("Process", key="vigenere_process_btn"):
            if plaintext and key:
                try:
                    # Validate the key contains at least one alphabetic character
                    if not any(c.isalpha() for c in key):
                        st.error("Key must contain at least one alphabetic character")
                    else:
                        encrypted = vigenere_cipher.encrypt(plaintext, key)
                        decrypted = vigenere_cipher.decrypt(encrypted, key)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.success("Encrypted Text:")
                            st.code(encrypted)
                        
                        with col2:
                            st.success("Decrypted Text:")
                            st.code(decrypted)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
            else:
                st.warning("Please enter both text and a keyword.")

    elif option == "File":
        uploaded_file = st.file_uploader("Upload a file", type=None, key="vigenere_file_upload")
        key = st.text_input("Enter keyword (alphabetic characters only):", "KEY", key="vigenere_file_key")
        
        if uploaded_file is not None and key:
            file_content = uploaded_file.read()
            file_name = uploaded_file.name
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Encrypt File", key="vigenere_encrypt_file_btn"):
                    try:
                        # Validate the key contains at least one alphabetic character
                        if not any(c.isalpha() for c in key):
                            st.error("Key must contain at least one alphabetic character")
                        else:
                            encrypted_content = vigenere_cipher.encrypt_file(file_content, key)
                            
                            st.success("File encrypted successfully!")
                            st.download_button(
                                label="Download Encrypted File",
                                data=encrypted_content,
                                file_name=f"{file_name}.encrypted",
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error encrypting file: {str(e)}")
            
            with col2:
                if st.button("Decrypt File", key="vigenere_decrypt_file_btn"):
                    try:
                        # Validate the key contains at least one alphabetic character
                        if not any(c.isalpha() for c in key):
                            st.error("Key must contain at least one alphabetic character")
                        else:
                            decrypted_content = vigenere_cipher.decrypt_file(file_content, key)
                            
                            st.success("File decrypted successfully!")
                            st.download_button(
                                label="Download Decrypted File",
                                data=decrypted_content,
                                file_name=f"{file_name}.decrypted",
                                mime="application/octet-stream"
                            )
                    except Exception as e:
                        st.error(f"Error decrypting file: {str(e)}")

elif encryption_type == "Vernam Cipher (One-Time Pad)":
    # Helper functions for Vernam cipher
    def show_vernam_results(ciphertext, used_key):
        """Display Vernam cipher encryption results"""
        st.success("Encryption Successful!")
        
        st.subheader("Key (Base64 encoded):")
        key_b64 = base64.b64encode(used_key).decode('utf-8')
        st.code(key_b64)
        
        st.subheader("Ciphertext (Base64 encoded):")
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        st.code(ciphertext_b64)
        
        # Create download buttons for the key and ciphertext
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="Download Key",
                data=used_key,
                file_name="vernam_key.bin",
                mime="application/octet-stream"
            )
        with col2:
            st.download_button(
                label="Download Ciphertext",
                data=ciphertext,
                file_name="vernam_ciphertext.bin",
                mime="application/octet-stream"
            )

    def show_vernam_file_results(encrypted_content, used_key, file_name):
        """Display Vernam cipher file encryption results"""
        st.success("File encrypted successfully!")
        
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="Download Encrypted File",
                data=encrypted_content,
                file_name=f"{file_name}.encrypted",
                mime="application/octet-stream"
            )
        with col2:
            st.download_button(
                label="Download Key",
                data=used_key,
                file_name=f"{file_name}.key",
                mime="application/octet-stream"
            )
    
    st.sidebar.subheader("📘 Vernam Cipher Description")
    if st.sidebar.checkbox("Show Description", key="vernam_desc_check"):
        st.sidebar.write("""
        ### Vernam Cipher (One-Time Pad):
        The Vernam Cipher, also known as the One-Time Pad, is a theoretically unbreakable 
        encryption method when used correctly. It requires a truly random key that is at least 
        as long as the plaintext and is used only once.
        
        **Security Level:** Very High (theoretically unbreakable when used properly)
        """)
    
    st.sidebar.subheader("🔍 Process")
    if st.sidebar.checkbox("Show Process", key="vernam_process_check"):
        st.sidebar.write("""
        #### How It Works:
        1. Generate a truly random key (one-time pad) that is the same length as the plaintext.
        2. Convert both the plaintext and the key to their binary or numerical representations.
        3. Apply a bitwise XOR operation between each plaintext bit and its corresponding key bit.
        4. The result is the ciphertext. To decrypt, XOR the ciphertext with the same key.
        
        **Important**: The key should be used only once and securely destroyed after use.
        """)

    st.write("## Vernam Cipher (One-Time Pad) 🔒")
    option = st.radio("Choose Input Type:", ("Text", "File"), key="vernam_input_type")

    if option == "Text":
        plaintext = st.text_area("Enter plaintext:", "", key="vernam_plaintext")
        use_random_key = st.checkbox("Generate random key", value=True, key="vernam_random_key_check")
        
        if not use_random_key:
            key = st.text_area("Enter key (must be at least as long as the plaintext):", "", key="vernam_key_input")
        else:
            key = None
        
        if st.button("Encrypt", key="vernam_encrypt_btn"):
            if plaintext:
                try:
                    if not use_random_key and key:
                        key_bytes = key.encode('utf-8')
                        if len(key_bytes) < len(plaintext.encode('utf-8')):
                            st.error("Key must be at least as long as the plaintext.")
                        else:
                            ciphertext, used_key = vernam_cipher.encrypt_text(plaintext, key_bytes)
                            show_vernam_results(ciphertext, used_key)
                    else:
                        ciphertext, used_key = vernam_cipher.encrypt_text(plaintext)
                        show_vernam_results(ciphertext, used_key)
                except Exception as e:
                    st.error(f"Error during encryption: {str(e)}")
            else:
                st.warning("Please enter text to encrypt.")
        
        with st.expander("Decrypt Text"):
            encrypted_text = st.text_area("Enter Base64-encoded encrypted text:", "", key="vernam_encrypted_text")
            key_text = st.text_area("Enter Base64-encoded key:", "", key="vernam_decrypt_key")
            
            if st.button("Decrypt", key="vernam_decrypt_btn"):
                if encrypted_text and key_text:
                    try:
                        # Decode base64 inputs
                        try:
                            ciphertext_bytes = base64.b64decode(encrypted_text)
                            key_bytes = base64.b64decode(key_text)
                        except Exception:
                            st.error("Invalid Base64 encoding in the input.")
                            st.stop()
                        
                        # Ensure key is long enough
                        if len(key_bytes) < len(ciphertext_bytes):
                            st.error("Key must be at least as long as the ciphertext.")
                        else:
                            try:
                                decrypted_text = vernam_cipher.decrypt_text(ciphertext_bytes, key_bytes)
                                st.success("Decryption Successful!")
                                st.code(decrypted_text)
                            except Exception as e:
                                st.error(f"Error during decryption: {str(e)}")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
                else:
                    st.warning("Please enter both encrypted text and key.")

    elif option == "File":
        uploaded_file = st.file_uploader("Upload a file to encrypt/decrypt", type=None, key="vernam_file_upload")
        
        if uploaded_file is not None:
            file_content = uploaded_file.read()
            file_name = uploaded_file.name
            
            tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])
            
            with tab1:
                use_random_key = st.checkbox("Generate random key", value=True, key="vernam_file_random_key")
                
                if not use_random_key:
                    uploaded_key = st.file_uploader("Upload key file (must be at least as long as the input file)", key="vernam_key_upload")
                
                if st.button("Encrypt File", key="vernam_encrypt_file_btn"):
                    try:
                        if not use_random_key:
                            if uploaded_key is None:
                                st.error("Please upload a key file or choose to generate a random key.")
                            else:
                                key_data = uploaded_key.read()
                                if len(key_data) < len(file_content):
                                    st.error("Key file must be at least as long as the input file.")
                                else:
                                    encrypted_content, used_key = vernam_cipher.encrypt_file(file_content, key_data)
                                    show_vernam_file_results(encrypted_content, used_key, file_name)
                        else:
                            encrypted_content, used_key = vernam_cipher.encrypt_file(file_content)
                            show_vernam_file_results(encrypted_content, used_key, file_name)
                    except Exception as e:
                        st.error(f"Error during file encryption: {str(e)}")
            
            with tab2:
                uploaded_key = st.file_uploader("Upload key file", key="vernam_decrypt_key_upload")
                
                if st.button("Decrypt File", key="vernam_decrypt_file_btn") and uploaded_key is not None:
                    try:
                        key_data = uploaded_key.read()
                        
                        if len(key_data) < len(file_content):
                            st.error("Key file must be at least as long as the encrypted file.")
                            st.stop()
                            
                        decrypted_content = vernam_cipher.decrypt_file(file_content, key_data)
                        
                        st.success("File decrypted successfully!")
                        st.download_button(
                            label="Download Decrypted File",
                            data=decrypted_content,
                            file_name=f"{os.path.splitext(file_name)[0]}.decrypted",
                            mime="application/octet-stream"
                        )
                    except Exception as e:
                        st.error(f"Error during file decryption: {str(e)}")
