"""
Asymmetric Encryption Page
Implements RSA and Diffie-Hellman key exchange
"""

import streamlit as st
import os
import sys
import base64
import time
import json
import random
import importlib
import secrets
import hashlib
import math
from math import gcd

# Must be the first Streamlit command
st.set_page_config(
    page_title="Asymmetric Encryption",
    page_icon="https://img.icons8.com/?size=100&id=WMWP1MqUZRiS&format=png&color=000000",
)

# Helper function for RSA demo to calculate modular inverse
def modinv(a, m):
    """Calculate the modular inverse of a % m, which is
    the number x such that a*x % m = 1"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find gcd and coefficients"""
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

# Add the parent directory to sys.path to allow importing from crypto_algorithms
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the asymmetric encryption algorithms
from crypto_algorithms.asymmetric.diffie_hellman import (
    DiffieHellman, simple_diffie_hellman, 
    encrypt_with_derived_key, decrypt_with_derived_key
)
from crypto_algorithms.asymmetric.rsa_algorithm import (
    RSA, generate_key_pair, encrypt_with_public_key, 
    decrypt_with_private_key
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

st.markdown("<h1 style='color: #00ffa2ff;'>Asymmetric Encryption</h1>", unsafe_allow_html=True)
st.write("""
Asymmetric encryption uses a pair of keys: a public key for encryption and a private key for decryption. 
This allows secure communication without needing to share secret keys in advance.
""")

encryption_type = st.selectbox("Select Encryption Algorithm", ["RSA", "Diffie-Hellman Key Exchange"])

# Sidebar information
st.sidebar.subheader(":blue[Description]")
if st.sidebar.checkbox("Show Description"):
    if encryption_type == "RSA":
        st.sidebar.write("""
        ### RSA Algorithm:
        RSA (Rivest–Shamir–Adleman) is an asymmetric encryption algorithm widely used for secure data transmission. 
        It is based on the practical difficulty of factoring the product of two large prime numbers.
        
        **Security Level:** High (with proper key size)
        
        **Key Features:**
        - Uses a public key for encryption and a private key for decryption
        - Mathematical security based on the difficulty of factoring large numbers
        - Widely adopted in secure communications and digital signatures
        """)
    else:  # Diffie-Hellman
        st.sidebar.write("""
        ### Diffie-Hellman Key Exchange:
        Diffie-Hellman is a method for securely exchanging cryptographic keys over a public channel without requiring 
        a pre-shared secret. It allows two parties to jointly establish a shared secret over an insecure communications channel.
        
        **Security Level:** High (with proper parameters)
        
        **Key Features:**
        - Allows secure key establishment over insecure channels
        - Mathematical security based on the discrete logarithm problem
        - Foundation for many modern secure communications systems
        - Not an encryption algorithm itself, but enables secure symmetric encryption
        """)

st.sidebar.subheader(":blue[Process]")
if st.sidebar.checkbox("Show Process"):
    if encryption_type == "RSA":
        st.sidebar.write("""
        #### RSA Process:
        1. **Key Generation:**
           - Generate two large prime numbers, p and q
           - Calculate n = p × q
           - Calculate φ(n) = (p-1) × (q-1)
           - Choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
           - Calculate d where d × e ≡ 1 (mod φ(n))
           - Public key: (n, e), Private key: (n, d)
        
        2. **Encryption:**
           - Convert the plaintext to a number m
           - Compute ciphertext c = m^e mod n
        
        3. **Decryption:**
           - Compute plaintext m = c^d mod n
        """)
    else:  # Diffie-Hellman
        st.sidebar.write("""
        #### Diffie-Hellman Process:
        1. **Parameter Setup:**
           - Choose a large prime number p and a generator g
        
        2. **Key Exchange:**
           - Alice chooses a private key a and computes public key A = g^a mod p
           - Bob chooses a private key b and computes public key B = g^b mod p
           - Alice and Bob exchange their public keys A and B
        
        3. **Shared Secret Calculation:**
           - Alice computes the shared secret s = B^a mod p
           - Bob computes the shared secret s = A^b mod p
           - Both Alice and Bob now have the same shared secret s
        
        4. **Secure Communication:**
           - The shared secret is used as a key for symmetric encryption
        """)

if encryption_type == "Diffie-Hellman Key Exchange":
    st.write("## Diffie-Hellman Key Exchange")
    
    tabs = st.tabs(["Basic Demo", "Encrypt", "Decrypt"])
    
    with tabs[0]:
        st.write("### Interactive Diffie-Hellman Demonstration")
        st.write("""
        This demonstration shows how Alice and Bob can establish a shared secret key over an insecure channel.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Step 1: Public Parameters")
            prime = st.number_input("Prime Number (p)", min_value=5, value=23)
            generator = st.number_input("Generator (g)", min_value=2, max_value=prime-1, value=5)
            
            st.info(f"Alice and Bob agree on public parameters p={prime} and g={generator}")
        
        with col2:
            st.subheader("Step 2: Private Keys")
            alice_private = st.number_input("Alice's Private Key", min_value=1, max_value=prime-1, value=6)
            bob_private = st.number_input("Bob's Private Key", min_value=1, max_value=prime-1, value=15)
            
            st.info("These private keys are kept secret")
        
        # Calculate public keys
        alice_public = pow(generator, alice_private, prime)
        bob_public = pow(generator, bob_private, prime)
        
        st.subheader("Step 3: Public Key Exchange")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"Alice's Public Key: A = g^a mod p = {generator}^{alice_private} mod {prime} = {alice_public}")
        with col2:
            st.write(f"Bob's Public Key: B = g^b mod p = {generator}^{bob_private} mod {prime} = {bob_public}")
        
        # Calculate shared secrets
        alice_shared = pow(bob_public, alice_private, prime)
        bob_shared = pow(alice_public, bob_private, prime)
        
        st.subheader("Step 4: Shared Secret Calculation")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"Alice calculates: B^a mod p = {bob_public}^{alice_private} mod {prime} = {alice_shared}")
        with col2:
            st.write(f"Bob calculates: A^b mod p = {alice_public}^{bob_private} mod {prime} = {bob_shared}")
        
        if alice_shared == bob_shared:
            st.success(f"Shared Secret Successfully Established: {alice_shared}")
            st.write("""
            **Note:** Both Alice and Bob now have the same shared secret key without ever transmitting 
            the key itself over the network. An eavesdropper would only see p, g, A, and B.
            """)
        else:
            st.error("Something went wrong! The shared secrets do not match.")
    
    with tabs[1]:
        st.write("### Encrypt with Diffie-Hellman")
        st.write("""
        Generate a shared key using Diffie-Hellman key exchange and use it to encrypt a message.
        Only someone with the matching shared key can decrypt the message.
        """)
        
        # Parameter sharing guide
        with st.expander("How to Share Parameters", expanded=True):
            st.markdown("""
            **First Browser:** Generate parameters → Download → Share with peer
            
            **Second Browser:** Upload parameters → Generate key pair → Exchange public keys
            
            **Both:** Enter peer's public key → Generate shared secret → Encrypt/decrypt
            """)
            
        # Add important note about parameters
        st.info("**Important:** Both parties must use the **same parameters** for successful key exchange.")
        
        # Generate new keys or display existing ones
        if 'dh_alice' not in st.session_state:
            # Option to generate new parameters or use provided ones
            param_option = st.radio("DH Parameters Source", 
                                   ["Generate New Parameters", 
                                    "Upload Parameters File", 
                                    "Paste Parameters Text"])
            
            if param_option == "Generate New Parameters":
                if st.button("Generate Key Pair with New Parameters"):
                    with st.spinner("Generating secure Diffie-Hellman parameters..."):
                        # Generate parameters and keys
                        st.session_state['dh_alice'] = DiffieHellman()
                        st.session_state['dh_parameters_bytes'] = st.session_state['dh_alice'].get_parameters_bytes()
                        st.session_state['dh_public_key_bytes'] = st.session_state['dh_alice'].get_public_key_bytes()
                        
                        # Store parameters in session for future use
                        st.session_state['dh_parameters_pem'] = st.session_state['dh_parameters_bytes'].decode('utf-8')
                        st.session_state['dh_public_key_pem'] = st.session_state['dh_public_key_bytes'].decode('utf-8')
                        
                    st.success("Diffie-Hellman key pair generated successfully!")
            else:
                # Either upload a parameters file or paste parameters text
                if param_option == "Upload Parameters File":
                    uploaded_params = st.file_uploader("Upload DH Parameters (.pem)", type=['pem'], key="encrypt_params_upload")
                    if uploaded_params is not None:
                        param_pem = uploaded_params.getvalue().decode('utf-8')
                        if st.button("Generate Key Pair with Uploaded Parameters"):
                            try:
                                with st.spinner("Generating key pair with provided parameters..."):
                                    # Load the parameters
                                    params_bytes = param_pem.encode('utf-8')
                                    params = DiffieHellman.load_parameters(params_bytes)
                                    
                                    # Create DH instance with these parameters
                                    st.session_state['dh_alice'] = DiffieHellman(parameters=params)
                                    st.session_state['dh_parameters_bytes'] = st.session_state['dh_alice'].get_parameters_bytes()
                                    st.session_state['dh_public_key_bytes'] = st.session_state['dh_alice'].get_public_key_bytes()
                                    
                                    # Store parameters in session for future use
                                    st.session_state['dh_parameters_pem'] = st.session_state['dh_parameters_bytes'].decode('utf-8')
                                    st.session_state['dh_public_key_pem'] = st.session_state['dh_public_key_bytes'].decode('utf-8')
                                    
                                st.success("Diffie-Hellman key pair generated with uploaded parameters!")
                            except Exception as e:
                                st.error(f"Error loading parameters: {str(e)}")
                else:
                    param_pem = st.text_area("Paste DH Parameters (PEM format):", height=150)
                    if st.button("Generate Key Pair with Pasted Parameters") and param_pem:
                        try:
                            with st.spinner("Generating key pair with provided parameters..."):
                                # Load the parameters
                                params_bytes = param_pem.encode('utf-8')
                                params = DiffieHellman.load_parameters(params_bytes)
                                
                                # Create DH instance with these parameters
                                st.session_state['dh_alice'] = DiffieHellman(parameters=params)
                                st.session_state['dh_parameters_bytes'] = st.session_state['dh_alice'].get_parameters_bytes()
                                st.session_state['dh_public_key_bytes'] = st.session_state['dh_alice'].get_public_key_bytes()
                                
                                # Store parameters in session for future use
                                st.session_state['dh_parameters_pem'] = st.session_state['dh_parameters_bytes'].decode('utf-8')
                                st.session_state['dh_public_key_pem'] = st.session_state['dh_public_key_bytes'].decode('utf-8')
                                
                            st.success("Diffie-Hellman key pair generated with provided parameters!")
                        except Exception as e:
                            st.error(f"Error loading parameters: {str(e)}")
        
        # Display the key exchange information if keys exist
        if 'dh_alice' in st.session_state:
            st.write("### Your Diffie-Hellman Parameters and Public Key")
            
            # Display parameters
            st.write("**DH Parameters** (share these with others)")
            st.code(st.session_state['dh_parameters_pem'], language="text")
            
            # Display public key
            st.write("**Public Key** (share this with others)")
            st.code(st.session_state['dh_public_key_pem'], language="text")
            
            # Download options
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="Download Parameters",
                    data=st.session_state['dh_parameters_pem'],
                    file_name="dh_parameters.pem",
                    mime="application/x-pem-file"
                )
            with col2:
                st.download_button(
                    label="Download Public Key",
                    data=st.session_state['dh_public_key_pem'],
                    file_name="dh_public_key.pem",
                    mime="application/x-pem-file"
                )
            
            # Peer's public key input
            st.write("### Enter Peer's Public Key")
            st.info("""
            Make sure the peer generated their key pair using your parameters.
            Copy and paste their complete public key, including BEGIN and END headers.
            """)
            
            # Option to upload peer's public key from file or paste it
            peer_key_option = st.radio("Public Key Source", ["Upload Public Key File", "Paste Public Key Text"])
            
            peer_public_key_pem = None
            if peer_key_option == "Upload Public Key File":
                uploaded_key = st.file_uploader("Upload Peer's Public Key (.pem)", type=['pem'], key="peer_key_upload")
                if uploaded_key is not None:
                    peer_public_key_pem = uploaded_key.getvalue().decode('utf-8')
                    st.success("Peer's public key uploaded successfully")
            else:
                peer_public_key_pem = st.text_area("Paste the other party's public key here:", height=150)
            
            if st.button("Generate Shared Secret"):
                if peer_public_key_pem:
                    try:
                        # Check if it's a valid PEM format
                        if "-----BEGIN PUBLIC KEY-----" not in peer_public_key_pem or "-----END PUBLIC KEY-----" not in peer_public_key_pem:
                            st.warning("The entered key doesn't appear to be in the proper PEM format. Please make sure to include the BEGIN and END markers.")
                            st.stop()
                        
                        # First try to load the public key without parameter checking
                        try:
                            # Basic validity check
                            peer_public_key = serialization.load_pem_public_key(
                                peer_public_key_pem.encode('utf-8'),
                                default_backend()
                            )
                            
                            # Now check compatibility with our parameters
                            peer_public_key = DiffieHellman.load_public_key(
                                peer_public_key_pem.encode('utf-8'),
                                st.session_state['dh_alice'].parameters
                            )
                        except ValueError as e:
                            st.error(f"Incompatible public key: {str(e)}")
                            st.info("This public key was generated with different parameters. Make sure both parties use the same parameters.")
                            st.stop()
                        except Exception as key_error:
                            st.error(f"Error loading public key: {str(key_error)}")
                            st.info("Make sure you've copied the entire public key including the BEGIN and END headers.")
                            st.stop()
                        
                        # Generate shared secret with more robust error handling
                        try:
                            shared_secret = st.session_state['dh_alice'].generate_shared_secret(peer_public_key)
                            st.session_state['shared_secret'] = shared_secret
                            
                            # Store a hex representation for display
                            st.session_state['shared_secret_hex'] = shared_secret.hex()[:16] + "..."
                            
                            st.success("Shared secret generated successfully!")
                            st.write("**Shared Secret (first bytes):**")
                            st.code(st.session_state['shared_secret_hex'], language="text")
                        except ValueError as e:
                            st.error(f"Error generating shared secret: {str(e)}")
                            st.info("""
                            The key might be from an incompatible system. Make sure both parties are using the same Diffie-Hellman parameters.
                            
                            IMPORTANT: For Diffie-Hellman to work, both users must use the same parameters:
                            - First user generates parameters and shares them
                            - Second user uses these parameters to generate their own key pair
                            """)
                    except Exception as e:
                        st.error(f"Error generating shared secret: {str(e)}")
                else:
                    st.warning("Please enter the peer's public key")
            
            # Message encryption
            if 'shared_secret' in st.session_state:
                st.write("### Encrypt a Message")
                message = st.text_area("Enter a message to encrypt:", 
                                       value="Hello! This is a secure message using Diffie-Hellman key exchange.",
                                       height=100)
                
                if st.button("Encrypt Message"):
                    if message:
                        try:
                            # Encrypt the message
                            encrypted_message = encrypt_with_derived_key(message.encode('utf-8'), st.session_state['shared_secret'])
                            encrypted_b64 = base64.b64encode(encrypted_message).decode('utf-8')
                            
                            # Store in session state for decryption demo
                            st.session_state['dh_encrypted_message'] = encrypted_message
                            st.session_state['dh_encrypted_b64'] = encrypted_b64
                            
                            st.success("Message encrypted successfully!")
                            st.write("### Encrypted Message (Base64)")
                            st.code(encrypted_b64, language="text")
                            
                            # Download option
                            st.download_button(
                                label="Download Encrypted Message",
                                data=encrypted_b64,
                                file_name="encrypted_dh_message.txt",
                                mime="text/plain"
                            )
                        except Exception as e:
                            st.error(f"Encryption error: {str(e)}")
                    else:
                        st.warning("Please enter a message to encrypt")
        else:
            st.info("Please generate a Diffie-Hellman key pair first")
            
    with tabs[2]:
        st.write("### Decrypt with Diffie-Hellman")
        st.write("""
        Decrypt a message that was encrypted using a shared key from Diffie-Hellman key exchange.
        You need the same shared key that was used for encryption.
        """)
        
        st.info("""
        **Important:** For decryption to work, you must use the same parameters that were used for encryption.
        Make sure you've exchanged parameters with your peer before attempting to decrypt messages.
        """)
        
        # Check if we have a shared secret already
        has_shared_secret = 'shared_secret' in st.session_state
        
        if not has_shared_secret:
            st.warning("You need to establish a shared secret first. Go to the Encrypt tab to generate one or upload parameters below.")
        
        # Option to upload parameters and keys
        use_existing_params = st.checkbox("Use existing parameters and keys", value=has_shared_secret)
        
        if not use_existing_params:
            # Option to get parameters from different sources
            param_source = st.radio("DH Parameters Source", 
                                  ["Upload Parameters File", 
                                   "Paste Parameters Text"], 
                                  key="decrypt_param_source")
            
            params_pem = None
            if param_source == "Upload Parameters File":
                # Upload DH parameters
                st.write("### Upload Diffie-Hellman Parameters")
                dh_params_file = st.file_uploader("Upload DH Parameters (.pem)", type=['pem'], key="dh_params_upload")
                
                if dh_params_file is not None:
                    params_pem = dh_params_file.getvalue().decode('utf-8')
            else:
                # Paste parameters
                st.write("### Paste Diffie-Hellman Parameters")
                params_pem = st.text_area("Paste the DH parameters here:", height=150, key="decrypt_params_paste")
            
            # Generate key pair from parameters
            if params_pem:
                st.write("### Generate Your Key Pair")
                if st.button("Generate Key Pair from Parameters"):
                    try:
                        # Load parameters and create a DH instance
                        params = DiffieHellman.load_parameters(params_pem.encode('utf-8'))
                        dh_instance = DiffieHellman(parameters=params)
                        
                        # Store in session state
                        st.session_state['dh_instance'] = dh_instance
                        st.session_state['dh_instance_public_key'] = dh_instance.get_public_key_bytes().decode('utf-8')
                        
                        st.success("Key pair generated successfully!")
                        
                        # Display public key
                        st.write("### Your Public Key")
                        st.code(st.session_state['dh_instance_public_key'], language="text")
                        
                        # Download option
                        st.download_button(
                            label="Download Your Public Key",
                            data=st.session_state['dh_instance_public_key'],
                            file_name="your_dh_public_key.pem",
                            mime="application/x-pem-file"
                        )
                    except Exception as e:
                        st.error(f"Error loading parameters: {str(e)}")
            else:
                st.info("Please provide Diffie-Hellman parameters first")
            
            # Input for peer's public key
            if 'dh_instance' in st.session_state:
                st.write("### Enter Peer's Public Key")
                st.info("Make sure to copy and paste the complete public key, including BEGIN and END headers")
                
                # Option to upload peer's public key from file or paste it
                peer_key_option = st.radio("Public Key Source", 
                                         ["Upload Public Key File", "Paste Public Key Text"],
                                         key="decrypt_peer_key_option")
                
                peer_key_input = None
                if peer_key_option == "Upload Public Key File":
                    uploaded_peer_key = st.file_uploader("Upload Peer's Public Key (.pem)", 
                                                       type=['pem'], 
                                                       key="decrypt_peer_key_file")
                    if uploaded_peer_key is not None:
                        peer_key_input = uploaded_peer_key.getvalue().decode('utf-8')
                        st.success("Peer's public key uploaded successfully")
                else:
                    peer_key_input = st.text_area("Paste the other party's public key:", 
                                                height=150, 
                                                key="decrypt_peer_key_text")
                
                if st.button("Generate Shared Secret for Decryption"):
                    if peer_key_input:
                        try:
                            # Check if it's a valid PEM format
                            if "-----BEGIN PUBLIC KEY-----" not in peer_key_input or "-----END PUBLIC KEY-----" not in peer_key_input:
                                st.warning("The entered key doesn't appear to be in the proper PEM format. Please make sure to include the BEGIN and END markers.")
                                st.stop()
                                
                            # First try to load the public key without parameter checking
                            try:
                                # Basic validity check
                                peer_key_basic = serialization.load_pem_public_key(
                                    peer_key_input.encode('utf-8'),
                                    default_backend()
                                )
                                
                                # Now check compatibility with our parameters
                                peer_key = DiffieHellman.load_public_key(
                                    peer_key_input.encode('utf-8'),
                                    st.session_state['dh_instance'].parameters
                                )
                            except ValueError as e:
                                st.error(f"Incompatible public key: {str(e)}")
                                st.info("This public key was generated with different parameters. Make sure both parties use the same parameters.")
                                st.stop()
                            except Exception as key_error:
                                st.error(f"Error loading public key: {str(key_error)}")
                                st.info("Make sure you've copied the entire public key including the BEGIN and END headers.")
                                st.stop()
                            
                            # Generate shared secret with more robust error handling
                            try:
                                decryption_secret = st.session_state['dh_instance'].generate_shared_secret(peer_key)
                                st.session_state['decryption_secret'] = decryption_secret
                                
                                st.success("Shared secret for decryption generated successfully!")
                            except ValueError as e:
                                st.error(f"Error generating shared secret: {str(e)}")
                                st.info("The key might be from an incompatible system. Make sure both parties are using the same Diffie-Hellman parameters.")
                        except Exception as e:
                            st.error(f"Error generating shared secret: {str(e)}")
                    else:
                        st.warning("Please enter the peer's public key")
        
        # Message decryption
        decrypt_secret = None
        if use_existing_params and 'shared_secret' in st.session_state:
            decrypt_secret = st.session_state['shared_secret']
        elif 'decryption_secret' in st.session_state:
            decrypt_secret = st.session_state['decryption_secret']
            
        if decrypt_secret is not None:
            st.write("### Decrypt a Message")
            
            # Options for input
            decrypt_option = st.radio(
                "Encrypted Message Source",
                ["Enter Base64 Encrypted Text", "Use Previously Encrypted Message", "Upload Encrypted File"],
                key="dh_decrypt_option"
            )
            
            encrypted_data = None
            
            if decrypt_option == "Enter Base64 Encrypted Text":
                encrypted_input = st.text_area("Enter Encrypted Message (Base64):", height=100, key="dh_encrypted_input")
                if encrypted_input:
                    try:
                        encrypted_data = base64.b64decode(encrypted_input)
                    except:
                        st.error("Invalid Base64 data. Please check your input.")
            
            elif decrypt_option == "Use Previously Encrypted Message":
                if 'dh_encrypted_message' in st.session_state:
                    encrypted_data = st.session_state['dh_encrypted_message']
                    st.success("Using previously encrypted message")
                else:
                    st.warning("No previously encrypted message found. Please encrypt a message first or use another option.")
            
            else:  # Upload Encrypted File
                uploaded_file = st.file_uploader("Upload Encrypted File", type=['txt'], key="dh_encrypted_file_upload")
                if uploaded_file is not None:
                    try:
                        encrypted_text = uploaded_file.getvalue().decode('utf-8')
                        encrypted_data = base64.b64decode(encrypted_text)
                        st.success("Encrypted file uploaded successfully")
                    except:
                        st.error("Invalid file format. Please upload a valid Base64 encoded file.")
            
            if st.button("Decrypt Message") and encrypted_data:
                try:
                    # Decrypt the message
                    decrypted_message = decrypt_with_derived_key(encrypted_data, decrypt_secret)
                    
                    st.success("Message decrypted successfully!")
                    st.write("### Decrypted Message")
                    st.code(decrypted_message.decode('utf-8'), language="text")
                except Exception as e:
                    st.error(f"Decryption error: {str(e)}")

else:  # RSA Encryption
    st.write("## RSA Encryption")
    
    tabs = st.tabs(["Basic Demo", "Encrypt", "Decrypt"])
    
    with tabs[0]:
        st.write("### Interactive RSA Demonstration")
        st.write("""
        This demonstration shows how RSA encryption works using small numbers for educational purposes.
        In practice, much larger prime numbers are used to ensure security.
        """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Step 1: Choose Prime Numbers")
            p = st.number_input("First Prime Number (p)", min_value=3, max_value=100, value=11)
            q = st.number_input("Second Prime Number (q)", min_value=3, max_value=100, value=13)
            
            # Calculate n
            n = p * q
            st.info(f"Public Modulus (n = p × q): {n}")
            
            # Calculate Euler's totient function
            phi = (p - 1) * (q - 1)
            st.info(f"Euler's Totient (φ(n)): {phi}")
        
        with col2:
            st.subheader("Step 2: Choose Public Exponent")
            # Find possible e values (coprime with phi)
            possible_e = [e for e in range(2, phi) if gcd(e, phi) == 1][:5]  # Take first 5
            e_options = st.selectbox(
                "Public Exponent (e) - Coprime with φ(n)",
                possible_e,
                format_func=lambda x: f"{x} (gcd with {phi} = 1)"
            )
            
            # Calculate private exponent
            d = modinv(e_options, phi)
            st.info(f"Private Exponent (d): {d}")
            st.success(f"Public Key: (n={n}, e={e_options})")
            st.success(f"Private Key: (n={n}, d={d})")
        
        # Message encryption/decryption demo
        st.subheader("Step 3: Encrypt and Decrypt a Message")
        demo_message = st.number_input("Enter a numerical message (must be less than n)", min_value=1, max_value=n-1, value=min(42, n-1))
        
        # Encrypt
        ciphertext = pow(demo_message, e_options, n)
        st.write(f"Encrypted: {demo_message}^{e_options} mod {n} = {ciphertext}")
        
        # Decrypt
        decrypted = pow(ciphertext, d, n)
        st.write(f"Decrypted: {ciphertext}^{d} mod {n} = {decrypted}")
        
        if decrypted == demo_message:
            st.success("The message was successfully encrypted and decrypted!")
        else:
            st.error("Something went wrong! The original message and decrypted message don't match.")
    
    with tabs[1]:
        st.write("### Encrypt with RSA")
        st.write("""
        Generate an RSA key pair and use the public key to encrypt a message.
        Only someone with the corresponding private key can decrypt the message.
        """)
        
        st.info("**Remember:** Share your public key, keep your private key secret. Encrypt with recipient's public key, decrypt with your private key.")
        
        # Generate new keys or display existing ones
        if 'rsa_keys' not in st.session_state:
            col1, col2 = st.columns(2)
            with col1:
                key_size = st.select_slider(
                    "Select Key Size (bits)",
                    options=[1024, 2048, 4096],
                    value=2048,
                    help="Larger keys are more secure but slower"
                )
            
            with col2:
                if st.button("Generate RSA Key Pair"):
                    with st.spinner("Generating secure RSA key pair..."):
                        # Generate keys
                        public_key_pem, private_key_pem = generate_key_pair(key_size)
                        
                        # Store in session state
                        st.session_state['rsa_keys'] = {
                            'public_key': public_key_pem,
                            'private_key': private_key_pem
                        }
                        
                    st.success(f"RSA {key_size}-bit key pair generated successfully!")
        
        # Display the key information if keys exist
        if 'rsa_keys' in st.session_state:
            st.write("### Your RSA Keys")
            
            tab1, tab2 = st.tabs(["Public Key", "Private Key"])
            
            with tab1:
                st.write("**Public Key** (share this with others)")
                st.code(st.session_state['rsa_keys']['public_key'], language="text")
                
                st.download_button(
                    label="Download Public Key",
                    data=st.session_state['rsa_keys']['public_key'],
                    file_name="rsa_public_key.pem",
                    mime="application/x-pem-file"
                )
            
            with tab2:
                st.write("**Private Key** (keep this secret)")
                
                if st.checkbox("Show Private Key", value=False):
                    st.code(st.session_state['rsa_keys']['private_key'], language="text")
                else:
                    st.warning("⚠️ Keep your private key secret! Only reveal it for demonstration purposes.")
                
                st.download_button(
                    label="Download Private Key",
                    data=st.session_state['rsa_keys']['private_key'],
                    file_name="rsa_private_key.pem",
                    mime="application/x-pem-file"
                )
            
            # Message encryption
            st.write("### Encrypt a Message")
            st.write("You can either use your public key or upload someone else's public key.")
              # Public key selection
            key_option = st.radio(
                "Select Public Key for Encryption",
                ["Use My Public Key", "Upload Someone's Public Key", "Paste Public Key Text"]
            )
            
            encryption_key = None
            if key_option == "Use My Public Key":
                encryption_key = st.session_state['rsa_keys']['public_key']
                st.success("Using your public key for encryption")
            elif key_option == "Upload Someone's Public Key":
                uploaded_key = st.file_uploader("Upload Public Key (.pem)", type=['pem'], key="rsa_encrypt_key_upload")
                if uploaded_key is not None:
                    encryption_key = uploaded_key.getvalue().decode('utf-8')
                    st.success("Public key uploaded successfully")
            else:  # Paste Public Key Text
                pasted_key = st.text_area("Paste the Public Key (PEM format):", height=150, key="rsa_encrypt_key_paste")
                if pasted_key:
                    if "-----BEGIN PUBLIC KEY-----" in pasted_key and "-----END PUBLIC KEY-----" in pasted_key:
                        encryption_key = pasted_key
                        st.success("Public key provided successfully")
                    else:
                        st.error("Invalid public key format. Make sure to include the BEGIN and END headers.")
            
            if encryption_key:
                message = st.text_area(
                    "Enter a message to encrypt:",
                    value="Hello! This is a secure message using RSA encryption.",
                    height=100
                )
                
                if st.button("Encrypt Message"):
                    if message:
                        try:
                            # Encrypt the message
                            encrypted_base64 = encrypt_with_public_key(message, encryption_key)
                            
                            # Store in session state
                            st.session_state['rsa_encrypted'] = encrypted_base64
                            
                            st.success("Message encrypted successfully!")
                            st.write("### Encrypted Message (Base64)")
                            st.code(encrypted_base64, language="text")
                            
                            # Download option
                            st.download_button(
                                label="Download Encrypted Message",
                                data=encrypted_base64,
                                file_name="encrypted_rsa_message.txt",
                                mime="text/plain"
                            )
                        except Exception as e:
                            st.error(f"Encryption error: {str(e)}")
                    else:
                        st.warning("Please enter a message to encrypt")
        else:
            st.info("Please generate an RSA key pair first")
    
    with tabs[2]:
        st.write("### Decrypt with RSA")
        st.write("""
        Decrypt a message that was encrypted with your public key using your private key.
        Only you, with your private key, can decrypt messages encrypted with your public key.
        """)
        
        st.info("""
        **Important:** For decryption to work, the message must have been encrypted with your public key,
        and you must use your corresponding private key.
        """)
        
        # Check if we have a private key
        has_private_key = 'rsa_keys' in st.session_state
        
        if not has_private_key:
            st.warning("You need to generate an RSA key pair first. Go to the Encrypt tab to generate one.")
        else:            # Option to use existing private key or upload one
            key_source = st.radio(
                "Private Key Source",
                ["Use My Private Key", "Upload Private Key", "Paste Private Key Text"],
                index=0
            )
            
            decryption_key = None
            if key_source == "Use My Private Key":
                decryption_key = st.session_state['rsa_keys']['private_key']
                st.success("Using your private key for decryption")
            elif key_source == "Upload Private Key":
                uploaded_key = st.file_uploader("Upload Private Key (.pem)", type=['pem'], key="rsa_decrypt_key_upload")
                if uploaded_key is not None:
                    decryption_key = uploaded_key.getvalue().decode('utf-8')
                    st.success("Private key uploaded successfully")
            else:  # Paste Private Key Text
                pasted_key = st.text_area("Paste the Private Key (PEM format):", height=150, key="rsa_decrypt_key_paste")
                if pasted_key:
                    if "-----BEGIN PRIVATE KEY-----" in pasted_key and "-----END PRIVATE KEY-----" in pasted_key:
                        decryption_key = pasted_key
                        st.success("Private key provided successfully")
                    else:
                        st.error("Invalid private key format. Make sure to include the BEGIN and END headers.")
            
            if decryption_key:
                # Options for input
                decrypt_option = st.radio(
                    "Encrypted Message Source",
                    ["Enter Base64 Encrypted Text", "Use Previously Encrypted Message", "Upload Encrypted File"],
                    key="rsa_decrypt_option"
                )
                
                encrypted_base64 = None
                
                if decrypt_option == "Enter Base64 Encrypted Text":
                    encrypted_input = st.text_area("Enter Encrypted Message (Base64):", height=100, key="rsa_encrypted_input")
                    if encrypted_input:
                        encrypted_base64 = encrypted_input
                
                elif decrypt_option == "Use Previously Encrypted Message":
                    if 'rsa_encrypted' in st.session_state:
                        encrypted_base64 = st.session_state['rsa_encrypted']
                        st.success("Using previously encrypted message")
                    else:
                        st.warning("No previously encrypted message found. Please encrypt a message first or use another option.")
                
                else:  # Upload Encrypted File
                    uploaded_file = st.file_uploader("Upload Encrypted File", type=['txt'], key="rsa_encrypted_file_upload")
                    if uploaded_file is not None:
                        try:
                            encrypted_base64 = uploaded_file.getvalue().decode('utf-8')
                            st.success("Encrypted file uploaded successfully")
                        except:
                            st.error("Invalid file format. Please upload a valid text file.")
                
                if st.button("Decrypt Message") and encrypted_base64:
                    try:
                        # Decrypt the message
                        decrypted_message = decrypt_with_private_key(encrypted_base64, decryption_key)
                        
                        st.success("Message decrypted successfully!")
                        st.write("### Decrypted Message")
                        st.code(decrypted_message, language="text")
                    except Exception as e:
                        st.error(f"Decryption error: {str(e)}")
                        st.info("""
                        This could happen because:
                        1. The message was encrypted with a different public key
                        2. The private key doesn't match the public key used for encryption
                        3. The encrypted message was modified or corrupted
                        """)

# Add instruction alert
st.info("""
**Quick Guide:**

**DH:** Share parameters → Exchange public keys → Generate shared secret → Encrypt/decrypt messages

**RSA:** Generate key pair → Share public key → Encrypt with recipient's public key → Decrypt with private key
""")

# Add custom footer
st.markdown("""
<div class="footer">
    <p>Made with ❤️ by Group 2 | BSCS 3B | Applied Cryptography CSAC 329</p>
    <p>© 2025 All Rights Reserved</p>
</div>
""", unsafe_allow_html=True)
