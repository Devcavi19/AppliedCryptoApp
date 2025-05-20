"""
Asymmetric Encryption Page
Implements RSA and Diffie-Hellman key exchange
"""

import streamlit as st

# Must be the first Streamlit command
st.set_page_config(
    page_title="Asymmetric Encryption",
    page_icon="https://img.icons8.com/?size=100&id=WMWP1MqUZRiS&format=png&color=000000",
)

import sys
import os
import base64
import rsa
import json
import random

try:
    import M2Crypto
    # Using M2Crypto for prime number generation
    def get_prime(bits):
        """Generate a prime number with specified bits using M2Crypto"""
        return int(M2Crypto.m2.bn_generate_prime_ex(bits, 0, None, None, None, None).hex(), 16)
except ImportError:
    # Fallback if M2Crypto is not available
    st.warning("M2Crypto not installed. Using fallback methods for prime number generation.")
    
    # Simple fallback for prime number generation
    def is_prime(n, k=5):
        """Miller-Rabin primality test"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def get_prime(bits):
        """Generate a prime number with specified bits"""
        while True:
            # Generate a random odd number with specified bits
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if is_prime(p):
                return p

# Add the parent directory to sys.path to allow importing from crypto_algorithms
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the asymmetric encryption algorithms
try:
    from crypto_algorithms.asymmetric import rsa_algorithm, diffie_hellman
    # Check if M2Crypto implementations are available
    from crypto_algorithms.asymmetric import has_m2crypto
    if has_m2crypto:
        from crypto_algorithms.asymmetric import RSAM2Crypto, DiffieHellmanM2Crypto
        st.success("M2Crypto library available for enhanced cryptographic operations!")
except ImportError as e:
    has_m2crypto = False
    st.error(f"Error importing crypto modules: {e}")
    st.info("Some features might not work correctly.")

st.markdown("<h1 style='color: #00ffa2ff;'>Asymmetric Encryption Algorithms</h1>", unsafe_allow_html=True)
st.write("Asymmetric encryption uses different keys for encryption and decryption: a public key and a private key.")

encryption_type = st.selectbox("Select Encryption Algorithm", ["RSA", "Diffie-Hellman"])

if encryption_type == "RSA":
    st.sidebar.subheader("📘 RSA Description")
    if st.sidebar.checkbox("Show Description"):
        st.sidebar.write("""
        ### RSA Encryption:
        RSA (Rivest-Shamir-Adleman) is one of the first public-key cryptosystems and is widely used for secure data transmission. It involves the use of a public key for encryption and a private key for decryption.
        
        ### Secure Communication Between Alice and Bob:
        RSA enables secure message exchange between two parties (commonly referred to as Alice and Bob) without requiring them to share a secret key beforehand.
        
        1. **Key Generation**: Alice and Bob each generate their own private and public key pairs.
        2. **Public Key Exchange**: They share their public keys with each other (and potentially anyone else).
        3. **Secure Messaging**: 
           - Alice encrypts her message using Bob's public key.
           - Only Bob can decrypt it using his private key.
           - Similarly, Bob encrypts his replies using Alice's public key.
           - Only Alice can decrypt them using her private key.
        
        This ensures that their communication remains confidential, even if intercepted.
        """)
        
    st.sidebar.subheader("🔍 Process")
    if st.sidebar.checkbox("Show Process"):
        st.sidebar.write("""
        #### Process:
        1. Generate RSA public and private keys.
        2. Enter the plaintext message.
        3. Encrypt the message using the recipient's public key.
        4. Decrypt the message using the recipient's private key.
        
        #### Real-world Application:
        - When you connect to a secure website (HTTPS), your browser uses RSA to establish a secure connection.
        - RSA is used for secure email communication (PGP/GPG).
        - Digital signatures rely on RSA to verify the authenticity of messages and documents.
        """)

    st.write("## RSA Encryption")
    
    # Add Alice-Bob secure communication visualization
    st.write("### Alice and Bob's Secure Communication")
    
    with st.expander("Understand how Alice and Bob can communicate securely using RSA"):
        col1, col2, col3 = st.columns([1, 3, 1])
        
        with col2:
            st.markdown("""
            #### How Alice sends a secure message to Bob:
            
            ```
            ┌─────────┐                                 ┌─────────┐
            │  Alice  │◀─────── Bob's Public Key ───────│   Bob   │
            └────┬────┘                                 └────┬────┘
                 │                                           │
                 │ 1. Write Message: "Hello Bob!"            │
                 │                                           │
                 │ 2. Encrypt Using Bob's Public Key         │
                 │    "Hello Bob!" ──▶ "x9f#@3jL..."         │
                 │                                           │
                 │                                           │
                 └───────▶ Encrypted Message ───────────────▶┘
                                                             │
                                                             │ 3. Decrypt Using Bob's Private Key
                                                             │    "x9f#@3jL..." ──▶ "Hello Bob!"
                                                             │
            ```
            
            #### How Bob replies securely to Alice:
            
            ```
            ┌─────────┐                                 ┌─────────┐
            │  Alice  │─────── Alice's Public Key ─────▶│   Bob   │
            └────┬────┘                                 └────┬────┘
                 │                                           │
                 │                                           │ 1. Write Reply: "Hi Alice!"
                 │                                           │
                 │                                           │ 2. Encrypt Using Alice's Public Key
                 │                                           │    "Hi Alice!" ──▶ "j7%dK@p2..."
                 │                                           │
                 │                                           │
                 └───────◀── Encrypted Reply ───────────────◀┘
                 │
                 │ 3. Decrypt Using Alice's Private Key
                 │    "j7%dK@p2..." ──▶ "Hi Alice!"
                 │
            ```
            
            #### Security Features:
            - Even if an eavesdropper intercepts the encrypted messages, they cannot decrypt them without the private keys.
            - The public keys can be freely shared without compromising security.
            - Each person keeps their private key secret.
            """)
    
    try:
        # Try using M2Crypto for RSA operations
        if 'M2Crypto' in sys.modules:
            # Generate key pair using M2Crypto
            st.info("Using M2Crypto for RSA operations")
            
            def generate_rsa_keys(bits=1024):
                rsa_key = M2Crypto.RSA.gen_key(bits, 65537)
                # Export public and private keys in PEM format
                bio = M2Crypto.BIO.MemoryBuffer()
                rsa_key.save_pub_key_bio(bio)
                pub_key_pem = bio.read_all()
                
                bio = M2Crypto.BIO.MemoryBuffer()
                rsa_key.save_key_bio(bio, cipher=None)  # No encryption for private key
                priv_key_pem = bio.read_all()
                
                return pub_key_pem, priv_key_pem, rsa_key
                
            def encrypt_with_m2crypto(data, public_key_pem):
                # Create RSA object from public key PEM
                bio = M2Crypto.BIO.MemoryBuffer(public_key_pem)
                rsa_pub = M2Crypto.RSA.load_pub_key_bio(bio)
                # Encrypt with PKCS1 padding
                encrypted = rsa_pub.public_encrypt(data, M2Crypto.RSA.pkcs1_padding)
                return encrypted
                
            def decrypt_with_m2crypto(encrypted_data, private_key):
                # Decrypt with PKCS1 padding
                decrypted = private_key.private_decrypt(encrypted_data, M2Crypto.RSA.pkcs1_padding)
                return decrypted
            
            # Generate RSA key pairs for Alice and Bob
            alice_pub_pem, alice_priv_pem, alice_private_key = generate_rsa_keys(1024)
            bob_pub_pem, bob_priv_pem, bob_private_key = generate_rsa_keys(1024)
            
            # Create tabs for Alice and Bob conversation
            alice_tab, bob_tab = st.tabs(["Alice's Message to Bob", "Bob's Reply to Alice"])
            
            with alice_tab:
                st.write("### Alice's Message to Bob")
                st.write("Alice will encrypt her message using Bob's public key.")
                
                # Display Bob's reply if it exists
                if "bob_message" in st.session_state:
                    st.write(f"Bob's message to Alice: \"{st.session_state['bob_message']}\"")
                
                alice_text = st.text_area("Enter Alice's message to Bob:")
                if alice_text:
                    alice_text_bytes = alice_text.encode('utf8')
                else:
                    alice_text_bytes = b''
                    
                if st.button("Encrypt Alice's Message"):
                    if not alice_text_bytes:
                        st.warning("Please enter a message for Alice to send.")
                    else:
                        try:
                            # Check message length
                            max_length = 1024 // 8 - 11  # Max bytes that can be encrypted with 1024-bit key
                            if len(alice_text_bytes) > max_length:
                                st.error(f"Message too long! With a 1024-bit key, Alice can encrypt up to {max_length} bytes.")
                            else:
                                # Alice encrypts message using Bob's public key
                                encrypted = encrypt_with_m2crypto(alice_text_bytes, bob_pub_pem)
                                
                                st.success("✅ Alice has encrypted her message with Bob's public key!")
                                st.write("## Encrypted message (bytes):")
                                st.code(str(encrypted))
                                
                                st.write("## Bob decrypts the message with his private key:")
                                decrypted = decrypt_with_m2crypto(encrypted, bob_private_key)
                                st.info(f"Bob reads: \"{decrypted.decode('utf8')}\"")
                                
                                # Store the message for Bob's tab
                                st.session_state["alice_message"] = alice_text
                        except Exception as e:
                            st.error(f"Encryption error: {str(e)}")
            
            with bob_tab:
                st.write("### Bob's Reply to Alice")
                st.write("Bob will encrypt his reply using Alice's public key.")
                
                if "alice_message" in st.session_state:
                    st.write(f"Alice's message to Bob: \"{st.session_state['alice_message']}\"")
                
                bob_text = st.text_area("Enter Bob's reply to Alice:")
                if bob_text:
                    bob_text_bytes = bob_text.encode('utf8')
                else:
                    bob_text_bytes = b''
                
                if st.button("Encrypt Bob's Reply"):
                    if not bob_text_bytes:
                        st.warning("Please enter a reply for Bob to send.")
                    else:
                        try:
                            # Check message length
                            max_length = 1024 // 8 - 11  # Max bytes that can be encrypted with 1024-bit key
                            if len(bob_text_bytes) > max_length:
                                st.error(f"Reply too long! With a 1024-bit key, Bob can encrypt up to {max_length} bytes.")
                            else:
                                # Bob encrypts message using Alice's public key
                                encrypted = encrypt_with_m2crypto(bob_text_bytes, alice_pub_pem)
                                
                                st.success("✅ Bob has encrypted his reply with Alice's public key!")
                                st.write("## Encrypted reply (bytes):")
                                st.code(str(encrypted))
                                
                                st.write("## Alice decrypts the reply with her private key:")
                                decrypted = decrypt_with_m2crypto(encrypted, alice_private_key)
                                st.info(f"Alice reads: \"{decrypted.decode('utf8')}\"")
                                
                                # Store Bob's message for Alice's tab
                                st.session_state["bob_message"] = bob_text
                                
                                st.success("🔒 Secure communication completed successfully!")
                                st.info("Note: Each message was readable only by the intended recipient because it was encrypted with their public key and could only be decrypted with their private key.")
                        except Exception as e:
                            st.error(f"Encryption error: {str(e)}")
            
            # Original RSA demo code
            st.write("## Standard RSA Encryption Demo")
            # Generate a standard RSA key pair for the demo
            std_pub_key_pem, std_priv_key_pem, std_rsa_private_key = generate_rsa_keys(1024)
            
            text = st.text_area("Enter your message: ")
            if text:
                text_bytes = text.encode('utf8')
            else:
                text_bytes = b''
                
            if st.button("Encrypt"):
                if not text_bytes:
                    st.warning("Please enter a message to encrypt.")
                else:
                    try:
                        # Check message length - RSA with padding can't encrypt messages
                        # longer than key size - padding (11 bytes for PKCS1)
                        max_length = 1024 // 8 - 11  # Max bytes that can be encrypted with 1024-bit key
                        if len(text_bytes) > max_length:
                            st.error(f"Message too long! With a 1024-bit key, you can encrypt up to {max_length} bytes.")
                            st.info("For longer messages, consider using hybrid encryption (RSA + symmetric cipher).")
                        else:
                            ciphertext = encrypt_with_m2crypto(text_bytes, std_pub_key_pem)
                            
                            st.write("## Encrypted text in bytes:")
                            st.code(str(ciphertext))
                            
                            st.write("## Encrypted text in hex:")
                            st.code(ciphertext.hex())
                            
                            st.write("## Public Key (PEM format):")
                            st.code(std_pub_key_pem.decode())
                            
                            # Decrypt the message
                            decrypted = decrypt_with_m2crypto(ciphertext, std_rsa_private_key)
                            
                            st.write("## Decrypted text:")
                            st.code(decrypted.decode('utf8'))
                    except Exception as e:
                        st.error(f"M2Crypto encryption error: {str(e)}")
                        st.info("Falling back to standard RSA library for encryption...")
                        
                        # Fallback to standard rsa library
                        try:
                            # Generate new RSA keys using standard library
                            fallback_publickey, fallback_privatekey = rsa.newkeys(1024)
                            fallback_ciphertext = rsa.encrypt(text_bytes, fallback_publickey)
                            
                            st.write("## Encrypted text in bytes:")
                            st.code(str(fallback_ciphertext))
                            
                            st.write("## Encrypted text in hex:")
                            st.code(fallback_ciphertext.hex())
                            
                            fallback_decrypted = rsa.decrypt(fallback_ciphertext, fallback_privatekey)
                            st.write("## Decrypted text:")
                            st.code(fallback_decrypted.decode('utf8'))
                        except Exception as e2:
                            st.error(f"Fallback encryption also failed: {str(e2)}")
                            st.info("This might be due to the message being too long for RSA encryption. Try a shorter message.")
        else:
            # Fallback to standard RSA if M2Crypto is not available
            st.write("## Standard RSA Encryption Demo (using Python RSA library)")
            
            # Generate RSA key pair using standard library
            standard_publickey, standard_privatekey = rsa.newkeys(1024)
            
            text = st.text_area("Enter your message: ")
            if text:
                text_bytes = text.encode('utf8')
            else:
                text_bytes = b''
                
            if st.button("Encrypt"):
                if not text_bytes:
                    st.warning("Please enter a message to encrypt.")
                else:
                    try:
                        st.write("## Encrypted text in bytes:")
                        standard_ciphertext = rsa.encrypt(text_bytes, standard_publickey)
                        st.code(str(standard_ciphertext))
                        
                        st.write("## Encrypted text in hex:")
                        st.code(standard_ciphertext.hex())
                        
                        standard_decrypted = rsa.decrypt(standard_ciphertext, standard_privatekey)
                        st.write("## Decrypted text:")
                        st.code(standard_decrypted.decode('utf8'))
                    except Exception as e:
                        st.error(f"Encryption error: {str(e)}")
                        st.info("This might be due to the message being too long for RSA encryption. Try a shorter message.")
    
    except Exception as e:
        st.error(f"Error setting up RSA: {str(e)}")
        st.info("Make sure M2Crypto or the rsa package is properly installed.")
        text = st.text_area("Enter your message: ")
        text_bytes = text.encode('utf8') if text else b''

elif encryption_type == "Diffie-Hellman":
    st.sidebar.subheader(":blue[Description]")
    if st.sidebar.checkbox("Show Description"):
        st.sidebar.write("""
        ### Diffie-Hellman Key Exchange:
        Diffie-Hellman key exchange is a method of securely exchanging cryptographic keys over a public channel. It allows two parties to generate a shared secret key without exchanging the secret key directly.
        
        ### Secure Key Establishment Between Alice and Bob:
        Diffie-Hellman enables Alice and Bob to establish a shared secret key even when communicating over an insecure channel where others might be listening.
        
        ### Step-by-Step Mathematical Process:
        
        1. **Initial Setup**: 
           - Alice and Bob agree on public parameters:
             - A large prime number p
             - A generator g (usually a small integer like 2 or 5)
           - These values can be known to everyone, including eavesdroppers
        
        2. **Private Key Generation**:
           - Alice chooses a secret number a (her private key)
           - Bob chooses a secret number b (his private key)
           - These values are kept strictly private
        
        3. **Public Key Exchange**:
           - Alice calculates A = g^a mod p (her public key)
           - Bob calculates B = g^b mod p (his public key)
           - They exchange these public keys over the insecure channel
        
        4. **Shared Secret Calculation**:
           - Alice computes shared secret: S = B^a mod p
           - Bob computes shared secret: S = A^b mod p
           - Due to mathematical properties: S = g^(ab) mod p for both parties
        
        5. **Secure Communication**:
           - They use this identical shared secret to derive encryption keys
           - All subsequent messages can be encrypted using symmetric algorithms
        
        ### Security Guarantee:
        Even if an attacker intercepts p, g, A, and B, they cannot feasibly calculate the shared secret without knowing either private key a or b. This security relies on the discrete logarithm problem being computationally difficult to solve for large numbers.
        """)
        
    st.sidebar.subheader(":blue[Process]")
    if st.sidebar.checkbox("Show Process"):
        st.sidebar.write("""
        #### Process:
        1. Choose a prime number (p) and a generator (g).
        2. Choose private keys for Alice and Bob (a and b).
        3. Generate shared secret keys for Alice and Bob using the Diffie-Hellman key exchange algorithm.
        4. Encrypt and decrypt messages using the shared secret key.
        
        #### Real-world Applications:
        - Secure web browsing (HTTPS) uses Diffie-Hellman during the TLS handshake.
        - VPN connections use DH to establish secure tunnels.
        - Messaging apps like Signal use DH for end-to-end encryption.
        """)

    # Add Alice-Bob key exchange visualization
    st.write("### Alice and Bob's Key Exchange")
    
    with st.expander("Understand how Alice and Bob establish a shared secret key"):
        col1, col2, col3 = st.columns([1, 3, 1])
        
        with col2:
            st.markdown("""
            #### Diffie-Hellman Key Exchange Protocol:
            
            ```
            ┌─────────┐                                    ┌─────────┐
            │  Alice  │                                    │   Bob   │
            └────┬────┘                                    └────┬────┘
                 │                                              │
                 │  Both agree on public values:                │
                 │  Prime p and Generator g                     │
                 │                                              │
                 │  Alice chooses private value a               │  Bob chooses private value b
                 │                                              │
                 │  Computes: A = g^a mod p                     │  Computes: B = g^b mod p
                 │                                              │
                 │                A                             │
                 ├─────────────────────────────────────────────▶│
                 │                                              │
                 │                B                             │
                 │◀─────────────────────────────────────────────┤
                 │                                              │
                 │  Computes shared secret:                     │  Computes shared secret:
                 │  S = B^a mod p                               │  S = A^b mod p
                 │                                              │
                 │  The secrets are identical!                  │
                 │  S = B^a = (g^b)^a = g^(ab) mod p            │
                 │  S = A^b = (g^a)^b = g^(ab) mod p            │
            ```
            
            #### Using the shared secret for messaging:
            
            ```
            ┌─────────┐                                    ┌─────────┐
            │  Alice  │                                    │   Bob   │
            └────┬────┘                                    └────┬────┘
                 │                                              │
                 │ 1. Write Message: "Hello Bob!"               │
                 │                                              │
                 │ 2. Encrypt Using Shared Secret Key S         │
                 │    "Hello Bob!" ──▶ "x9f#@3jL..."            │
                 │                                              │
                 │                                              │
                 └───────▶ Encrypted Message ──────────────────▶┘
                                                                │
                                                                │ 3. Decrypt Using Shared Secret Key S
                                                                │    "x9f#@3jL..." ──▶ "Hello Bob!"
                                                                │
            ```
            
            #### Security Features:
            - The private values (a and b) never leave Alice and Bob's systems.
            - An eavesdropper would see p, g, A, and B, but can't compute S without knowing a or b.
            - This allows Alice and Bob to establish a shared encryption key for symmetric encryption.
            - Unlike RSA, Diffie-Hellman itself doesn't encrypt messages - it just creates a shared key.
            """)
    
    # First try to use M2Crypto for Diffie-Hellman if available
    use_m2crypto = 'M2Crypto' in sys.modules
    
    if use_m2crypto:
        st.info("Using M2Crypto for Diffie-Hellman operations")
        
        try:
            def generate_dh_params():
                """Generate Diffie-Hellman parameters using M2Crypto"""
                # Generate DH parameters with 512 bits (can be increased for better security)
                dh = M2Crypto.DH.gen_params(512, 2)  # 2 is the generator
                return dh
                
            def compute_public_key(dh, private_key):
                """Compute public key from private key using DH parameters"""
                dh.set_x(private_key)
                dh.gen_key()
                return dh.pub
                
            def compute_shared_secret(dh, other_public_key):
                """Compute shared secret from other party's public key"""
                shared_key = dh.compute_key(other_public_key)
                # Use first 4 bytes as a simple key
                return int.from_bytes(shared_key[:4], byteorder='big')
                
            # Generate DH parameters
            dh_params = generate_dh_params()
            p = dh_params.p
            g = dh_params.g
            
            st.write(f"Prime (p): {p}")
            st.write(f"Generator (g): {g}")
            
            st.write("Choose private keys for Alice and Bob:")
            a = st.number_input("Alice's private key (a):", min_value=1, value=123, step=1)
            b = st.number_input("Bob's private key (b):", min_value=1, value=456, step=1)
            
            # Set Alice's private key and compute public key
            dh_alice = M2Crypto.DH.set_params(p, g)
            dh_alice.set_x(a)
            dh_alice.gen_key()
            
            # Set Bob's private key and compute public key
            dh_bob = M2Crypto.DH.set_params(p, g)
            dh_bob.set_x(b)
            dh_bob.gen_key()
            
            # Exchange public keys and compute shared secrets
            alice_shared = dh_alice.compute_key(dh_bob.pub)
            bob_shared = dh_bob.compute_key(dh_alice.pub)
            
            # Use first 4 bytes as simple keys
            alice_key = int.from_bytes(alice_shared[:4], byteorder='big')
            bob_key = int.from_bytes(bob_shared[:4], byteorder='big')
            
            if alice_key == bob_key:
                st.write(f"Shared Secret Key: {alice_key}")
                
                def encrypt(text, key):
                    """Encrypt plaintext using a key"""
                    return ''.join([chr((ord(char) + key) % 256) for char in text])

                def decrypt(text, key):
                    """Decrypt ciphertext using a key"""
                    return ''.join([chr((ord(char) - key) % 256) for char in text])
                
                # Create tabs for Alice and Bob's secure conversation
                st.write("### Alice and Bob's Secure Conversation Demo")
                st.info("Now that Alice and Bob have established a shared secret key, they can use it for symmetric encryption.")
                
                alice_msg_tab, bob_msg_tab = st.tabs(["Alice's Message", "Bob's Reply"])
                
                with alice_msg_tab:
                    st.write("### Alice's Message to Bob")
                    st.write("Alice will encrypt her message using their shared secret key.")
                    
                    # Display Bob's reply if it exists
                    if "bob_dh_message" in st.session_state:
                        st.write(f"Bob's message to Alice: \"{st.session_state['bob_dh_message']}\"")
                    
                    alice_plaintext = st.text_area("Enter Alice's message to Bob:")
                    
                    if st.button("Alice Encrypts & Sends"):
                        if not alice_plaintext:
                            st.warning("Please enter a message for Alice to send.")
                        else:
                            # Alice encrypts using the shared key
                            alice_encrypted = encrypt(alice_plaintext, alice_key)
                            
                            st.success("✅ Alice has encrypted her message with the shared secret key!")
                            st.write("## Encrypted message:")
                            st.code(alice_encrypted)
                            
                            st.write("## Bob decrypts the message with his copy of the shared key:")
                            bob_decrypted = decrypt(alice_encrypted, bob_key)
                            st.info(f"Bob reads: \"{bob_decrypted}\"")
                            
                            # Store the message for Bob's tab
                            st.session_state["alice_dh_message"] = alice_plaintext
                
                with bob_msg_tab:
                    st.write("### Bob's Reply to Alice")
                    st.write("Bob will encrypt his reply using their shared secret key.")
                    
                    if "alice_dh_message" in st.session_state:
                        st.write(f"Alice's message to Bob: \"{st.session_state['alice_dh_message']}\"")
                    
                    bob_plaintext = st.text_area("Enter Bob's reply to Alice:")
                    
                    if st.button("Bob Encrypts & Sends"):
                        if not bob_plaintext:
                            st.warning("Please enter a reply for Bob to send.")
                        else:
                            # Bob encrypts using the shared key
                            bob_encrypted = encrypt(bob_plaintext, bob_key)
                            
                            st.success("✅ Bob has encrypted his reply with the shared secret key!")
                            st.write("## Encrypted reply:")
                            st.code(bob_encrypted)
                            
                            st.write("## Alice decrypts the reply with her copy of the shared key:")
                            alice_decrypted = decrypt(bob_encrypted, alice_key)
                            st.info(f"Alice reads: \"{alice_decrypted}\"")
                            
                            # Store Bob's message for Alice's tab
                            st.session_state["bob_dh_message"] = bob_plaintext
                            
                            st.success("🔒 Secure communication completed successfully!")
                            st.info("Note: Both Alice and Bob could read each other's messages because they established the same shared secret key through the Diffie-Hellman key exchange.")
                
                # Original simple encryption demo
                st.write("## Standard Encryption Demo")
                plaintext = st.text_input("Enter the plaintext:")
                if st.button("Encrypt"):
                    encrypted_text = encrypt(plaintext, alice_key)
                    st.write(f"## :green[Encrypted text]: {encrypted_text}")
                    
                    decrypted_text = decrypt(encrypted_text, alice_key)
                    st.write(f"## :red[Decrypted text]: {decrypted_text}")
            else:
                st.error("Shared key mismatch! This shouldn't happen with correct implementation.")
        
        except Exception as e:
            st.error(f"Error with M2Crypto DH: {str(e)}")
            st.info("Falling back to standard implementation...")
            use_m2crypto = False
    
    if not use_m2crypto:
        # Fallback to standard implementation if M2Crypto is not available or had an error
        def modexp(b, e, m):
            """Efficient modular exponentiation"""
            result = 1
            b = b % m
            while e > 0:
                if e % 2 == 1:
                    result = (result * b) % m
                e = e >> 1
                b = (b * b) % m
            return result

        def generate_shared_secret(p, g, a, b):
            """Generate shared secret using Diffie-Hellman key exchange"""
            A = modexp(g, a, p)
            B = modexp(g, b, p)
            secret_A = modexp(B, a, p)
            secret_B = modexp(A, b, p)
            if secret_A == secret_B:
                return secret_A
            else:
                return None

        def encrypt(text, key):
            """Encrypt plaintext using a key"""
            return ''.join([chr((ord(char) + key) % 256) for char in text])

        def decrypt(text, key):
            """Decrypt ciphertext using a key"""
            return ''.join([chr((ord(char) - key) % 256) for char in text])

    st.write("## Diffie-Hellman Key Exchange Demonstration")

    p = st.sidebar.number_input("Enter a prime number (p):", min_value=2, value=23, step=1)
    g = st.sidebar.number_input("Enter a generator (g):", min_value=2, value=5, step=1)

    st.write("Choose private keys for Alice and Bob:")
    a = st.number_input("Alice's private key (a):", min_value=1, value=6, step=1)
    b = st.number_input("Bob's private key (b):", min_value=1, value=15, step=1)
    
    # Calculate public keys
    A = modexp(g, a, p)  # Alice's public key
    B = modexp(g, b, p)  # Bob's public key
    
    # Visual representation of the key exchange
    st.write("### Key Exchange Process")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("#### Alice's Calculations")
        st.write(f"Private key (a): {a}")
        st.write(f"Public key (A = g^a mod p): {A}")
        st.write(f"A = {g}^{a} mod {p} = {A}")
        
        # Show shared secret calculation
        alice_secret = modexp(B, a, p)
        st.write(f"Shared Secret = B^a mod p")
        st.write(f"Shared Secret = {B}^{a} mod {p} = {alice_secret}")
    
    with col2:
        st.write("#### Bob's Calculations")
        st.write(f"Private key (b): {b}")
        st.write(f"Public key (B = g^b mod p): {B}")
        st.write(f"B = {g}^{b} mod {p} = {B}")
        
        # Show shared secret calculation
        bob_secret = modexp(A, b, p)
        st.write(f"Shared Secret = A^b mod p")
        st.write(f"Shared Secret = {A}^{b} mod {p} = {bob_secret}")
    
    # Verify that both Alice and Bob calculated the same shared secret
    shared_secret = generate_shared_secret(p, g, a, b)
    
    if shared_secret:
        st.success(f"✅ Success! Alice and Bob have established the same shared secret: {shared_secret}")
    else:
        st.error("❌ Error! The shared secrets don't match. This shouldn't happen with a correct implementation.")

    if shared_secret:
        st.write(f"Shared Secret Key: {shared_secret}")

        # Create tabs for Alice and Bob's secure conversation
        st.write("### Alice and Bob's Secure Conversation Demo")
        st.info("Now that Alice and Bob have established a shared secret key, they can use it for symmetric encryption.")
        
        alice_msg_tab, bob_msg_tab = st.tabs(["Alice's Message", "Bob's Reply"])
        
        with alice_msg_tab:
            st.write("### Alice's Message to Bob")
            st.write("Alice will encrypt her message using their shared secret key.")
            
            # Display Bob's reply if it exists
            if "bob_std_dh_message" in st.session_state:
                st.write(f"Bob's message to Alice: \"{st.session_state['bob_std_dh_message']}\"")
            
            alice_plaintext = st.text_area("Enter Alice's message to Bob:")
            
            if st.button("Alice Encrypts & Sends"):
                if not alice_plaintext:
                    st.warning("Please enter a message for Alice to send.")
                else:
                    # Alice encrypts using the shared key
                    alice_encrypted = encrypt(alice_plaintext, shared_secret)
                    
                    st.success("✅ Alice has encrypted her message with the shared secret key!")
                    st.write("## Encrypted message:")
                    st.code(alice_encrypted)
                    
                    st.write("## Bob decrypts the message with his copy of the shared key:")
                    bob_decrypted = decrypt(alice_encrypted, shared_secret)
                    st.info(f"Bob reads: \"{bob_decrypted}\"")
                    
                    # Store the message for Bob's tab
                    st.session_state["alice_std_dh_message"] = alice_plaintext
        
        with bob_msg_tab:
            st.write("### Bob's Reply to Alice")
            st.write("Bob will encrypt his reply using their shared secret key.")
            
            if "alice_std_dh_message" in st.session_state:
                st.write(f"Alice's message to Bob: \"{st.session_state['alice_std_dh_message']}\"")
            
            bob_plaintext = st.text_area("Enter Bob's reply to Alice:")
            
            if st.button("Bob Encrypts & Sends"):
                if not bob_plaintext:
                    st.warning("Please enter a reply for Bob to send.")
                else:
                    # Bob encrypts using the shared key
                    bob_encrypted = encrypt(bob_plaintext, shared_secret)
                    
                    st.success("✅ Bob has encrypted his reply with the shared secret key!")
                    st.write("## Encrypted reply:")
                    st.code(bob_encrypted)
                    
                    st.write("## Alice decrypts the reply with her copy of the shared key:")
                    alice_decrypted = decrypt(bob_encrypted, shared_secret)
                    st.info(f"Alice reads: \"{alice_decrypted}\"")
                    
                    # Store Bob's message for Alice's tab
                    st.session_state["bob_std_dh_message"] = bob_plaintext
                    
                    st.success("🔒 Secure communication completed successfully!")
                    st.info("Note: Both Alice and Bob could read each other's messages because they established the same shared secret key through the Diffie-Hellman key exchange.")
        
        # Original simple encryption demo
        st.write("## Standard Encryption Demo")
        plaintext = st.text_input("Enter the plaintext:")
        if st.button("Encrypt"):
            encrypted_text = encrypt(plaintext, shared_secret)
            st.write(f"## :green[Encrypted text]: {encrypted_text}")
            
            decrypted_text = decrypt(encrypted_text, shared_secret)
            st.write(f"## :red[Decrypted text]: {decrypted_text}")

    else:
        st.write("Invalid private keys. Please choose different private keys.")
