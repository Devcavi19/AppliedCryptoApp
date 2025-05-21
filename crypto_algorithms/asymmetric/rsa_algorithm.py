"""
RSA Algorithm Implementation
A widely used public-key encryption method.
"""

import rsa
import base64
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class RSA:
    def __init__(self):
        """
        Initialize an RSA instance with a new key pair.
        """
        self.private_key = None
        self.public_key = None
        self.crypto_private_key = None
        self.crypto_public_key = None
    
    def generate_key_pair(self, key_size=2048):
        """
        Generate a new RSA key pair.
        
        Args:
            key_size (int): The key size in bits (default: 2048)
        """
        # Generate keys using the rsa library
        (pubkey, privkey) = rsa.newkeys(key_size)
        self.public_key = pubkey
        self.private_key = privkey
        
        # Also generate keys using cryptography library for more advanced features
        self.crypto_private_key = crypto_rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.crypto_public_key = self.crypto_private_key.public_key()
    
    def load_key_pair(self, public_key_pem=None, private_key_pem=None):
        """
        Load an RSA key pair from PEM format strings.
        
        Args:
            public_key_pem (str): The public key in PEM format
            private_key_pem (str): The private key in PEM format (optional)
        """
        if public_key_pem:
            self.crypto_public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
        if private_key_pem:
            self.crypto_private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            self.crypto_public_key = self.crypto_private_key.public_key()
    
    def export_public_key(self):
        """
        Export the public key in PEM format.
        
        Returns:
            str: The public key in PEM format
        """
        if self.crypto_public_key:
            return self.crypto_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        return None
    
    def export_private_key(self):
        """
        Export the private key in PEM format.
        
        Returns:
            str: The private key in PEM format
        """
        if self.crypto_private_key:
            return self.crypto_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        return None
    
    def encrypt(self, message):
        """
        Encrypt a message using the public key.
        
        Args:
            message (str): The message to encrypt
            
        Returns:
            bytes: The encrypted message
        """
        if self.public_key:  # Using rsa library
            try:
                # Simple encryption with rsa library
                return rsa.encrypt(message.encode('utf-8'), self.public_key)
            except:
                pass
        
        if self.crypto_public_key:  # Using cryptography library
            try:
                # More secure encryption with cryptography library
                ciphertext = self.crypto_public_key.encrypt(
                    message.encode('utf-8'),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return ciphertext
            except:
                pass
        
        raise Exception("No valid public key available for encryption")
    
    def decrypt(self, ciphertext):
        """
        Decrypt a message using the private key.
        
        Args:
            ciphertext (bytes): The encrypted message
            
        Returns:
            str: The decrypted message
        """
        if self.private_key:  # Using rsa library
            try:
                # Simple decryption with rsa library
                return rsa.decrypt(ciphertext, self.private_key).decode('utf-8')
            except:
                pass
        
        if self.crypto_private_key:  # Using cryptography library
            try:
                # More secure decryption with cryptography library
                plaintext = self.crypto_private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return plaintext.decode('utf-8')
            except:
                pass
        
        raise Exception("No valid private key available for decryption")
    
    def sign(self, message):
        """
        Create a digital signature for a message.
        
        Args:
            message (str): The message to sign
            
        Returns:
            bytes: The signature
        """
        if self.private_key:  # Using rsa library
            try:
                # Simple signing with rsa library
                return rsa.sign(message.encode('utf-8'), self.private_key, 'SHA-256')
            except:
                pass
        
        if self.crypto_private_key:  # Using cryptography library
            try:
                # More secure signing with cryptography library
                signature = self.crypto_private_key.sign(
                    message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return signature
            except:
                pass
        
        raise Exception("No valid private key available for signing")
    
    def verify(self, message, signature):
        """
        Verify a digital signature for a message.
        
        Args:
            message (str): The message to verify
            signature (bytes): The signature to verify
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        if self.public_key:  # Using rsa library
            try:
                # Simple verification with rsa library
                rsa.verify(message.encode('utf-8'), signature, self.public_key)
                return True
            except:
                pass
        
        if self.crypto_public_key:  # Using cryptography library
            try:
                # More secure verification with cryptography library
                self.crypto_public_key.verify(
                    signature,
                    message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except:
                pass
        
        return False

# Utility functions for easier use
def generate_key_pair(key_size=2048):
    """
    Generate an RSA key pair.
    
    Args:
        key_size (int): The key size in bits (default: 2048)
        
    Returns:
        tuple: (public_key, private_key)
    """
    rsa_instance = RSA()
    rsa_instance.generate_key_pair(key_size)
    return rsa_instance.export_public_key(), rsa_instance.export_private_key()

def encrypt_with_public_key(message, public_key_pem):
    """
    Encrypt a message using a public key.
    
    Args:
        message (str): The message to encrypt
        public_key_pem (str): The public key in PEM format
        
    Returns:
        str: The encrypted message in base64 format
    """
    rsa_instance = RSA()
    rsa_instance.load_key_pair(public_key_pem=public_key_pem)
    encrypted = rsa_instance.encrypt(message)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_with_private_key(encrypted_message_base64, private_key_pem):
    """
    Decrypt a message using a private key.
    
    Args:
        encrypted_message_base64 (str): The encrypted message in base64 format
        private_key_pem (str): The private key in PEM format
        
    Returns:
        str: The decrypted message
    """
    rsa_instance = RSA()
    rsa_instance.load_key_pair(private_key_pem=private_key_pem)
    encrypted = base64.b64decode(encrypted_message_base64)
    return rsa_instance.decrypt(encrypted)

# Add helper functions for simpler usage in the app
def encrypt_message(message_bytes, public_key):
    """
    Encrypt a message using a public key.
    
    Args:
        message_bytes (bytes): The message to encrypt as bytes
        public_key: The public key object
        
    Returns:
        bytes: The encrypted message
    """
    try:
        # Use the cryptography library for encryption
        ciphertext = public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    except Exception as e:
        raise Exception(f"Encryption error: {str(e)}")

def decrypt_message(ciphertext, private_key):
    """
    Decrypt a message using a private key.
    
    Args:
        ciphertext (bytes): The encrypted message
        private_key: The private key object
        
    Returns:
        str: The decrypted message
    """
    try:
        # Use the cryptography library for decryption
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    except Exception as e:
        raise Exception(f"Decryption error: {str(e)}")

# Function to generate keys for the app
def generate_keys(key_size=2048):
    """
    Generate a new RSA key pair and return both keys.
    
    Args:
        key_size (int): The key size in bits
        
    Returns:
        dict: Dictionary containing public and private key objects
    """
    # Generate private key
    private_key = crypto_rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    return {
        'public_key': public_key,
        'private_key': private_key
    }
