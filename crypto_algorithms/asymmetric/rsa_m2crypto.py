"""
RSA Algorithm Implementation using M2Crypto
A wrapper for M2Crypto's RSA implementation.
"""

import base64
import hashlib

try:
    import M2Crypto
    M2CRYPTO_AVAILABLE = True
except ImportError:
    M2CRYPTO_AVAILABLE = False

class RSAM2Crypto:
    def __init__(self):
        """
        Initialize an RSA instance with M2Crypto.
        """
        if not M2CRYPTO_AVAILABLE:
            raise ImportError("M2Crypto is not available. Please install it using 'pip install M2Crypto'")
        
        self.rsa_key = None
    
    def generate_key_pair(self, key_size=2048):
        """
        Generate a new RSA key pair.
        
        Args:
            key_size (int): The key size in bits (default: 2048)
        """
        self.rsa_key = M2Crypto.RSA.gen_key(key_size, 65537)
        return self.rsa_key
    
    def load_key_pair(self, public_key_pem=None, private_key_pem=None):
        """
        Load an RSA key pair from PEM format strings.
        
        Args:
            public_key_pem (str): The public key in PEM format
            private_key_pem (str): The private key in PEM format (optional)
        """
        if private_key_pem:
            # Load the private key (which includes the public key info)
            bio = M2Crypto.BIO.MemoryBuffer(private_key_pem.encode('utf-8'))
            self.rsa_key = M2Crypto.RSA.load_key_bio(bio)
        elif public_key_pem:
            # Load just the public key
            bio = M2Crypto.BIO.MemoryBuffer(public_key_pem.encode('utf-8'))
            self.rsa_key = M2Crypto.RSA.load_pub_key_bio(bio)
    
    def export_private_key(self, passphrase=None):
        """
        Export the private key in PEM format.
        
        Args:
            passphrase (str): An optional passphrase to encrypt the private key
            
        Returns:
            str: The private key in PEM format
        """
        if not self.rsa_key:
            raise ValueError("No key pair has been generated or loaded")
            
        bio = M2Crypto.BIO.MemoryBuffer()
        if passphrase:
            cipher = 'aes_256_cbc'
            self.rsa_key.save_key_bio(bio, cipher, lambda x: passphrase.encode('utf-8'))
        else:
            self.rsa_key.save_key_bio(bio, cipher=None)
            
        return bio.read_all().decode('utf-8')
    
    def export_public_key(self):
        """
        Export the public key in PEM format.
        
        Returns:
            str: The public key in PEM format
        """
        if not self.rsa_key:
            raise ValueError("No key pair has been generated or loaded")
            
        bio = M2Crypto.BIO.MemoryBuffer()
        self.rsa_key.save_pub_key_bio(bio)
        return bio.read_all().decode('utf-8')
    
    def encrypt(self, data):
        """
        Encrypt data using the public key.
        
        Args:
            data (bytes or str): The data to encrypt
            
        Returns:
            bytes: The encrypted data
        """
        if not self.rsa_key:
            raise ValueError("No key pair has been generated or loaded")
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Use PKCS1 padding for encryption
        encrypted = self.rsa_key.public_encrypt(data, M2Crypto.RSA.pkcs1_padding)
        return encrypted
    
    def decrypt(self, encrypted_data):
        """
        Decrypt data using the private key.
        
        Args:
            encrypted_data (bytes): The encrypted data
            
        Returns:
            bytes: The decrypted data
        """
        if not self.rsa_key:
            raise ValueError("No key pair has been generated or loaded")
            
        if self.rsa_key.check_key() != 1:
            raise ValueError("Invalid private key for decryption")
            
        # Use PKCS1 padding for decryption
        decrypted = self.rsa_key.private_decrypt(encrypted_data, M2Crypto.RSA.pkcs1_padding)
        return decrypted
    
    def sign(self, data, hash_algo='sha256'):
        """
        Sign data with the private key.
        
        Args:
            data (bytes or str): The data to sign
            hash_algo (str): The hash algorithm to use (default: 'sha256')
            
        Returns:
            bytes: The signature
        """
        if not self.rsa_key:
            raise ValueError("No key pair has been generated or loaded")
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Hash the data with specified algorithm
        hash_func = getattr(hashlib, hash_algo)
        data_hash = hash_func(data).digest()
        
        # Sign the hash
        signature = self.rsa_key.sign(data_hash, hash_algo)
        return signature
    
    def verify(self, data, signature, hash_algo='sha256'):
        """
        Verify a signature.
        
        Args:
            data (bytes or str): The original data
            signature (bytes): The signature to verify
            hash_algo (str): The hash algorithm used (default: 'sha256')
            
        Returns:
            bool: True if the signature is valid, False otherwise
        """
        if not self.rsa_key:
            raise ValueError("No key pair has been generated or loaded")
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Hash the data with specified algorithm
        hash_func = getattr(hashlib, hash_algo)
        data_hash = hash_func(data).digest()
        
        # Verify the signature
        try:
            result = self.rsa_key.verify(data_hash, signature, hash_algo)
            return result == 1
        except Exception:
            return False
    
    @staticmethod
    def is_available():
        """Check if M2Crypto is available"""
        return M2CRYPTO_AVAILABLE
