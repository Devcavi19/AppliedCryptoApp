"""
Diffie-Hellman Key Exchange Implementation
A method of securely exchanging cryptographic keys over a public channel.
"""

import os
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class DiffieHellman:
    def __init__(self, parameters=None):
        """
        Initialize a Diffie-Hellman key exchange instance.
        
        Args:
            parameters: Optional DH parameters. If None, generates new parameters.
        """
        self.backend = default_backend()
        if parameters is None:
            # Generate DH parameters with a 2048-bit key size
            self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=self.backend)
        else:
            self.parameters = parameters
        
        # Generate a private key for this peer
        self.private_key = self.parameters.generate_private_key()
        
        # Get the public key to share with the other party
        self.public_key = self.private_key.public_key()
    
    def get_parameters_bytes(self):
        """
        Get the DH parameters as bytes for sharing with the other party.
        
        Returns:
            bytes: The DH parameters serialized to bytes
        """
        return self.parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
    
    def get_public_key_bytes(self):
        """
        Get the public key as bytes for sharing with the other party.
        
        Returns:
            bytes: The public key serialized to bytes
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def load_parameters(parameters_bytes):
        """
        Load DH parameters from bytes.
        
        Args:
            parameters_bytes (bytes): The serialized parameters
            
        Returns:
            DHParameters: The loaded parameters
        """
        return serialization.load_pem_parameters(parameters_bytes, default_backend())
    
    @staticmethod
    def load_public_key(public_key_bytes, parameters):
        """
        Load a public key from bytes.
        
        Args:
            public_key_bytes (bytes): The serialized public key
            parameters: The DH parameters
            
        Returns:
            DHPublicKey: The loaded public key
        """
        return serialization.load_pem_public_key(public_key_bytes, default_backend())
    
    def generate_shared_secret(self, other_public_key):
        """
        Generate a shared secret using the other party's public key.
        
        Args:
            other_public_key: The other party's public key
            
        Returns:
            bytes: The shared secret key
        """
        shared_key = self.private_key.exchange(other_public_key)
        
        # Derive a symmetric key from the shared secret
        # Using SHA-256 to derive a more secure key
        derived_key = hashlib.sha256(shared_key).digest()
        return derived_key

# Simplified version for educational purposes
def simple_diffie_hellman(p, g, private_a=None, private_b=None):
    """
    Simplified Diffie-Hellman key exchange for educational purposes.
    
    Args:
        p (int): A large prime number
        g (int): A generator (primitive root modulo p)
        private_a (int, optional): Alice's private key. If None, randomly generated.
        private_b (int, optional): Bob's private key. If None, randomly generated.
        
    Returns:
        dict: A dictionary with the generated keys and shared secret
    """
    if private_a is None:
        # Generate a random private key for Alice
        private_a = secrets.randbelow(p - 2) + 2
    
    if private_b is None:
        # Generate a random private key for Bob
        private_b = secrets.randbelow(p - 2) + 2
    
    # Calculate public keys
    public_a = pow(g, private_a, p)
    public_b = pow(g, private_b, p)
    
    # Calculate shared secrets (should be the same for both parties)
    shared_secret_a = pow(public_b, private_a, p)
    shared_secret_b = pow(public_a, private_b, p)
    
    # The shared secrets should be equal
    assert shared_secret_a == shared_secret_b
    
    return {
        "private_a": private_a,
        "private_b": private_b,
        "public_a": public_a,
        "public_b": public_b,
        "shared_secret": shared_secret_a
    }

# Utility functions for encryption/decryption with the derived key
def encrypt_with_derived_key(message, derived_key):
    """
    Encrypt a message using a derived key from Diffie-Hellman exchange.
    This is a simple XOR encryption for demonstration purposes.
    
    Args:
        message (bytes): The message to encrypt
        derived_key (bytes): The derived key from DH exchange
        
    Returns:
        bytes: The encrypted message
    """
    # For demonstration, we use a simple XOR with the derived key.
    # In practice, you'd want to use a proper symmetric cipher like AES.
    key_stream = derived_key * (len(message) // len(derived_key) + 1)
    key_stream = key_stream[:len(message)]
    
    result = bytearray()
    for i in range(len(message)):
        result.append(message[i] ^ key_stream[i])
    
    return bytes(result)

def decrypt_with_derived_key(ciphertext, derived_key):
    """
    Decrypt a message using a derived key from Diffie-Hellman exchange.
    
    Args:
        ciphertext (bytes): The encrypted message
        derived_key (bytes): The derived key from DH exchange
        
    Returns:
        bytes: The decrypted message
    """
    # XOR encryption is symmetric, so decryption is the same as encryption
    return encrypt_with_derived_key(ciphertext, derived_key)
