"""
Diffie-Hellman implementation using M2Crypto
A wrapper for M2Crypto's DH implementation.
"""

try:
    import M2Crypto
    M2CRYPTO_AVAILABLE = True
except ImportError:
    M2CRYPTO_AVAILABLE = False

class DiffieHellmanM2Crypto:
    """
    Diffie-Hellman key exchange implementation using M2Crypto.
    Provides methods for secure key exchange between two parties.
    """
    
    def __init__(self):
        """Initialize the Diffie-Hellman object."""
        if not M2CRYPTO_AVAILABLE:
            raise ImportError("M2Crypto is not available. Please install it using 'pip install M2Crypto'")
        
        self.dh = None
        self.p = None  # Prime
        self.g = None  # Generator
        self.private_key = None
        self.public_key = None
    
    def generate_parameters(self, bits=512):
        """
        Generate Diffie-Hellman parameters.
        
        Args:
            bits (int): The bit length of the prime number (default: 512)
        
        Returns:
            tuple: (p, g) - the prime and generator
        """
        self.dh = M2Crypto.DH.gen_params(bits, 2)  # Using 2 as generator
        self.p = self.dh.p
        self.g = self.dh.g
        return self.p, self.g
    
    def set_parameters(self, p, g):
        """
        Set the Diffie-Hellman parameters.
        
        Args:
            p (int): The prime number
            g (int): The generator
        """
        self.p = p
        self.g = g
        self.dh = M2Crypto.DH.set_params(p, g)
    
    def generate_keys(self):
        """
        Generate the private and public keys.
        
        Returns:
            int: The public key
        """
        if not self.dh:
            raise ValueError("Parameters must be set or generated first")
        
        # M2Crypto DH automatically generates a random private key internally
        self.dh.gen_key()
        self.public_key = self.dh.pub
        return self.public_key
    
    def set_private_key(self, private_key):
        """
        Set the private key.
        
        Args:
            private_key (int): The private key value
        """
        if not self.dh:
            raise ValueError("Parameters must be set or generated first")
        
        self.private_key = private_key
        self.dh.set_x(private_key)
        self.dh.gen_key()
        self.public_key = self.dh.pub
    
    def compute_shared_secret(self, other_public_key):
        """
        Compute the shared secret using the other party's public key.
        
        Args:
            other_public_key (int): The other party's public key
        
        Returns:
            bytes: The shared secret
        """
        if not self.dh:
            raise ValueError("Parameters must be set or generated first")
        
        shared_key = self.dh.compute_key(other_public_key)
        return shared_key
    
    @staticmethod
    def is_available():
        """Check if M2Crypto is available."""
        return M2CRYPTO_AVAILABLE
