"""
Vernam Cipher (One-Time Pad) Implementation
A theoretically unbreakable cipher when used correctly with truly random keys of the same length as the plaintext.
"""

import secrets  # For generating cryptographically secure random numbers

def generate_key(length):
    """
    Generates a cryptographically secure random key of specified length.
    
    Args:
        length (int): The desired length of the key in bytes
        
    Returns:
        bytes: The generated random key
    """
    return secrets.token_bytes(length)

def encrypt(plaintext, key):
    """
    Encrypts plaintext using Vernam cipher (XOR operation) with the given key.
    The key must be at least as long as the plaintext.
    
    Args:
        plaintext (bytes): The data to encrypt
        key (bytes): The encryption key (must be at least as long as plaintext)
        
    Returns:
        bytes: The encrypted data
    """
    if len(key) < len(plaintext):
        raise ValueError("Key must be at least as long as the plaintext")
    
    result = bytearray()
    for i in range(len(plaintext)):
        # XOR operation between plaintext byte and key byte
        result.append(plaintext[i] ^ key[i])
    
    return bytes(result)

def decrypt(ciphertext, key):
    """
    Decrypts ciphertext using Vernam cipher (XOR operation) with the given key.
    The key must be the same as used for encryption.
    
    Args:
        ciphertext (bytes): The data to decrypt
        key (bytes): The decryption key
        
    Returns:
        bytes: The decrypted data
    """
    # XOR is its own inverse, so encryption and decryption are the same operation
    return encrypt(ciphertext, key)

def encrypt_text(text, key=None):
    """
    Encrypts text using Vernam cipher.
    If key is not provided, generates a random key.
    
    Args:
        text (str): The text to encrypt
        key (bytes, optional): The encryption key. If None, generates a random key.
        
    Returns:
        tuple: (ciphertext bytes, key bytes)
    """
    plaintext_bytes = text.encode('utf-8')
    if key is None:
        key = generate_key(len(plaintext_bytes))
    elif len(key) < len(plaintext_bytes):
        raise ValueError("Key must be at least as long as the plaintext")
        
    ciphertext = encrypt(plaintext_bytes, key)
    return ciphertext, key

def decrypt_text(ciphertext, key):
    """
    Decrypts text using Vernam cipher.
    
    Args:
        ciphertext (bytes): The encrypted data
        key (bytes): The decryption key
        
    Returns:
        str: The decrypted text
    """
    plaintext_bytes = decrypt(ciphertext, key)
    try:
        return plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return "[Error: Could not decode result as UTF-8]"

def encrypt_file(file_content, key=None):
    """
    Encrypts file content using Vernam cipher.
    If key is not provided, generates a random key.
    
    Args:
        file_content (bytes): The file content to encrypt
        key (bytes, optional): The encryption key. If None, generates a random key.
        
    Returns:
        tuple: (encrypted file content bytes, key bytes)
    """
    if key is None:
        key = generate_key(len(file_content))
    elif len(key) < len(file_content):
        raise ValueError("Key must be at least as long as the file content")
        
    ciphertext = encrypt(file_content, key)
    return ciphertext, key

def decrypt_file(file_content, key):
    """
    Decrypts file content using Vernam cipher.
    
    Args:
        file_content (bytes): The file content to decrypt
        key (bytes): The decryption key
        
    Returns:
        bytes: The decrypted file content
    """
    return decrypt(file_content, key)
