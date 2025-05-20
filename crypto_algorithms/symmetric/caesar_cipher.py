"""
Caesar Cipher Implementation
A simple substitution cipher where each letter is shifted by a specified number of positions.
"""

def encrypt(plaintext, shift):
    """
    Encrypts plaintext using Caesar cipher with the given shift.
    
    Args:
        plaintext (str): The text to encrypt
        shift (int): The shift value (key)
        
    Returns:
        str: The encrypted text
    """
    result = ""
    
    for char in plaintext:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Apply the shift and wrap around using modulo
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            # Keep non-alphabetic characters unchanged
            result += char
            
    return result

def decrypt(ciphertext, shift):
    """
    Decrypts ciphertext using Caesar cipher with the given shift.
    
    Args:
        ciphertext (str): The text to decrypt
        shift (int): The shift value (key)
        
    Returns:
        str: The decrypted text
    """
    # Decryption is just encryption with the negative shift
    return encrypt(ciphertext, -shift)

def encrypt_file(file_content, shift):
    """
    Encrypts file content using Caesar cipher.
    
    Args:
        file_content (bytes): The file content to encrypt
        shift (int): The shift value (key)
        
    Returns:
        bytes: The encrypted file content
    """
    try:
        # Try to decode as text
        text = file_content.decode('utf-8')
        encrypted = encrypt(text, shift)
        return encrypted.encode('utf-8')
    except UnicodeDecodeError:
        # If it's not valid UTF-8, treat as binary
        result = bytearray()
        for byte in file_content:
            result.append((byte + shift) % 256)
        return bytes(result)

def decrypt_file(file_content, shift):
    """
    Decrypts file content using Caesar cipher.
    
    Args:
        file_content (bytes): The file content to decrypt
        shift (int): The shift value (key)
        
    Returns:
        bytes: The decrypted file content
    """
    try:
        # Try to decode as text
        text = file_content.decode('utf-8')
        decrypted = decrypt(text, shift)
        return decrypted.encode('utf-8')
    except UnicodeDecodeError:
        # If it's not valid UTF-8, treat as binary
        result = bytearray()
        for byte in file_content:
            result.append((byte - shift) % 256)
        return bytes(result)
