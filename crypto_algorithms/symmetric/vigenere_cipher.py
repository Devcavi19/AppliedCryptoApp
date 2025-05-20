"""
Vigenère Cipher Implementation
A polyalphabetic substitution cipher that uses a keyword to shift letters.
"""

def generate_key(message, key):
    """
    Generates a key stream that is as long as the message by repeating the key.
    
    Args:
        message (str): The message to be encrypted
        key (str): The encryption key
        
    Returns:
        str: The generated key stream
    """
    key = key.upper()
    # Remove non-alphabetic characters from the key
    key = ''.join(char for char in key if char.isalpha())
    if not key:
        raise ValueError("Key must contain at least one alphabetic character")
        
    key_stream = ""
    key_index = 0
    
    for char in message:
        if char.isalpha():
            key_stream += key[key_index % len(key)]
            key_index += 1
        else:
            key_stream += ' '  # Use space as placeholder for non-alphabetic chars
            
    return key_stream

def encrypt(plaintext, key):
    """
    Encrypts plaintext using Vigenère cipher with the given key.
    
    Args:
        plaintext (str): The text to encrypt
        key (str): The encryption key
        
    Returns:
        str: The encrypted text
    """
    key_stream = generate_key(plaintext, key)
    result = ""
    
    for i, char in enumerate(plaintext):
        if char.isalpha():
            # Determine the ASCII offset based on case
            is_upper = char.isupper()
            ascii_offset = ord('A') if is_upper else ord('a')
            
            # Get the corresponding key character and its value (0-25)
            key_char = key_stream[i]
            if key_char != ' ':
                key_val = ord(key_char) - ord('A')
                
                # Apply the shift and wrap around using modulo
                shifted = (ord(char) - ascii_offset + key_val) % 26 + ascii_offset
                result += chr(shifted)
            else:
                result += char
        else:
            result += char
            
    return result

def decrypt(ciphertext, key):
    """
    Decrypts ciphertext using Vigenère cipher with the given key.
    
    Args:
        ciphertext (str): The text to decrypt
        key (str): The decryption key
        
    Returns:
        str: The decrypted text
    """
    key_stream = generate_key(ciphertext, key)
    result = ""
    
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            # Determine the ASCII offset based on case
            is_upper = char.isupper()
            ascii_offset = ord('A') if is_upper else ord('a')
            
            # Get the corresponding key character and its value (0-25)
            key_char = key_stream[i]
            if key_char != ' ':
                key_val = ord(key_char) - ord('A')
                
                # Apply the reverse shift and wrap around using modulo
                shifted = (ord(char) - ascii_offset - key_val) % 26 + ascii_offset
                result += chr(shifted)
            else:
                result += char
        else:
            result += char
            
    return result

def encrypt_file(file_content, key):
    """
    Encrypts file content using Vigenère cipher.
    
    Args:
        file_content (bytes): The file content to encrypt
        key (str): The encryption key
        
    Returns:
        bytes: The encrypted file content
    """
    try:
        # Try to decode the file content as text
        text = file_content.decode('utf-8')
        encrypted_text = encrypt(text, key)
        return encrypted_text.encode('utf-8')
    except UnicodeDecodeError:
        # If the file is binary, treat each byte as a number
        # and apply Vigenère cipher numerically
        result = bytearray()
        key_bytes = key.encode('utf-8')
        key_len = len(key_bytes)
        
        for i, byte in enumerate(file_content):
            key_byte = key_bytes[i % key_len]
            # Apply Vigenère shift in the byte domain (0-255)
            encrypted_byte = (byte + key_byte) % 256
            result.append(encrypted_byte)
            
        return bytes(result)

def decrypt_file(file_content, key):
    """
    Decrypts file content using Vigenère cipher.
    
    Args:
        file_content (bytes): The file content to decrypt
        key (str): The decryption key
        
    Returns:
        bytes: The decrypted file content
    """
    try:
        # Try to decode the file content as text
        text = file_content.decode('utf-8')
        decrypted_text = decrypt(text, key)
        return decrypted_text.encode('utf-8')
    except UnicodeDecodeError:
        # If the file is binary, treat each byte as a number
        # and apply reverse Vigenère cipher numerically
        result = bytearray()
        key_bytes = key.encode('utf-8')
        key_len = len(key_bytes)
        
        for i, byte in enumerate(file_content):
            key_byte = key_bytes[i % key_len]
            # Apply reverse Vigenère shift in the byte domain (0-255)
            decrypted_byte = (byte - key_byte) % 256
            result.append(decrypted_byte)
            
        return bytes(result)
