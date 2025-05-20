"""
Hash Function Implementations (SHA-1, SHA-256, SHA-512, MD5)
Various cryptographic hash functions for data integrity.
"""

import hashlib

def sha1_hash(data):
    """
    Calculate the SHA-1 hash of data.
    
    Args:
        data: Data to hash (string or bytes)
        
    Returns:
        str: The hexadecimal hash value
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_obj = hashlib.sha1(data)
    return hash_obj.hexdigest()

def sha256_hash(data):
    """
    Calculate the SHA-256 hash of data.
    
    Args:
        data: Data to hash (string or bytes)
        
    Returns:
        str: The hexadecimal hash value
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_obj = hashlib.sha256(data)
    return hash_obj.hexdigest()

def sha512_hash(data):
    """
    Calculate the SHA-512 hash of data.
    
    Args:
        data: Data to hash (string or bytes)
        
    Returns:
        str: The hexadecimal hash value
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_obj = hashlib.sha512(data)
    return hash_obj.hexdigest()

def md5_hash(data):
    """
    Calculate the MD5 hash of data.
    
    Args:
        data: Data to hash (string or bytes)
        
    Returns:
        str: The hexadecimal hash value
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_obj = hashlib.md5(data)
    return hash_obj.hexdigest()

def file_hash(file_path, algorithm='sha256'):
    """
    Calculate the hash of a file.
    
    Args:
        file_path (str): The path to the file
        algorithm (str): The hash algorithm to use ('md5', 'sha1', or 'sha256')
        
    Returns:
        str: The hexadecimal hash value
    """
    hash_func = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }.get(algorithm.lower())
    
    if hash_func is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    with open(file_path, 'rb') as f:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def hash_data(data, algorithm='sha256'):
    """
    Calculate the hash of data using the specified algorithm.
    
    Args:
        data: Data to hash (string or bytes)
        algorithm (str): The hash algorithm to use ('md5', 'sha1', or 'sha256')
        
    Returns:
        str: The hexadecimal hash value
    """
    if algorithm.lower() == 'md5':
        return md5_hash(data)
    elif algorithm.lower() == 'sha1':
        return sha1_hash(data)
    elif algorithm.lower() == 'sha256':
        return sha256_hash(data)
    elif algorithm.lower() == 'sha512':
        return sha512_hash(data)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
