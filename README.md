# Applied Cryptography Final Project

## Project Overview

This application provides implementations of various cryptographic algorithms including symmetric encryption, asymmetric encryption, and hash functions.

### Members (Group 2):
- Herald Carl Avila
- Jamaica Mae Rosales
- Kaye Khrysna Olores

## Features

### Symmetric Algorithms
- **Caesar Cipher** - A simple substitution cipher with fixed shifting
- **Vigenère Cipher** - A polyalphabetic substitution cipher that uses a keyword to determine variable shifts
- **Vernam Cipher** (One-Time Pad) - A theoretically unbreakable cipher when used with a truly random key of the same length as the plaintext

### Asymmetric Algorithms
- **Diffie-Hellman** - Used for secure key exchange
- **RSA** - A widely used public-key encryption method

### Hash Functions
- **SHA-1** - A cryptographic hash function
- **SHA-256** - A more secure variant of SHA
- **SHA-512** - An even stronger cryptographic hash function
- **MD5** - A widely used hash function (now considered cryptographically broken)



## Installation

1. Clone this repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

### M2Crypto Support

This application supports M2Crypto for enhanced cryptographic operations. M2Crypto is a Python wrapper for OpenSSL that offers better performance and additional features.

If you encounter issues with the default crypto libraries, the application will automatically fall back to alternative implementations.

## Running the Application

To run the application, use the command:
```
streamlit run AppliedCryptoApp.py
```

## File Structure

```
cryptographic-app-main/
├── AppliedCryptoApp.py         # Main application entry point
├── README.md                   # This file
├── requirements.txt            # Required Python packages
├── crypto_algorithms/          # Core algorithm implementations
│   ├── symmetric/              # Symmetric encryption algorithms
│   │   ├── caesar_cipher.py    # Caesar cipher implementation
│   │   ├── vigenere_cipher.py  # Vigenère cipher implementation
│   │   └── vernam_cipher.py    # Vernam cipher implementation
│   ├── asymmetric/             # Asymmetric encryption algorithms
│   │   ├── rsa_algorithm.py    # RSA implementation
│   │   ├── rsa_m2crypto.py     # M2Crypto RSA implementation
│   │   ├── diffie_hellman.py   # Diffie-Hellman implementation
│   │   └── diffie_hellman_m2crypto.py # M2Crypto Diffie-Hellman implementation
│   └── hash/                   # Hash functions
│       └── hash_functions.py   # SHA-1, SHA-256, SHA-512, MD5 implementations
└── pages/                      # Streamlit pages for each algorithm category
    ├── 0_Symmetric.py          # Symmetric encryption UI
    ├── 1_Hashing.py            # Hash functions UI
    └── 2_Assymetric.py         # Asymmetric encryption UI
```
