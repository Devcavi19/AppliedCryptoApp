<div style="background-color: white; padding: 20px;">
 
<p align="center">
 <img height=200px src="./images/header.png" alt="Applied Cryptography App">
</p>

<h2 align="center">Applied Cryptography Final Project - CSAC 329</h2>

<div align="center">

[![Python version](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Streamlit version](https://img.shields.io/badge/streamlit-1.29.0-red.svg)](https://streamlit.io/)
[![Cryptography version](https://img.shields.io/badge/cryptography-41.0.0-green.svg)](https://cryptography.io/en/latest/)


<h4>This repository is intended for academic purposes only, specifically for the Applied Cryptography course (CSAC 329). This application provides implementations of various cryptographic algorithms including symmetric encryption, asymmetric encryption, and hash functions.</h4>

</div>

-----------------------------------------

### Project Overview

* This application provides a comprehensive showcase of various cryptographic algorithms. It includes implementations of symmetric encryption, asymmetric encryption, and hash functions with an interactive Streamlit interface for educational purposes. Users can explore each algorithm's workings, encrypt/decrypt messages, generate keys, and visualize the cryptographic processes.

### Members (Group 2):
- Herald Carl Avila
- Jamaica Mae Rosales
- Kaye Khrysna Olores

------------------------------------------
### Features

#### Symmetric Algorithms

* **Caesar Cipher** - A simple substitution cipher with fixed shifting
* **Vigenère Cipher** - A polyalphabetic substitution cipher that uses a keyword to determine variable shifts
* **Vernam Cipher** (One-Time Pad) - A theoretically unbreakable cipher when used with a truly random key of the same length as the plaintext

<p align="center">
 <img height=400px src="./images/symmetric_demo.gif" alt="Symmetric Encryption Demo">
</p>

<br> 

------------------------------------------

#### Asymmetric Algorithms

* **Diffie-Hellman** - Used for secure key exchange between parties
* **RSA** - A widely used public-key encryption method for secure communications

<p align="center">
 <img height=400px src="./images/asymmetric_demo.gif" alt="Asymmetric Encryption Demo">
</p>

<br> 

------------------------------------------

#### Hash Functions

* **SHA-1** - A cryptographic hash function (now considered cryptographically broken)
* **SHA-256** - A more secure variant of SHA
* **SHA-512** - An even stronger cryptographic hash function
* **MD5** - A widely used hash function (now considered cryptographically broken)

<p align="center">
 <img height=400px src="./images/hash_demo.gif" alt="Hash Functions Demo">
</p>

<br>

------------------------------------------

### Implementation Details

This repository contains the implementation of various cryptographic algorithms. The project uses the following key technologies and concepts:

1. **Streamlit** - Streamlit is an open-source app framework for Machine Learning and Data Science teams. This project uses Streamlit for its user interface to provide an interactive experience for exploring cryptographic algorithms. - [Streamlit Documentation](https://docs.streamlit.io/)

2. **Cryptography Library** - The Python cryptography library provides cryptographic recipes and primitives. This application uses it for enhanced security operations and modern implementations of cryptographic algorithms. - [Cryptography Documentation](https://cryptography.io/en/latest/)

3. **Custom Algorithm Implementations** - For educational purposes, many algorithms are implemented from scratch to demonstrate their inner workings while also comparing with industry-standard implementations.

------------------------------------------

### Prerequisites

1. [Python 3.12+](https://www.python.org/downloads/)
2. Required Python packages (see requirements.txt)

------------------------------------------
### Installation

* Step I: Clone the Repository
```sh
      $ git clone https://github.com/Devcavi19/AppliedCryptoApp.git
```

* Step II: Install the required packages
```sh
      # On the terminal, move into the AppliedCryptoApp directory
      $ cd AppliedCryptoApp
      $ pip install -r requirements.txt
```

* Step III: Run the application
```sh
      # To run the Streamlit application
      $ streamlit run AppliedCryptoApp.py
```

------------------------------------------
### File Structure

```
AppliedCryptoApp/
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
│   │   └── diffie_hellman.py   # Diffie-Hellman implementation
│   └── hash/                   # Hash functions
│       └── hash_functions.py   # SHA-1, SHA-256, SHA-512, MD5 implementations
└── pages/                      # Streamlit pages for each algorithm category
    ├── 0_Symmetric.py          # Symmetric encryption UI
    ├── 1_Hashing.py            # Hash functions UI
    └── 2_Assymetric.py         # Asymmetric encryption UI
```

------------------------------------------
### Contributors

- Herald Carl Avila - [GitHub](https://github.com/Devcavi19)
- Jamaica Mae Rosales - [GitHub](https://github.com/IamJamm)
- Kaye Khrysna Olores - [GitHub](https://github.com/kikisna)

------------------------------------------
</div>
