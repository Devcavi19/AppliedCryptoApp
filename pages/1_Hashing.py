"""
Hash Functions Page
Implements SHA-1, SHA-256, SHA-512, MD5, and file integrity verification
"""

import streamlit as st

# Must be the first Streamlit command
st.set_page_config(
    page_title="Hash Functions",
    page_icon="https://img.icons8.com/?size=100&id=WMWP1MqUZRiS&format=png&color=000000",
)

import hashlib
import sys
import os
import base64

# Add the parent directory to sys.path to allow importing from crypto_algorithms
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the hash functions
from crypto_algorithms.hash.hash_functions import hash_data, file_hash, sha1_hash, sha256_hash, sha512_hash, md5_hash

st.markdown("<h1 style='color: #00ffa2ff;'>Hash Functions</h1>", unsafe_allow_html=True)
st.write("Hash functions convert data of arbitrary size to a fixed-size value, used for data integrity verification.")

hash_type = st.selectbox("Select Hashing Algorithm", ["MD5", "SHA-1", "SHA-256", "SHA-512", "Compare Multiple Hashes"])

st.sidebar.subheader("📘 Hash Function Description")
if st.sidebar.checkbox("Show Description"):
    if hash_type == "MD5":
        st.sidebar.write("""
        ### MD5 Hash:
        MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It's commonly used to verify data integrity.
        
        **Security Level:** Low (not collision-resistant, should not be used for security-critical applications)
        
        **Applications:** File integrity checks, non-security-critical checksums
        """)
    elif hash_type == "SHA-1":
        st.sidebar.write("""
        ### SHA-1 Hash:
        SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function that produces a 160-bit (20-byte) hash value. Like MD5, SHA-1 is also used to verify data integrity.
        
        **Security Level:** Low-Medium (vulnerable to collision attacks)
        
        **Applications:** Legacy systems, version control systems (like Git)
        """)
    elif hash_type == "SHA-256":
        st.sidebar.write("""
        ### SHA-256 Hash:
        SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It is part of the SHA-2 family of hashing algorithms.
        
        **Security Level:** High (currently considered secure)
        
        **Applications:** Digital signatures, password storage, blockchain technology, SSL/TLS certificates
        """)
    elif hash_type == "SHA-512":
        st.sidebar.write("""
        ### SHA-512 Hash:
        SHA-512 (Secure Hash Algorithm 512-bit) is a cryptographic hash function that produces a 512-bit (64-byte) hash value. It is also part of the SHA-2 family and offers even stronger security than SHA-256.
        
        **Security Level:** Very High (currently considered very secure)
        
        **Applications:** Critical systems, high-security applications, government and military systems, protecting highly sensitive data
        """)
    elif hash_type == "Compare Multiple Hashes":
        st.sidebar.write("""
        ### Compare Multiple Hashes:
        This feature allows you to compare MD5, SHA-1, and SHA-256 hashes of the same input data to observe the differences between hash functions.
        
        **Use Cases:**
        - Understanding the differences in hash length and patterns
        - Verifying data integrity using multiple hash functions for increased reliability
        - Educational purposes to demonstrate how different hash functions process the same input
        """)

st.sidebar.subheader("🔍 Process")
if st.sidebar.checkbox("Show Process"):
    st.sidebar.write("""
    #### How Hash Functions Work:
    1. Input data of any size is processed (text or file content).
    2. The hashing algorithm processes the data through complex mathematical operations.
    3. The result is a fixed-size hash value (digest) that is unique to the input.
    4. Even a small change in the input produces a completely different hash value.
    5. The process is one-way: you cannot derive the original input from the hash value.
    
    **Key Properties:**
    - Deterministic: Same input always produces the same output
    - Fast computation
    - Preimage resistance: Hard to reverse
    - Small changes in input cause significant changes in output (avalanche effect)
    """)

option = st.radio("Choose Input Option", ("Enter Text", "Upload File", "Verify File Integrity"))

if option == "Enter Text":
    user_input = st.text_area("Enter TEXT: ")
    if st.button("Generate Hash"):
        if user_input:
            if hash_type == "MD5":
                result = md5_hash(user_input)
                st.success(f"MD5 Hash: `{result}`")
                st.info("**Note:** MD5 is considered cryptographically broken and unsuitable for security applications.")
            
            elif hash_type == "SHA-1":
                result = sha1_hash(user_input)
                st.success(f"SHA-1 Hash: `{result}`")
                st.info("**Note:** SHA-1 is considered weak against determined attackers.")
            
            elif hash_type == "SHA-256":
                result = sha256_hash(user_input)
                st.success(f"SHA-256 Hash: `{result}`")
                st.info("SHA-256 is currently considered secure for most applications.")
            
            elif hash_type == "SHA-512":
                result = sha512_hash(user_input)
                st.success(f"SHA-512 Hash: `{result}`")
                st.info("SHA-512 provides very high security with its 512-bit output length.")
            
            elif hash_type == "Compare Multiple Hashes":
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("MD5 (128 bits)")
                    md5_result = md5_hash(user_input)
                    st.code(md5_result)
                    st.text(f"Length: {len(md5_result)} chars")
                
                with col2:
                    st.subheader("SHA-1 (160 bits)")
                    sha1_result = sha1_hash(user_input)
                    st.code(sha1_result)
                    st.text(f"Length: {len(sha1_result)} chars")
                
                col3, col4 = st.columns(2)
                
                with col3:
                    st.subheader("SHA-256 (256 bits)")
                    sha256_result = sha256_hash(user_input)
                    st.code(sha256_result)
                    st.text(f"Length: {len(sha256_result)} chars")
                
                with col4:
                    st.subheader("SHA-512 (512 bits)")
                    sha512_result = sha512_hash(user_input)
                    st.code(sha512_result)
                    st.text(f"Length: {len(sha512_result)} chars")
                
                # Show the effects of changing a single character
                st.subheader("Avalanche Effect Demonstration")
                if len(user_input) > 0:
                    modified_input = user_input[:-1] + ('A' if user_input[-1] != 'A' else 'B')
                    
                    st.markdown(f"Original text: `{user_input}`")
                    st.markdown(f"Modified text (last char changed): `{modified_input}`")
                    
                    # Show SHA-256 comparison
                    st.write("#### SHA-256 Comparison")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Original SHA-256 hash:**")
                        st.code(sha256_result)
                    
                    with col2:
                        st.markdown("**Modified SHA-256 hash:**")
                        modified_hash_256 = sha256_hash(modified_input)
                        st.code(modified_hash_256)
                    
                    # Calculate how many bits are different for SHA-256
                    original_bits_256 = ''.join(format(ord(c), '08b') for c in sha256_result)
                    modified_bits_256 = ''.join(format(ord(c), '08b') for c in modified_hash_256)
                    diff_count_256 = sum(a != b for a, b in zip(original_bits_256, modified_bits_256))
                    
                    # Show SHA-512 comparison
                    st.write("#### SHA-512 Comparison")
                    col3, col4 = st.columns(2)
                    
                    sha512_original = sha512_hash(user_input)
                    sha512_modified = sha512_hash(modified_input)
                    
                    with col3:
                        st.markdown("**Original SHA-512 hash:**")
                        st.code(sha512_original)
                    
                    with col4:
                        st.markdown("**Modified SHA-512 hash:**")
                        st.code(sha512_modified)
                    
                    # Calculate how many bits are different for SHA-512
                    original_bits_512 = ''.join(format(ord(c), '08b') for c in sha512_original)
                    modified_bits_512 = ''.join(format(ord(c), '08b') for c in sha512_modified)
                    diff_count_512 = sum(a != b for a, b in zip(original_bits_512, modified_bits_512))
                    
                    st.info(f"Changing just one character results in approximately {diff_count_256} bits changing in the SHA-256 hash and {diff_count_512} bits changing in the SHA-512 hash, demonstrating the avalanche effect.")
                    
                    # Display the percentage of bits that changed
                    percent_256 = (diff_count_256 / len(original_bits_256)) * 100
                    percent_512 = (diff_count_512 / len(original_bits_512)) * 100
                    st.success(f"Percentage of bits changed: SHA-256: {percent_256:.2f}%, SHA-512: {percent_512:.2f}%")
                    st.info("A good hash function should change about 50% of the bits when the input is slightly modified.")
        else:
            st.warning("Please enter text to hash.")

elif option == "Upload File":
    uploaded_file = st.file_uploader("Choose a file", type=None)
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue()
        
        if hash_type == "MD5":
            result = md5_hash(file_content)
            st.success(f"MD5 Hash of {uploaded_file.name}: `{result}`")
            # Create a text file with the hash
            hash_file_content = f"MD5 hash of {uploaded_file.name}: {result}"
            st.download_button(
                label="Download Hash as Text File",
                data=hash_file_content,
                file_name=f"{uploaded_file.name}.md5.txt",
                mime="text/plain"
            )
        
        elif hash_type == "SHA-1":
            result = sha1_hash(file_content)
            st.success(f"SHA-1 Hash of {uploaded_file.name}: `{result}`")
            hash_file_content = f"SHA-1 hash of {uploaded_file.name}: {result}"
            st.download_button(
                label="Download Hash as Text File",
                data=hash_file_content,
                file_name=f"{uploaded_file.name}.sha1.txt",
                mime="text/plain"
            )
        
        elif hash_type == "SHA-256":
            result = sha256_hash(file_content)
            st.success(f"SHA-256 Hash of {uploaded_file.name}: `{result}`")
            hash_file_content = f"SHA-256 hash of {uploaded_file.name}: {result}"
            st.download_button(
                label="Download Hash as Text File",
                data=hash_file_content,
                file_name=f"{uploaded_file.name}.sha256.txt",
                mime="text/plain"
            )
        
        elif hash_type == "SHA-512":
            result = sha512_hash(file_content)
            st.success(f"SHA-512 Hash of {uploaded_file.name}: `{result}`")
            hash_file_content = f"SHA-512 hash of {uploaded_file.name}: {result}"
            st.download_button(
                label="Download Hash as Text File",
                data=hash_file_content,
                file_name=f"{uploaded_file.name}.sha512.txt",
                mime="text/plain"
            )
        
        elif hash_type == "Compare Multiple Hashes":
            st.subheader(f"Hash Values for {uploaded_file.name}")
            
            col1, col2 = st.columns(2)
            
            with col1:
                md5_result = md5_hash(file_content)
                st.markdown("**MD5 Hash:**")
                st.code(md5_result)
            
            with col2:
                sha1_result = sha1_hash(file_content)
                st.markdown("**SHA-1 Hash:**")
                st.code(sha1_result)
            
            col3, col4 = st.columns(2)
            
            with col3:
                sha256_result = sha256_hash(file_content)
                st.markdown("**SHA-256 Hash:**")
                st.code(sha256_result)
            
            with col4:
                sha512_result = sha512_hash(file_content)
                st.markdown("**SHA-512 Hash:**")
                st.code(sha512_result)
            
            # Create a text file with all hashes
            hash_file_content = f"""File: {uploaded_file.name}
MD5: {md5_result}
SHA-1: {sha1_result}
SHA-256: {sha256_result}
SHA-512: {sha512_result}
File size: {len(file_content)} bytes
"""
            st.download_button(
                label="Download All Hashes as Text File",
                data=hash_file_content,
                file_name=f"{uploaded_file.name}.hashes.txt",
                mime="text/plain"
            )

elif option == "Verify File Integrity":
    st.write("## File Integrity Verification")
    st.write("Upload a file and provide its expected hash value to verify its integrity.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        uploaded_file = st.file_uploader("Choose a file to verify", type=None)
    
    with col2:
        verification_method = st.selectbox("Hash Algorithm", ["MD5", "SHA-1", "SHA-256", "SHA-512"])
        expected_hash = st.text_input("Expected Hash Value")
    
    if uploaded_file is not None and expected_hash:
        file_content = uploaded_file.getvalue()
        
        if verification_method == "MD5":
            actual_hash = md5_hash(file_content)
        elif verification_method == "SHA-1":
            actual_hash = sha1_hash(file_content)
        elif verification_method == "SHA-256":
            actual_hash = sha256_hash(file_content)
        elif verification_method == "SHA-512":
            actual_hash = sha512_hash(file_content)
        
        st.write(f"Calculated {verification_method} Hash: `{actual_hash}`")
        
        if expected_hash.lower() == actual_hash.lower():
            st.success("✅ File integrity verified! The hash values match.")
        else:
            st.error("❌ File integrity check failed! The hash values do not match.")
            st.warning("This may indicate that the file has been modified or corrupted during transfer.")

