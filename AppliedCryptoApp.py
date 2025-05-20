"""
Final Project Applied Cryptography CSAC 329

This application provides implementations of various cryptographic algorithms including:
- Symmetric: Caesar Cipher, Vigenère Cipher, Vernam Cipher (One-Time Pad)
- Asymmetric: Diffie-Hellman Key Exchange, RSA (including M2Crypto implementation)
- Hash Functions: SHA-1, SHA-256, SHA-512, MD5

The application features a user-friendly Streamlit interface with Medium-style formatting,
interactive elements, and comprehensive educational content about cryptographic principles.

Created by: Group 2
BSCS 3B
May 2025
"""

import streamlit as st
from streamlit.logger import get_logger
import os
import base64

LOGGER = get_logger(__name__)

def load_css():
    """Load custom CSS to enhance the look and feel of the app in a Medium-like style"""
    st.markdown("""
        <style>
        /* Medium-like styling */
        @import url('https://fonts.googleapis.com/css2?family=Source+Serif+Pro:wght@400;600;700&family=Source+Sans+Pro:wght@400;600&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Source Sans Pro', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            -webkit-font-smoothing: antialiased;
            color: #fafafaff;
        }
        
        .main-header {
            font-family: 'Source Serif Pro', Georgia, Cambria, 'Times New Roman', Times, serif;
            font-size: 2.8em;
            font-weight: 700;
            color: rgb(0, 255, 163);
            text-align: center;
            margin: 1.5em auto 1em;
            line-height: 1.2;
            letter-spacing: -0.015em;
        }
        
        .sub-header {
            font-family: 'Source Serif Pro', Georgia, Cambria, 'Times New Roman', Times, serif;
            font-size: 1.75em;
            font-weight: 600;
            color: rgb(0, 255, 163);
            margin: 2em 0 0.8em;
            line-height: 1.2;
        }
        
        p, li {
            font-family: 'Source Sans Pro', sans-serif;
            font-size: 1.25rem;
            line-height: 1.58;
            color: #fafafaff;
            margin-bottom: 1.5em;
            letter-spacing: -0.003em;
        }
        
        .highlight {
            font-family: 'Source Sans Pro', sans-serif;
            font-size: 1.25em;
            line-height: 1.58;
            color: #fafafaff;
            border-left: 3px solid rgb(0, 255, 163);
            padding-left: 20px;
            padding-right: 10px;
            margin: 2em 0;
        }
        
        .info-box {
            background-color: rgba(250, 250, 250, 0.05);
            padding: 20px;
            border-radius: 4px;
            margin: 2em 0;
            font-size: 1.1em;
        }
        
        .algo-title {
            font-weight: 600;
            color: #cc4154ff;
            font-style: italic;
        }
        
        /* Algorithm lists styling */
        .algo-list {
            margin: 1.5em 0;
        }
        
        .algo-list li {
            padding: 0.5em 0;
        }
        
        .section-divider {
            text-align: center;
            margin: 2em 0;
        }
        
        .section-divider span {
            font-size: 1.5em;
            color: rgba(250, 250, 250, 0.5);
            letter-spacing: 0.5em;
        }
        
        /* Button styling */
        .stButton > button {
            background-color: rgba(0, 0, 0, 0.84);
            color: white;
            border-radius: 4px;
            padding: 0.5em 1em;
            border: none;
            font-weight: 600;
            transition: background-color 0.2s;
        }
        
        .stButton > button:hover {
            background-color: rgba(0, 0, 0, 0.7);
        }
        
        /* Streamlit Element Customization */
        .stTextInput > div > div > input, .stTextArea > div > div > textarea {
            background-color: white;
            border: 1px solid rgba(0, 0, 0, 0.15);
            padding: 10px;
            border-radius: 4px;
            font-family: 'Source Sans Pro', sans-serif;
        }
        
        /* Custom footer */
        .footer {
            font-family: 'Source Sans Pro', sans-serif;
            text-align: center;
            margin-top: 4em;
            padding: 2em 0;
            border-top: 1px solid rgba(250, 250, 250, 0.2);
            color: #fafafaff;
            font-size: 0.9em;
        }
        
        footer {
            visibility: hidden;
        }
        </style>
    """, unsafe_allow_html=True)

def run():
    # Set page configuration for Medium-like reading experience
    st.set_page_config(
        page_title="CSAC 329 Project",
        page_icon="https://img.icons8.com/?size=100&id=WMWP1MqUZRiS&format=png&color=000000",
        layout="centered",  # Changed to centered for better reading experience like Medium
        initial_sidebar_state="collapsed"  # Medium typically has a clean reading view first
    )
    
    # Load custom CSS
    load_css()
    
    # Custom header with HTML in Medium style
    st.markdown('<div class="main-header">Applied Cryptography Application</div>', unsafe_allow_html=True)
    
    # Medium-style author line
    st.markdown('<div style="text-align: center; margin-bottom: 1em; color: #fafafaff; font-size: 1.1em;">By Group 2 · BSCS 3B · Applied Cryptography CSAC 329</div>', unsafe_allow_html=True)
    st.markdown('''
        <div style="text-align: center; margin-bottom: 1.5em; color: #fafafaff; font-size: 1em;">
            <p style="margin-bottom: 0.3em;">Members:</p>
            <p style="margin: 0; font-weight: bold; color: rgb(0, 255, 163);">Herald Carl Avila</p>
            <p style="margin: 0; font-weight: bold; color: rgb(0, 255, 163);">Jamaica Mae Rosales</p>
            <p style="margin: 0; font-weight: bold; color: rgb(0, 255, 163);">Kaye Khrysna Olores</p>
        </div>
    ''', unsafe_allow_html=True)
    
    # Introduction - Medium-style lead paragraph
    st.markdown("""
        <div class="highlight">
        The Applied Cryptography Application implements various cryptographic techniques to secure 
        communication, data, and information exchange. Cryptography is the science of encoding and 
        decoding messages to protect their confidentiality, integrity, and authenticity.
        </div>
    """, unsafe_allow_html=True)
    
    # Medium-style section divider
    st.markdown('<div class="section-divider"><span>...</span></div>', unsafe_allow_html=True)
    
    # Display the algorithms available with Medium-style formatting
    st.markdown('<div class="sub-header">Available Algorithms</div>', unsafe_allow_html=True)
    
    # Using wider columns for better readability
    col1, col2 = st.columns([3, 3])
    
    with col1:
        st.markdown("""
            <p style="font-weight: 600; font-size: 1.1em; margin-bottom: 0.8em; color: #f5364cff;">Symmetric Algorithms</p>
            <ul class="algo-list">
                <li><span class="algo-title">Caesar Cipher</span> — A simple substitution cipher where each letter is shifted by a fixed number of positions.</li>
                <li><span class="algo-title">Vigenère Cipher</span> — A polyalphabetic substitution cipher using a keyword to determine different shift values.</li>
                <li><span class="algo-title">Vernam Cipher (One-Time Pad)</span> — A theoretically unbreakable cipher when used with a truly random key of equal length to the message.</li>
            </ul>
            
            <p style="font-weight: 600; font-size: 1.1em; margin: 1.5em 0 0.8em; color: #f5364cff;">Asymmetric Algorithms</p>
            <ul class="algo-list">
                <li><span class="algo-title">Diffie-Hellman</span> — A secure method for exchanging cryptographic keys over a public channel without requiring a pre-shared secret.</li>
                <li><span class="algo-title">RSA</span> — A widely used public-key encryption system based on the practical difficulty of factoring large composite numbers.</li>
            </ul>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
            <p style="font-weight: 600; font-size: 1.1em; margin-bottom: 0.8em; color: #f5364cff;">Hash Functions</p>
            <ul class="algo-list">
                <li><span class="algo-title">SHA-1</span> — A cryptographic hash function that produces a 160-bit hash value, now considered weak for security-critical applications.</li>
                <li><span class="algo-title">SHA-256</span> — A more secure hash function from the SHA-2 family, producing a 256-bit output used in many security protocols.</li>
                <li><span class="algo-title">SHA-512</span> — An even stronger cryptographic hash function with 512-bit output, offering enhanced security for critical applications.</li>
                <li><span class="algo-title">MD5</span> — A widely used legacy hash function that produces a 128-bit output, now considered cryptographically broken.</li>
            </ul>
        """, unsafe_allow_html=True)
    
    # Medium-style section divider
    st.markdown('<div class="section-divider"><span>...</span></div>', unsafe_allow_html=True)

    # How to Use section with Medium-style typography and layout
    st.markdown('<div class="sub-header">Getting Started</div>', unsafe_allow_html=True)
    st.markdown("""
        <p style="font-size: 1.2em; color: #fafafaff; margin-bottom: 1.2em;">
            Using our cryptography application is straightforward and intuitive. Follow these simple steps to explore the world of secure communication:
        </p>
        
        <div class="info-box">
            <p style="font-weight: 600; margin-bottom: 1em;">Navigate through the application:</p>
            <ol>
                <li>Select your desired algorithm category from the sidebar menu.</li>
                <li>Follow the specific instructions on each algorithm page to input your data.</li>
                <li>View the encrypted/decrypted results or hash values instantly.</li>
            </ol>
            <p style="margin-top: 1.5em; font-style: italic; color: #fafafaff;">
                Each algorithm includes detailed descriptions and process explanations to help you understand how the cryptographic techniques work.
            </p>
        </div>
    """, unsafe_allow_html=True)
    
    # Medium-style pull quote
    st.markdown("""
        <div style="border-left: 3px solid #fafafaff; padding-left: 20px; margin: 2em 0;">
            <p style="font-family: 'Source Serif Pro', Georgia, serif; font-size: 1.5em; font-style: italic; line-height: 1.4; color: #fafafaff;">
                "Cryptography is the essential building block of independence for organizations on the Internet, just like armies are the essential building blocks of states."
            </p>
            <p style="color: #fafafaff; font-size: 1em;">— Julian Assange</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Medium-style section divider
    st.markdown('<div class="section-divider"><span>...</span></div>', unsafe_allow_html=True)
    
    # About this Project - Medium-style section
    st.markdown('<div class="sub-header">About this Project</div>', unsafe_allow_html=True)
    st.markdown("""
        <p style="font-size: 1.2em; line-height: 1.6; color: #fafafaff;">
            This application was developed as a final project for the Applied Cryptography course (CSAC 329). 
            Our goal was to create an educational tool that demonstrates various cryptographic algorithms 
            in an interactive and user-friendly way.
        </p>
        
        <p style="font-size: 1.2em; line-height: 1.6; color: #fafafaff; font-style: italic;">
            This project showcases our understanding of cryptographic principles and our ability to implement 
            them in a Python-based web application using the Streamlit framework.
        </p>
    """, unsafe_allow_html=True)
    
    # Credits in sidebar with Medium-style
    st.sidebar.markdown("""
        <div style="padding: 1.5em 0; border-bottom: 1px solid rgba(250,250,250,0.2);">
            <p style="font-family: 'Source Serif Pro', Georgia, serif; font-size: 1.2em; font-weight: 600; margin-bottom: 0.5em; color: #fafafaff;">About the Team</p>
            <p style="color: #fafafaff; font-size: 1em; margin-bottom: 0.5em;">Group 2 - BSCS 3B</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Medium-style footer
    st.markdown("""
        <div class="footer">
            <p>© 2025 Applied Cryptography CSAC 329 - Group 2</p>
            <p style="font-size: 0.9em; margin-top: 0.5em; color: #fafafaff;">
                A final project demonstrating cryptographic algorithms and their implementations
            </p>
        </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    run()
