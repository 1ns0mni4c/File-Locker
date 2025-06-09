# Ransomware Proof of Concept

⚠️ **EDUCATIONAL PURPOSE ONLY** ⚠️

This repository contains a proof-of-concept ransomware implementation for educational and research purposes only. **DO NOT use this code for malicious purposes.**

## Overview

This project demonstrates the basic cryptographic principles behind ransomware operations. It consists of two Python files that showcase file encryption and decryption mechanisms using a hybrid cryptographic approach (RSA + AES).

## Features

- **Hybrid Encryption**: Combines RSA and AES encryption methods
- **Cross-Platform**: Supports multiple operating systems
- **Offline Operation**: Fully functional without internet connectivity
- **Minimal Implementation**: Barebones code without typical ransomware features (no ransom notes, no network communication)

## Components

### 1. Ransomware Script
- Contains hardcoded RSA public key
- Searches for files on the system
- Generates unique AES key for each file
- Encrypts files using the generated AES key
- Encrypts the AES key using the RSA public key
- Embeds the encrypted AES key within the encrypted file
- Appends `.locked` extension to all encrypted files

### 2. Decryption Script
- Contains hardcoded RSA private key
- Searches for files with `.locked` extension
- Extracts and decrypts the embedded AES key using the RSA private key
- Decrypts the file content using the recovered AES key
- Restores files to their original state
