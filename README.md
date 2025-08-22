![App Showcase](assets/securechat-readme.png)
<p align="center">
  <img src="https://img.shields.io/badge/language-Python-blue.svg">
  <img src="https://img.shields.io/badge/encryption-RSA%202048%20%7C%20AES%20256%20%7C%20PBKDF2-green.svg">
  <img src="https://img.shields.io/badge/grade-100-brightgreen.svg">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg">
  <img src="https://img.shields.io/badge/license-Educational-red.svg">
</p>

## 📋 Table of Contents
- [📖 Overview](#-overview)
- [🎯 Features](#-features)
- [📂 Project Structure](#-project-structure)
- [🛠 Installation & Setup](#-installation--setup)
- [🚀 Usage Guide](#-usage-guide)
- [🔒 Security Implementation](#-security-implementation)
- [📌 Message Structure](#-message-structure)
- [🛡 Security Considerations](#-security-considerations--assumptions)
- [🔧 Future Improvements](#-future-improvements)
- [❓ Troubleshooting](#-troubleshooting)
- [🤝 Contributions](#-contributions)
- [📝 License](#-license)

## 📖 Overview

This project is an **End-to-End Encrypted (E2EE) messaging system** developed for **Final project**. It enables secure communication with strong cryptographic measures, ensuring **confidentiality, integrity, and authentication**.

### 🎓 Educational Purpose
This system demonstrates advanced cryptographic concepts including:
- **Asymmetric encryption** for key exchange and digital signatures
- **Symmetric encryption** for efficient message encryption
- **Key derivation functions** for secure password-based encryption
- **Message authentication** to prevent tampering and ensure authenticity

## 🎯 Features

✅ **End-to-End Encryption** using **RSA-2048** (for key exchange & signatures) and **AES-256-CFB** (for message encryption).  
✅ **Digital Signatures** for message authentication (SHA-256 + RSA).  
✅ **Client-Server Architecture** supporting secure **message exchange and delivery receipts**.  
✅ **OTP-based Secure Registration** with **RSA-encrypted** authentication.  
✅ **Support for Offline Messages**, ensuring messages are stored and delivered upon reconnection.  
✅ **Secure Key Management** using **PBKDF2 with SHA-256** for key derivation.  
✅ **MITM Attack Resistance** with signed and encrypted message structures.  
✅ **Multi-threading Support** for handling multiple concurrent connections.  
✅ **Automatic Delivery Receipts** for message confirmation.  

---

## 📂 Project Structure

```
SecureChat-E2EE/
├── 📄 Client.py                    # Main client application
├── 📄 Server.py                    # Main server application
├── 📄 README.md                    # Project documentation
├── 🔑 server_private_key.pem       # Server's private key (generate this)
└── 🔑 server_public_key.pem        # Server's public key (generate this)
```

### **🔹 Main Components**
- **`Server.py`** – Manages users, key exchange, and encrypted messaging.
- **`Client.py`** – Handles secure message transmission and authentication.
- **`server_private_key.pem` / `server_public_key.pem`** – Server's RSA key pair.

### **🔹 Security Highlights**
- **Asymmetric Encryption (RSA-2048)** – Secures key exchange and signatures.
- **Symmetric Encryption (AES-256-CFB)** – Encrypts messages efficiently.
- **Message Authentication** – SHA-256 used to verify integrity and authenticity.
- **PBKDF2 (SHA-256)** – Secure key derivation for password-based encryption.

---

## 🛠 Installation & Setup

### **Prerequisites**
- **Python 3.8 or higher**
- **pip** (Python package installer)
- **Git** (for cloning the repository)

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/YOUR_USERNAME/SecureChat-E2EE.git
cd SecureChat-E2EE
```

### **2️⃣ Install Dependencies**
Install the required cryptographic libraries:
```bash
pip install pycryptodome cryptography
```

**Note:** If you encounter issues with `pycryptodome`, you can also use:
```bash
pip install pycrypto cryptography
```

### **3️⃣ Generate Server RSA Key Pair**
The server needs a pre-generated RSA key pair for secure communication. Run this command:

```bash
python -c "from Crypto.PublicKey import RSA; key = RSA.generate(2048); open('server_private_key.pem', 'wb').write(key.export_key()); open('server_public_key.pem', 'wb').write(key.publickey().export_key()); print('Server keys generated successfully!')"
```

**Alternative method** (if the above doesn't work):
```python
# Create a file called generate_keys.py
from Crypto.PublicKey import RSA

# Generate RSA key pair
key = RSA.generate(2048)

# Save private key
with open('server_private_key.pem', 'wb') as f:
    f.write(key.export_key())

# Save public key
with open('server_public_key.pem', 'wb') as f:
    f.write(key.publickey().export_key())

print("Server keys generated successfully!")
```

Then run:
```bash
python generate_keys.py
```

---

## 🚀 Usage Guide

### **Step 1: Start the Secure Server**
Open a terminal and run:
```bash
python Server.py
```

You should see output like:
```
Server listening on localhost:12345
```

### **Step 2: Run the Secure Client**
Open another terminal and run:
```bash
python Client.py
```

### **📌 First-Time Registration Process**
1. **Enter your phone number** (e.g., "123456789")
2. The server will display a **6-digit verification code**
3. **Enter the verification code** exactly as shown
4. **Create a strong password** (minimum 8 characters) to protect your private key
5. The system will generate your **RSA key pair** and complete registration

### **📌 Sending Encrypted Messages**
1. Enter the recipient's **phone number**
2. Type your **message**
3. The system automatically:
   - Generates a new **AES session key**
   - Encrypts your message with **AES-256-CFB**
   - Encrypts the session key with the recipient's **RSA public key**
   - Creates a **digital signature** for authentication
   - Sends the encrypted message securely

### **📌 Receiving Encrypted Messages**
The client automatically:
1. **Listens for incoming messages**
2. **Verifies the digital signature** using the sender's public key
3. **Decrypts the session key** using your private key
4. **Decrypts and displays** the message content
5. **Sends delivery receipt** to confirm message received

---

## 🔒 Security Implementation

### **1️⃣ Encryption & Key Exchange**
| Component  | Algorithm  | Purpose  | Security Level |
|------------|------------|----------|----------------|
| **Public Key Encryption**  | RSA-2048  | Encrypts session keys & verifies signatures | 112-bit security |
| **Symmetric Encryption**  | AES-256-CFB  | Encrypts actual message content | 256-bit security |
| **Key Derivation**  | PBKDF2 (SHA-256)  | Securely encrypts and stores private keys | 100,000 iterations |
| **Message Hashing**  | SHA-256  | Creates message digests for signatures | 256-bit security |

### **2️⃣ Digital Signatures for Authentication**
- Messages are **signed using the sender's RSA private key**
- The recipient **verifies the message** using the sender's **public key**
- Ensures authenticity and prevents **Man-In-The-Middle (MITM) attacks**
- **SHA-256** is used to create message digests before signing

### **3️⃣ Secure Registration & Key Storage**
- **OTP verification** ensures **legitimate user registration**
- **PBKDF2-based encryption** secures the private key with 100,000 iterations
- **Keys are never transmitted in plaintext**
- **Salt and IV** are randomly generated for each encryption

### **4️⃣ Handling Offline Messages**
- If the recipient is **offline**, the server **securely stores encrypted messages**
- **Maximum 2 pending messages** per user to prevent spam
- Upon reconnection, the client fetches and decrypts pending messages
- **Delivery receipts** confirm successful message delivery

---

## 📌 Message Structure

Each message follows a **secure, structured format**:

```json
{
  "sender_id": "123456789",
  "recipient_id": "987654321",
  "encrypted_content": "<AES-256-CFB Encrypted Data>",
  "encrypted_aes_key": "<RSA-2048 Encrypted AES Session Key>",
  "signature": "<RSA-2048 Digital Signature>",
  "timestamp": 1700000000,
  "type": "message"
}
```

### **Message Flow:**
1. **Sender** encrypts message with AES session key
2. **Sender** encrypts session key with recipient's RSA public key
3. **Sender** signs encrypted content with their RSA private key
4. **Server** receives and forwards encrypted message
5. **Recipient** verifies signature with sender's public key
6. **Recipient** decrypts session key with their private key
7. **Recipient** decrypts message with session key

---

## 🛡 Security Considerations & Assumptions

### **✅ Implemented Security Measures**
1. **End-to-End Encryption** – Messages are encrypted on sender's device and decrypted on recipient's device
2. **Digital Signatures** – Every message is signed to ensure authenticity
3. **Secure Key Storage** – Private keys are encrypted with PBKDF2
4. **Session Key Rotation** – New AES keys for each conversation
5. **Message Integrity** – SHA-256 hashing prevents tampering

### **⚠️ Current Limitations**
1. **Server's Public Key is Pre-Known** – Clients trust the server's public key
2. **Users Must Store Their Private Keys Securely** – If lost, messages cannot be decrypted
3. **System is Limited to 10 Users** – To simulate a controlled secure system
4. **No Perfect Forward Secrecy** – Session keys are not rotated per message
5. **No Key Revocation** – Compromised keys cannot be invalidated

### **🔒 Security Assumptions**
- **Server is trusted** for message routing (not content)
- **Network is untrusted** (hence end-to-end encryption)
- **Users keep their private keys secure**
- **Verification codes are transmitted securely** (simulated)

---

## 🔧 Future Improvements

### **🔹 Security Enhancements**
- Implement **Perfect Forward Secrecy (PFS)** using **Diffie-Hellman key exchange**
- Support **secure key revocation & rotation**
- Add **elliptic curve cryptography (ECC)** for better performance
- Implement **post-quantum cryptography** resistance

### **🔹 Scalability Improvements**
- Enhance **database-backed message storage** for scalability
- Add **load balancing** for multiple server instances
- Implement **message compression** for efficiency
- Support **file sharing** with encryption

### **🔹 User Experience**
- Add **graphical user interface (GUI)**
- Implement **message history** and search
- Add **contact management** system
- Support **group messaging** with encryption

---

## ❓ Troubleshooting

### **Common Issues and Solutions**

#### **1. Import Errors**
```bash
ModuleNotFoundError: No module named 'Crypto'
```
**Solution:** Install the correct package:
```bash
pip uninstall pycrypto pycryptodome
pip install pycryptodome
```

#### **2. Key Generation Issues**
```bash
FileNotFoundError: [Errno 2] No such file or directory: 'server_private_key.pem'
```
**Solution:** Generate the server keys first:
```bash
python -c "from Crypto.PublicKey import RSA; key = RSA.generate(2048); open('server_private_key.pem', 'wb').write(key.export_key()); open('server_public_key.pem', 'wb').write(key.publickey().export_key())"
```

#### **3. Connection Refused**
```bash
ConnectionRefusedError: [Errno 111] Connection refused
```
**Solution:** Make sure the server is running first:
1. Start the server: `python Server.py`
2. Then start the client: `python Client.py`

#### **4. Authentication Failures**
```bash
Authentication failed: Maximum attempts exceeded
```
**Solution:** 
- Check if you're using the correct password
- If you forgot your password, delete your key files and re-register
- Ensure the server is running and accessible

#### **5. Public Key Not Found**
```bash
Security Error: Public key for [phone] not found
```
**Solution:** 
- Make sure the recipient has registered on the server
- Check that the recipient's public key file exists
- Try re-registering the recipient

### **Debug Mode**
To enable detailed logging, you can modify the print statements in the code or add logging configuration.

---

## 🤝 Contributions

Contributions are welcome! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
4. **Push to the branch** (`git push origin feature/AmazingFeature`)
5. **Open a Pull Request**

### **Development Guidelines**
- Follow **PEP 8** style guidelines
- Add **comprehensive comments** for security-critical code
- Include **unit tests** for new features
- Update **documentation** for any changes

---

## 📝 License

This project is developed for **educational purposes** and demonstrates cryptographic concepts. 

**⚠️ Important Notice:**
- This system is **NOT intended for production use**
- **No security guarantees** are provided
- Use at your own risk
- For real-world applications, use established, audited cryptographic libraries

**Developed by:** Natanel Fishman  
**Project:** Final Project - Secure End-to-End Encrypted Messaging System  
**Date:** 2024

---

## 📚 References

- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/)
- [Cryptography Library](https://cryptography.io/)
- [RSA Encryption](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [End-to-End Encryption](https://en.wikipedia.org/wiki/End-to-end_encryption)
