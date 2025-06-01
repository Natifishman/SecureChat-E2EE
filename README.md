# 🔐 Secure End-to-End Encrypted Messaging System (E2EE)

![Language](https://img.shields.io/badge/language-Python-blue.svg)
![Security](https://img.shields.io/badge/encryption-RSA%202048%20%7C%20AES%20256%20%7C%20PBKDF2-green.svg)
![Final Grade](https://img.shields.io/badge/grade-100-brightgreen.svg)

## 📖 Overview

This project is an **End-to-End Encrypted (E2EE) messaging system** developed for **Final project**. It enables secure communication with strong cryptographic measures, ensuring **confidentiality, integrity, and authentication**.

## 🎯 Features

✅ **End-to-End Encryption** using **RSA-2048** (for key exchange & signatures) and **AES-256-CFB** (for message encryption).  
✅ **Digital Signatures** for message authentication (SHA-256 + RSA).  
✅ **Client-Server Architecture** supporting secure **message exchange and delivery receipts**.  
✅ **OTP-based Secure Registration** with **RSA-encrypted** authentication.  
✅ **Support for Offline Messages**, ensuring messages are stored and delivered upon reconnection.  
✅ **Secure Key Management** using **PBKDF2 with SHA-256** for key derivation.  
✅ **MITM Attack Resistance** with signed and encrypted message structures.  

---

## 📂 Project Structure

### **🔹 Main Components**
- **`Server.py`** – Manages users, key exchange, and encrypted messaging.
- **`Client.py`** – Handles secure message transmission and authentication.
- **`server_private_key.pem` / `server_public_key.pem`** – Server’s RSA key pair.

### **🔹 Security Highlights**
- **Asymmetric Encryption (RSA-2048)** – Secures key exchange and signatures.
- **Symmetric Encryption (AES-256-CFB)** – Encrypts messages efficiently.
- **Message Authentication** – SHA-256 used to verify integrity and authenticity.
- **PBKDF2 (SHA-256)** – Secure key derivation for password-based encryption.

---

## 🛠 Installation & Setup

### **1️⃣ Clone the Repository**
```sh
git clone https://github.com/YOUR_USERNAME/E2EE-Messaging.git
cd E2EE-Messaging
```

### **2️⃣ Install Dependencies**
Ensure you have Python 3.x and install required packages:
```sh
pip install pycryptodome cryptography
```

### **3️⃣ Generate Server RSA Key Pair**
```sh
python -c "from Crypto.PublicKey import RSA; key = RSA.generate(2048); open('server_private_key.pem', 'wb').write(key.export_key()); open('server_public_key.pem', 'wb').write(key.publickey().export_key())"
```

---

## 🚀 Usage Guide

### **Start the Secure Server**
```sh
python Server.py
```
The server will listen for incoming client connections.

### **Run the Secure Client**
```sh
python Client.py
```

#### **📌 First-Time Registration**
1. Enter your **phone number**.
2. The server will send an **OTP verification code** (simulated).
3. Enter the OTP to authenticate and register.
4. A **RSA key pair** will be generated for your client.
5. The public key is sent to the server, and the private key is **encrypted and stored securely**.

#### **📌 Sending Encrypted Messages**
1. Enter the recipient's **phone number**.
2. The system will **encrypt your message with AES-256-CFB**.
3. The **AES key is encrypted** with the recipient’s **RSA public key**.
4. A **digital signature** is generated for verification.
5. The message is securely transmitted.

#### **📌 Receiving Encrypted Messages**
1. The client listens for incoming messages.
2. The received message is **verified using RSA signature**.
3. The **AES session key is decrypted using your RSA private key**.
4. The message content is **decrypted and displayed**.

---

## 🔒 Security Implementation

### **1️⃣ Encryption & Key Exchange**
| Component  | Algorithm  | Purpose  |
|------------|------------|------------|
| **Public Key Encryption**  | RSA-2048  | Encrypts session keys & verifies signatures |
| **Symmetric Encryption**  | AES-256-CFB  | Encrypts actual message content |
| **Key Derivation**  | PBKDF2 (SHA-256)  | Securely encrypts and stores private keys |

### **2️⃣ Digital Signatures for Authentication**
- Messages are **signed using the sender’s RSA private key**.
- The recipient **verifies the message** using the sender’s **public key**.
- Ensures authenticity and prevents **Man-In-The-Middle (MITM) attacks**.

### **3️⃣ Secure Registration & Key Storage**
- **OTP verification** ensures **legitimate user registration**.
- **PBKDF2-based encryption** secures the private key.
- **Keys are never transmitted in plaintext**.

### **4️⃣ Handling Offline Messages**
- If the recipient is **offline**, the server **securely stores encrypted messages**.
- Upon reconnection, the client fetches and decrypts pending messages.

---

## 📌 Message Structure

Each message follows a **secure, structured format**:
```json
{
  "sender_id": "123456789",
  "recipient_id": "987654321",
  "encrypted_content": "<AES Encrypted Data>",
  "encrypted_aes_key": "<RSA Encrypted AES Key>",
  "signature": "<Digital Signature>",
  "timestamp": 1700000000
}
```

---

## 🛡 Security Considerations & Assumptions
1. **Server’s Public Key is Pre-Known** – Clients trust the server’s public key.
2. **Users Must Store Their Private Keys Securely** – If lost, messages cannot be decrypted.
3. **Zero Trust Assumption for Communication** – Every message is **encrypted and signed**.
4. **System is Limited to 10 Users** – To **simulate** a controlled secure system.

---

## 🔧 Future Improvements
🔹 Implement **Perfect Forward Secrecy (PFS)** using **Diffie-Hellman**.  
🔹 Support **secure key revocation & rotation**.  
🔹 Enhance **database-backed message storage** for scalability.  

---

## 🤝 Contributions
Contributions are welcome! Please:
1. **Fork the repository**
2. **Create a feature branch**
3. **Submit a pull request**

---

## 📝 License
This project is for educational purposes and does not guarantee real-world security.
Developed by **Natanel Fishman**  
