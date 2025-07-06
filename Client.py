from __future__ import annotations
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import socket
import json
import time
import threading
from typing import Optional, Dict
import os

"""
End-to-End Encrypted Messaging Client (E2EE)
Maman 16 - Natanel Fishman - 318555646

Message Structure:
- sender_id: str (phone number)
- recipient_id: str (phone number)
- encrypted_content: bytes (AES encrypted with random IV)
- encrypted_aes_key: bytes (RSA encrypted session key)
- signature: bytes (RSA signature on encrypted content)
- timestamp: int (unix timestamp)
- type: str (optional, "message" or "receipt")

Security Features:
- RSA-2048 for asymmetric encryption and signatures
- AES-256-CFB for symmetric message encryption
- PBKDF2 with SHA-256 for key derivation
- Digital signatures for message authentication
- 6-digit verification codes for initial registration
"""


class SecureClient:

    def __init__(self, phone: str, host='localhost', port=12345):
        self.phone = phone
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.private_key = None
        self.public_key = None
        self.session_keys: Dict[str, bytes] = {}
        self.message_listener: Optional[threading.Thread] = None
        self.running = True

    def derive_key(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """Generate a secure key from password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
        return key, salt

    def request_public_key(self, phone: str) -> bool:
        """Request public key from server."""
        try:
            # Send request for public key
            request = {
                'type': 'get_public_key',
                'phone': phone
            }
            self.socket.sendall(json.dumps(request).encode())

            # Receive response from server
            response = self.socket.recv(4096).decode()
            data = json.loads(response)

            if data.get('exists', False):
                # Save public key to file
                with open(f"{phone}_public_key.pem", "wb") as f:
                    f.write(data['public_key'].encode())
                return True
            return False
        except Exception as e:
            print(f"Error requesting public key: {e}")
            return False

    def encrypt_private_key(self, password: str) -> tuple[bytes, bytes, bytes]:
        """Encrypt private key with password before saving to disk."""
        key, salt = self.derive_key(password)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(self.private_key.export_key('PEM')) + encryptor.finalize()
        return encrypted_key, salt, iv

    def decrypt_private_key(self, encrypted_data: bytes, salt: bytes, iv: bytes, password: str) -> RSA.RsaKey:
        """Decrypt private key using password."""
        key, _ = self.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_key = decryptor.update(encrypted_data) + decryptor.finalize()
        return RSA.import_key(decrypted_key)

    def save_keys(self, password: str):
        """Save encrypted private key and public key to files."""
        # Save encrypted private key
        encrypted_key, salt, iv = self.encrypt_private_key(password)
        with open(f"{self.phone}_private_key.enc", "wb") as f:
            f.write(salt + iv + encrypted_key)

        # Save public key
        with open(f"{self.phone}_public_key.pem", "wb") as f:
            f.write(self.public_key.export_key('PEM'))

        print(f"Keys saved securely with password protection")

    def load_keys(self, password: str) -> bool:
        """Load and decrypt private key, and load public key."""
        try:
            # Load and decrypt private key
            with open(f"{self.phone}_private_key.enc", "rb") as f:
                data = f.read()
                salt = data[:16]
                iv = data[16:32]
                encrypted_key = data[32:]
                self.private_key = self.decrypt_private_key(encrypted_key, salt, iv, password)
                self.public_key = self.private_key.publickey()
                return True
        except Exception as e:
            print(f"Error loading keys: {e}")
            return False

    def encrypt_message(self, key: bytes, message: str) -> bytes:
        """Encrypt message using AES-256-CFB."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(message.encode()) + encryptor.finalize()
        return ciphertext

    def decrypt_message(self, key: bytes, ciphertext: bytes) -> str:
        """Decrypt message using AES-256-CFB."""
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        return plaintext.decode()

    def encrypt_verification_code(self, verification_code: str) -> bytes:
        """
        Encrypt verification code using server's public key.
        """
        try:
            print("\n=== Verification Code Encryption Process ===")
            print(f"Original verification code: {verification_code}")

            # Load server's public key
            with open("server_public_key.pem", "rb") as f:
                server_public_key = RSA.import_key(f.read())
            print("✓ Loaded server public key")

            # Create PKCS1_OAEP cipher object with server's public key
            cipher_rsa = PKCS1_OAEP.new(server_public_key)

            # Encrypt the verification code
            encrypted_code = cipher_rsa.encrypt(verification_code.encode())
            print(f"Encrypted code (hex): {encrypted_code.hex()[:64]}...")
            print("=====================================")

            return encrypted_code

        except Exception as e:
            print(f"Error encrypting verification code: {e}")
            raise

    def create_signature(self, message: bytes) -> bytes:
        """Create RSA signature using SHA-256."""
        h = SHA256.new(message)
        return pkcs1_15.new(self.private_key).sign(h)

    def verify_signature(self, sender_public_key, signature: bytes, message: bytes) -> bool:
        """Verify RSA signature using SHA-256."""
        try:
            h = SHA256.new(message)
            pkcs1_15.new(sender_public_key).verify(h, signature)
            return True
        except Exception:
            return False

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # Check if user exists on server
            try:
                print("\n=== Checking User Existence ===")
                # Send request for public key
                request = {
                    'type': 'get_public_key',
                    'phone': self.phone
                }
                print(f"Requesting public key for phone: {self.phone}")
                self.socket.sendall(json.dumps(request).encode())

                # Get response
                print("Waiting for server response...")
                response = self.socket.recv(4096).decode()
                data = json.loads(response)
                user_exists = data.get('exists', False)

                if user_exists:
                    print("✓ User found on server")
                    print("✓ Received public key from server")
                    # Save public key to file
                    with open(f"{self.phone}_public_key.pem", "wb") as f:
                        f.write(data['public_key'].encode())
                    print(f"✓ Saved public key to {self.phone}_public_key.pem")
                else:
                    print("✗ User not found on server")

                print("============================")

            except Exception as e:
                print(f"\n=== Debug Error ===")
                print(f"Error checking user existence: {e}")
                print(f"Response received: {response if 'response' in locals() else 'No response'}")
                print("==================")
                user_exists = False

            # Create new connection to server after existence check
            self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))

            # Send phone number to server
            self.socket.sendall(json.dumps({'phone': self.phone}).encode())
            print(f"Sent phone number: {self.phone}")

            if user_exists:
                print("Existing user found. Please enter your password.")
                max_attempts = 3
                for attempt in range(max_attempts):
                    password = input("Enter your password: ")
                    if self.load_keys(password):
                        print("Successfully authenticated!")
                        break
                    else:
                        remaining_attempts = max_attempts - attempt - 1
                        if remaining_attempts > 0:
                            print(f"Invalid password. {remaining_attempts} attempts remaining.")
                        else:
                            print("Maximum password attempts exceeded.")
                            self.socket.close()
                            raise Exception("Authentication failed: Maximum attempts exceeded")
                if not self.private_key:
                    raise Exception("Authentication failed")
            else:
                print("New user detected. Starting registration process...")
                if not self.register():
                    print("Registration failed. Please try again.")
                    self.socket.close()
                    raise Exception("Registration failed")

            # Start listening for messages
            self.message_listener = threading.Thread(target=self.listen_for_messages)
            self.message_listener.daemon = True
            self.message_listener.start()
            print("Message listener started")

        except Exception as e:
            print(f"Error connecting to server: {e}")
            if self.socket:
                self.socket.close()
            raise

    def register(self):
        try:
            print("\n=== Starting Security Registration Process ===")
            print("Waiting for verification code...")

            # Receive verification code from server
            initial_response = self.socket.recv(1024).decode()
            server_data = json.loads(initial_response)
            verification_code_from_server = server_data.get('verification_code')

            print(f"\n=== Verification Code from Server ===")
            print(f"Code: {verification_code_from_server}")
            print("=====================================")

            verification_code = input("Enter the verification code shown above: ")

            # Encrypt the verification code before sending
            encrypted_code = self.encrypt_verification_code(verification_code)

            # Send the encrypted code in hex format
            self.socket.sendall(json.dumps({
                'encrypted_code': encrypted_code.hex()
            }).encode())

            response = self.socket.recv(1024).decode()
            verification_response = json.loads(response)

            if not verification_response.get('success', False):
                print("Security Error: Invalid verification code. Registration failed.")
                self.socket.close()
                return False

            print("\n=== Generating Security Keys ===")
            print("- Generating RSA-2048 key pair for asymmetric encryption")
            print("- This will be used for secure message exchange")
            key = RSA.generate(2048)
            self.private_key = key
            self.public_key = key.publickey()
            print("✓ RSA key pair generated successfully")

            print("\n=== Exchanging Public Key with Server ===")
            public_key_pem = self.public_key.export_key('PEM')
            # I wanted to encrypt here(its pretty easy), but we do not know the technique needed in the work
            self.socket.sendall(public_key_pem)
            print("✓ Public key sent to server for future message encryption")

            print("\n=== Setting Up Key Protection ===")
            while True:
                password = input("Create a password to protect your private key: ")
                confirm_password = input("Confirm your password: ")

                if password == confirm_password:
                    if len(password) >= 8:
                        print("\nProtecting keys using PBKDF2 with SHA-256...")
                        self.save_keys(password)
                        print("✓ Keys encrypted and saved securely")
                        print("\n=== Security Setup Complete ===")
                        print("- RSA-2048 keys generated and protected")
                        print("- PBKDF2 key derivation implemented")
                        print("- AES-256-CFB encryption ready for messages")
                        print("- Digital signatures prepared for message authentication")
                        print("=======================================")
                        return True
                    else:
                        print("Security requirement: Password must be at least 8 characters long.")
                else:
                    print("Passwords do not match. Please try again.")

        except Exception as e:
            print(f"Security Error during registration: {e}")
            return False

    def send_message(self, recipient_id: str, content: str):
        try:
            print(f"\n=== Securing Message for {recipient_id} ===")

            if recipient_id not in self.session_keys:
                print("- Generating new AES-256 session key")
                self.session_keys[recipient_id] = os.urandom(32)
            else:
                print("- Using existing session key")
            session_key = self.session_keys[recipient_id]

            print("- Encrypting message content with AES-256-CFB")
            encrypted_content = self.encrypt_message(session_key, content)

            print("- Creating digital signature for message authentication")
            signature = self.create_signature(encrypted_content)

            try:
                print("- Encrypting session key with recipient's RSA public key")
                with open(f"{recipient_id}_public_key.pem", "rb") as f:
                    recipient_public_key = RSA.import_key(f.read())
                cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
                encrypted_session_key = cipher_rsa.encrypt(session_key)
                print("✓ Message secured successfully")
            except FileNotFoundError:
                print(f"Security Error: Public key for {recipient_id} not found")
                return

            message = {
                'sender_id': self.phone,
                'recipient_id': recipient_id,
                'encrypted_content': encrypted_content.hex(),
                'encrypted_aes_key': encrypted_session_key.hex(),
                'signature': signature.hex(),
                'timestamp': int(time.time()),
                'type': 'message'
            }

            print("\n=== Encrypted Message Structure ===")
            print(f"- Sender ID: {message['sender_id']}")
            print(f"- Recipient ID: {message['recipient_id']}")
            # Show only part of the encryption
            print(f"- Encrypted Content (hex): {message['encrypted_content'][:32]}...")
            print(f"- Encrypted AES Key (hex): {message['encrypted_aes_key'][:32]}...")
            print(f"- Digital Signature (hex): {message['signature'][:32]}...")
            print(f"- Timestamp: {message['timestamp']}")
            print(f"- Message Type: {message['type']}")
            print("=====================================")

            self.socket.sendall(json.dumps(message).encode())
            print("\n=== Message Security Summary ===")
            print("- Content encrypted with AES-256-CFB")
            print("- Session key encrypted with RSA-2048")
            print("- Message authenticated with digital signature")
            print("- End-to-end encryption achieved")
            print("==============================")

        except Exception as e:
            print(f"Security Error during message sending: {e}")
            raise

    def send_delivery_receipt(self, message_timestamp: int, sender_id: str):
        """Send delivery receipt for received message."""
        try:
            receipt = {
                'type': 'receipt',
                'message_timestamp': message_timestamp,
                'recipient_id': self.phone,
                'sender_id': sender_id,
                'timestamp': int(time.time())
            }
            signature = self.create_signature(json.dumps(receipt).encode())
            receipt['signature'] = signature.hex()
            self.socket.sendall(json.dumps(receipt).encode())
            print(f"Sent delivery receipt for message from {sender_id}")
        except Exception as e:
            print(f"Error sending delivery receipt: {e}")

    def listen_for_messages(self):
        """Listen for incoming messages and receipts."""
        while self.running:
            try:
                message_data = self.socket.recv(4096)
                if not message_data:
                    print("Server connection closed")
                    break

                message = json.loads(message_data)

                # Clear current line if there's open input
                print("\033[2K\r", end="")

                # Handle delivery receipt
                if 'type' in message and message['type'] == 'receipt':
                    print(f"\nReceived delivery receipt for message from {message['sender_id']}")
                    continue

                print("\n=== Received Encrypted Message ===")
                print(f"- Sender ID: {message['sender_id']}")
                print(f"- Recipient ID: {message['recipient_id']}")
                print(f"- Encrypted Content (hex): {message['encrypted_content'][:32]}...")
                print(f"- Encrypted AES Key (hex): {message['encrypted_aes_key'][:32]}...")
                print(f"- Digital Signature (hex): {message['signature'][:32]}...")
                print(f"- Timestamp: {message['timestamp']}")
                print("- Message Type: message")  # Fixed instead of taking from message
                print("=== Starting Decryption Process ===")

                sender_id = message['sender_id']
                encrypted_content = bytes.fromhex(message['encrypted_content'])
                encrypted_session_key = bytes.fromhex(message['encrypted_aes_key'])
                signature = bytes.fromhex(message['signature'])

                # Verify signature
                try:
                    print("- Loading sender's public key for signature verification")
                    with open(f"{sender_id}_public_key.pem", "rb") as f:
                        sender_public_key = RSA.import_key(f.read())
                except FileNotFoundError:
                    print(f"Security Error: Public key for {sender_id} not found")
                    continue

                print("- Verifying digital signature")
                if not self.verify_signature(sender_public_key, signature, encrypted_content):
                    print(f"Security Error: Invalid signature from {sender_id}")
                    continue
                print("✓ Signature verified successfully")

                print("- Decrypting session key with private RSA key")
                # Decrypt session key and message
                cipher_rsa = PKCS1_OAEP.new(self.private_key)
                session_key = cipher_rsa.decrypt(encrypted_session_key)

                print("- Decrypting message content with AES-256-CFB")
                content = self.decrypt_message(session_key, encrypted_content)

                print("\n=== Decryption Summary ===")
                print("- Digital signature verified")
                print("- Session key decrypted successfully")
                print("- Message content decrypted successfully")
                print("==============================")

                print(f"\nDecrypted message from {sender_id}: {content}")

                print("\n- Sending delivery receipt")
                # Send delivery receipt
                self.send_delivery_receipt(message['timestamp'], sender_id)

                # Reprint input prompt if needed
                print("\nEnter recipient phone number (or 'quit' to exit): ", end="", flush=True)

            except Exception as e:
                print(f"\nError in message listener: {e}")
                if not self.running:
                    break
                time.sleep(1)

    def close(self):
        """Close the client connection."""
        self.running = False
        if self.socket:
            self.socket.close()
        if self.message_listener:
            self.message_listener.join(timeout=1.0)


def main():
    """Main function to run the client."""
    while True:  # Loop that allows user to try again
        try:
            phone = input("Enter your phone number: ")
            client = SecureClient(phone)
            client.start()

            while True:
                recipient = input("\nEnter recipient phone number (or 'quit' to exit): ")
                if recipient.lower() == 'quit':
                    break

                message = input("Enter message: ")
                client.send_message(recipient, message)

            break  # Exit outer loop if user chose to quit

        except Exception as e:
            print(f"\nError: {e}")
            retry = input("Would you like to try again? (y/n): ")
            if retry.lower() != 'y':
                break

        finally:
            if 'client' in locals():
                client.close()

    print("\nClosing client...")


if __name__ == "__main__":
    main()
