from __future__ import annotations
import socket
import threading
import json
import time
import random
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP

"""
End-to-End Encrypted Messaging Server (E2EE)
Maman 16 - Natanel Fishman - 318555646

Server Data Structure:
- users: Dict[str, User]
    - phone: str (user's phone number)
    - public_key: RSA.RsaKey (user's public key)
    - registration_time: int (unix timestamp)
    - is_online: bool (connection status)
    - verification_code: str (6-digit code)
    - socket: socket (connection socket)

- pending_messages: Dict[str, List[Message]]
    - Key: recipient phone number
    - Value: list of pending messages for offline users
    - Maximum 2 pending messages per user

Security Features:
- RSA-2048 for asymmetric encryption and signatures
- SHA-256 for hashing
- 6-digit verification codes for registration
- Digital signatures for message authentication
- Multi-threading support
- Maximum 10 users limit
"""


@dataclass
class User:
    phone: str
    public_key: RSA.RsaKey
    registration_time: int
    is_online: bool
    verification_code: str = None
    socket: Any = None


@dataclass
class Message:
    sender_id: str
    recipient_id: str
    encrypted_content: bytes
    encrypted_aes_key: bytes
    signature: bytes
    timestamp: int
    receipt_received: bool = False


class SecureServer:
    """Secure messaging server supporting E2EE communication."""

    def __init__(self, host='localhost', port=12345):
        """Initialize server with host, port and required data structures."""
        self.host = host
        self.port = port
        self.users: Dict[str, User] = {}  # Limited to 10 users
        self.pending_messages: Dict[str, List[Message]] = {}  # Maximum 2 messages per user
        with open('server_private_key.pem', 'rb') as f:
            self.server_private_key = RSA.import_key(f.read())
        self.lock = threading.Lock()

    def start(self):
        """Start the server and listen for connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)  # Maximum 10 concurrent connections
            print(f"Server listening on {self.host}:{self.port}")

            while True:
                try:
                    client_socket, address = server_socket.accept()
                    print(f"Accepted connection from {address}")
                    client_handler = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_handler.daemon = True
                    client_handler.start()
                except Exception as e:
                    print(f"Error in main server loop: {e}")

    def handle_client(self, client_socket: socket.socket, address):
        """Handle client connection and message routing."""
        phone = None
        try:
            data = client_socket.recv(1024).decode()
            request = json.loads(data)

            # Handle public key request
            if 'type' in request and request['type'] == 'get_public_key':
                phone = request['phone']
                public_key = self.get_public_key(phone)

                response = {
                    'exists': public_key is not None,
                    'public_key': public_key.decode() if public_key else None
                }
                client_socket.sendall(json.dumps(response).encode())
                return

            # Handle registration/normal login
            phone = request['phone']
            print(f"Client {address} connected with phone {phone}")

            if phone not in self.users:
                if not self.handle_registration(phone, client_socket):
                    client_socket.close()
                    return

            with self.lock:
                self.users[phone].is_online = True
                self.users[phone].socket = client_socket

            self.send_pending_messages(phone)

            while True:
                try:
                    message_data = client_socket.recv(4096)
                    if not message_data:
                        print(f"Client {phone} disconnected")
                        break

                    self.process_message(message_data)
                except Exception as e:
                    print(f"Error receiving message from {phone}: {e}")
                    break

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            with self.lock:
                if phone and phone in self.users:
                    self.users[phone].is_online = False
                    self.users[phone].socket = None
            client_socket.close()
            print(f"Client {address} disconnected")

    def handle_registration(self, phone: str, client_socket: socket.socket) -> bool:
        """Handle new user registration process."""
        # Check maximum users limit
        if len(self.users) >= 10:
            client_socket.sendall(json.dumps({
                'success': False,
                'message': 'Server has reached maximum capacity'
            }).encode())
            print("Server has reached maximum capacity of 10 users")
            return False

        # SendBySecureChannel(...) but a little bit better
        try:
            verification_code = self.generate_verification_code()

            # Send code to client
            client_socket.sendall(json.dumps({
                'verification_code': verification_code
            }).encode())

            print(f"\n=== Verification Code for {phone} ===")
            print(f"Code: {verification_code}")
            print("=====================================")

            self.SendBySecureChannel(phone, verification_code)

            try:
                # Receive encrypted verification code from client
                data = client_socket.recv(1024).decode()
                encrypted_code = bytes.fromhex(json.loads(data)['encrypted_code'])

                # Decrypt the received code
                try:
                    decrypted_code = self.decrypt_verification_code(encrypted_code)
                except Exception as e:
                    print(f"Failed to decrypt verification code: {e}")
                    client_socket.sendall(json.dumps({
                        'success': False,
                        'message': 'Decryption failed'
                    }).encode())
                    return False

                # Check verification code
                print("\n=== Verification Code Comparison ===")
                print(f"Expected code: {verification_code}")
                print(f"Decrypted code: {decrypted_code}")
                if decrypted_code != verification_code:
                    print("❌ Verification failed - codes don't match")
                    client_socket.sendall(json.dumps({
                        'success': False,
                        'message': 'Invalid verification code'
                    }).encode())
                    print(f"Invalid verification code for {phone}")
                    return False
                print("✓ Verification successful - codes match")
                print("=====================================")

                # Send success response to client
                client_socket.sendall(json.dumps({
                    'success': True,
                    'message': 'Verification successful'
                }).encode())

                # Continue with public key exchange
                try:
                    public_key_data = client_socket.recv(4096)
                    public_key = RSA.import_key(public_key_data)

                    with self.lock:
                        self.users[phone] = User(
                            phone=phone,
                            public_key=public_key,
                            registration_time=int(time.time()),
                            is_online=True,
                            socket=client_socket
                        )
                    print(f"Successfully registered user {phone}")

                    # Print all registered users
                    print("\n=== Registered Users ===")
                    print(f"Total users: {len(self.users)}/10")
                    print("-" * 60)
                    for user_phone, user in self.users.items():
                        print(f"Phone: {user_phone}")
                        print(
                            f"Registration Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user.registration_time))}")
                        print(f"Status: {'Online' if user.is_online else 'Offline'}")

                        # Add public key display
                        public_key_str = user.public_key.export_key().decode()
                        # Show first and last parts of the public key
                        key_lines = public_key_str.split('\n')
                        if len(key_lines) > 4:  # Make sure we have enough lines
                            print("Public Key:")
                            print(f"  {key_lines[0]}")  # Show header
                            print("  ...")  # Indicate omitted content
                            print(f"  {key_lines[-2]}")  # Show last part of key
                            print(f"  {key_lines[-1]}")  # Show footer

                        print("-" * 60)
                    print("=" * 60)

                    return True
                except Exception as e:
                    print(f"Error processing public key: {e}")
                    client_socket.sendall(json.dumps({
                        'success': False,
                        'message': 'Error processing public key'
                    }).encode())
                    return False

            except Exception as e:
                print(f"Error receiving verification code: {e}")
                return False

        except Exception as e:
            print(f"Registration failed for {phone}. Error: {str(e)}")
            return False

    def process_message(self, message_data: bytes):
        """Process incoming messages and delivery receipts."""
        try:
            message_dict = json.loads(message_data.decode())

            # Handle delivery receipts
            if 'type' in message_dict and message_dict['type'] == 'receipt':
                self.process_delivery_receipt(message_dict)
                return

            # Process regular messages
            encrypted_content = bytes.fromhex(message_dict['encrypted_content'])
            encrypted_aes_key = bytes.fromhex(message_dict['encrypted_aes_key'])
            signature = bytes.fromhex(message_dict['signature'])

            message = Message(
                sender_id=message_dict['sender_id'],
                recipient_id=message_dict['recipient_id'],
                encrypted_content=encrypted_content,
                encrypted_aes_key=encrypted_aes_key,
                signature=signature,
                timestamp=message_dict['timestamp']
            )

            if not self.verify_signature(message):
                print(f"Failed to verify message signature from {message.sender_id}")
                return

            # Deliver or store message
            if message.recipient_id in self.users and self.users[message.recipient_id].is_online:
                try:
                    self.users[message.recipient_id].socket.sendall(message_data)
                    print(f"Delivered message to online user {message.recipient_id}")
                except Exception as e:
                    print(f"Error delivering message to {message.recipient_id}: {e}")
                    self.store_pending_message(message)
            else:
                self.store_pending_message(message)

        except Exception as e:
            print(f"Error processing message: {e}")

    def process_delivery_receipt(self, receipt_dict: dict):
        """Process delivery receipt and forward to original sender."""
        try:
            sender_id = receipt_dict['sender_id']
            recipient_id = receipt_dict['recipient_id']
            message_timestamp = receipt_dict['message_timestamp']
            signature = bytes.fromhex(receipt_dict['signature'])

            # Verify receipt signature
            if not self.verify_receipt_signature(recipient_id, signature, json.dumps({
                'type': 'receipt',
                'message_timestamp': message_timestamp,
                'recipient_id': recipient_id,
                'sender_id': sender_id,
                'timestamp': receipt_dict['timestamp']
            }).encode()):
                print(f"Invalid receipt signature from {recipient_id}")
                return

            # Forward to original sender if online
            if sender_id in self.users and self.users[sender_id].is_online:
                try:
                    self.users[sender_id].socket.sendall(json.dumps(receipt_dict).encode())
                    print(f"Forwarded delivery receipt to {sender_id}")
                except Exception as e:
                    print(f"Error forwarding receipt to {sender_id}: {e}")

            print(f"Processed delivery receipt for message {message_timestamp} from {recipient_id}")

        except Exception as e:
            print(f"Error processing delivery receipt: {e}")

    def store_pending_message(self, message: Message):
        """Store message for offline recipient (maximum 2 messages per user)."""
        with self.lock:
            if message.recipient_id not in self.pending_messages:
                self.pending_messages[message.recipient_id] = []
            # Check pending messages limit
            if len(self.pending_messages[message.recipient_id]) >= 2:
                print(f"Maximum pending messages reached for user {message.recipient_id}")
                return
            self.pending_messages[message.recipient_id].append(message)
            print(f"Stored pending message for user {message.recipient_id}")

    def send_pending_messages(self, phone: str):
        """Send stored messages to user when they come online."""
        with self.lock:
            if phone in self.pending_messages:
                for message in self.pending_messages[phone]:
                    message_dict = {
                        'sender_id': message.sender_id,
                        'recipient_id': message.recipient_id,
                        'encrypted_content': message.encrypted_content.hex(),
                        'encrypted_aes_key': message.encrypted_aes_key.hex(),
                        'signature': message.signature.hex(),
                        'timestamp': message.timestamp
                    }
                    try:
                        self.users[phone].socket.sendall(json.dumps(message_dict).encode())
                        print(f"Sent pending message to {phone}")
                    except Exception as e:
                        print(f"Error sending pending message to {phone}: {e}")
                        continue
                print(f"Sent {len(self.pending_messages[phone])} pending messages to {phone}")
                del self.pending_messages[phone]

    def verify_signature(self, message: Message) -> bool:
        """Verify message signature using sender's public key."""
        try:
            h = SHA256.new(message.encrypted_content)
            pkcs1_15.new(self.users[message.sender_id].public_key).verify(h, message.signature)
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def verify_receipt_signature(self, recipient_id: str, signature: bytes, receipt_data: bytes) -> bool:
        """Verify delivery receipt signature."""
        try:
            h = SHA256.new(receipt_data)
            pkcs1_15.new(self.users[recipient_id].public_key).verify(h, signature)
            return True
        except Exception as e:
            print(f"Receipt signature verification failed: {e}")
            return False

    def get_public_key(self, phone: str) -> Optional[bytes]:
        """Return user's public key if exists."""
        print(f"\n=== Public Key Request ===")
        print(f"Searching for user: {phone}")

        if phone in self.users:
            print(f"✓ Found user {phone}")
            public_key = self.users[phone].public_key.export_key('PEM')
            # Show first and last few characters of the key
            key_preview = public_key.decode()
            key_lines = key_preview.split('\n')
            print("Public Key Preview:")
            print(f"  {key_lines[0]}")  # Header
            print("  ...")
            print(f"  {key_lines[-1]}")  # Footer
            print("========================")
            return public_key

        print(f"✗ User {phone} not found")
        print("========================")
        return None

    def generate_verification_code(self) -> str:
        """Generate 6-digit verification code."""
        return str(random.randint(100000, 999999))

    # SendBySecureChannel(...) With another name
    def SendBySecureChannel(self, phone: str, code: str):
        """Simulate sending verification code through secure channel."""
        print(f"\n{'=' * 50}")
        print(f"Sending verification code {code} to {phone}")
        print(f"{'=' * 50}\n")
        return True

    def decrypt_verification_code(self, encrypted_code: bytes) -> str:
        """
        Decrypt verification code using server's private key.
        """
        try:
            print("\n=== Verification Code Decryption Process ===")
            print(f"Received encrypted code (hex): {encrypted_code.hex()[:64]}...")

            # Create PKCS1_OAEP cipher object with server's private key
            cipher_rsa = PKCS1_OAEP.new(self.server_private_key)
            print("✓ Initialized RSA decryption cipher")

            # Decrypt the verification code
            decrypted_code = cipher_rsa.decrypt(encrypted_code)
            decrypted_str = decrypted_code.decode()
            print(f"Decrypted verification code: {decrypted_str}")
            print("=========================================")

            return decrypted_str

        except Exception as e:
            print(f"Error decrypting verification code: {e}")
            raise


if __name__ == "__main__":
    server = SecureServer()
    server.start()
