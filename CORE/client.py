#!/usr/bin/env python3
"""
SECUREPEN CLIENT - ETHICAL TESTING TOOL
Version: 1.0 (Stable)
Author: [Your Name / Organization]
License: Ethical Use Only

STRICT REQUIREMENTS:
1. Must have written authorization for target systems
2. Only use during authorized testing windows
3. Never use against production systems without approval
"""

import os
import sys
import time
import socket
import ssl
import hashlib
import platform
import base64
from cryptography.fernet import Fernet

# ===== CONFIGURATION (MODIFY BEFORE USE) =====
AUTHORIZED_C2_SERVER = "YOUR.C2.SERVER.IP"  # Replace with your server IP/hostname
AUTHORIZED_PORT = 2095                       # Change if needed
PSK = "YOUR_SECRET_PSK"                      # Replace with your Pre-Shared Key (keep secret)
TESTING_WINDOW = (0, 23)                     # Authorized hours (0-23)

# ===== SECURITY PROTOCOLS =====
def verify_authorization():
    """Basic checks for authorized testing environment"""
    current_hour = time.localtime().tm_hour
    if not (TESTING_WINDOW[0] <= current_hour <= TESTING_WINDOW[1]):
        sys.exit("Outside authorized testing window")
    
    if platform.system().lower() not in ["linux", "windows"]:
        sys.exit("Unsupported platform")
    
    if os.getenv("AUTHORIZED_TESTING") != "TRUE":
        sys.exit("Missing authorization environment variable")

# ===== ENCRYPTED CHANNEL =====
class SecureChannel:
    def __init__(self, psk):
        key = hashlib.sha256(psk.encode()).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt(self, data):
        return self.cipher.decrypt(data).decode()

# ===== SAFE CONNECTION HANDLER =====
def establish_connection():
    try:
        context = ssl._create_unverified_context()  # Disable cert verification for testing

        sock = socket.create_connection((AUTHORIZED_C2_SERVER, AUTHORIZED_PORT), timeout=30)
        secure_sock = context.wrap_socket(sock, server_hostname=AUTHORIZED_C2_SERVER)

        # Verify server identity with PSK (SHA-256 hash)
        secure_sock.sendall(hashlib.sha256(PSK.encode()).hexdigest().encode())
        if secure_sock.recv(1024) != b"AUTH_OK":
            raise ValueError("Server authentication failed")

        return SecureChannel(PSK), secure_sock

    except Exception as e:
        print(f"Connection error: {str(e)}")
        sys.exit(1)

# ===== MAIN =====
if __name__ == "__main__":
    print("SecurePen Client - Authorized Use Only")
    verify_authorization()

    try:
        channel, conn = establish_connection()
        print(f"Secure session established with {AUTHORIZED_C2_SERVER}")

        while True:
            cmd = input("securepen> ").strip()
            if cmd.lower() in ["exit", "quit"]:
                conn.sendall(channel.encrypt("SESSION_TERMINATE"))
                break

            conn.sendall(channel.encrypt(cmd))
            response = channel.decrypt(conn.recv(4096))
            print(response)

    except KeyboardInterrupt:
        print("\nSession terminated by user")

    finally:
        if 'conn' in locals():
            conn.close()
        print("Cleanup complete")
