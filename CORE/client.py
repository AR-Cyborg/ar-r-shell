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
import subprocess
from cryptography.fernet import Fernet

# ===== CONFIGURATION (MUST MODIFY FOR LEGAL USE) =====
AUTHORIZED_C2_SERVER = "your-authorized-server.example.com"  # Change to your testing server
AUTHORIZED_PORT = 443                                      # Must match server config
PSK = "YOUR_COMPANY_PSK_" + time.strftime("%Y%m%d")        # Rotating key (change to your org PSK)
TESTING_WINDOW = (9, 17)                                   # 9AM-5PM local time

# ===== SECURITY PROTOCOLS =====
def verify_authorization():
    """Hard-coded safety checks"""
    if not (TESTING_WINDOW[0] <= time.localtime().tm_hour <= TESTING_WINDOW[1]):
        sys.exit("Outside authorized testing window")
    
    if platform.system().lower() not in ["linux", "windows"]:
        sys.exit("Unsupported platform")
    
    if os.getenv("AUTHORIZED_TESTING") != "TRUE":
        sys.exit("Missing authorization environment variable")

# ===== ENCRYPTED CHANNEL =====
class SecureChannel:
    def __init__(self, psk):
        self.cipher = Fernet(
            base64.urlsafe_b64encode(
                hashlib.sha256(psk.encode()).digest()
            )
        )

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt(self, data):
        return self.cipher.decrypt(data).decode()

# ===== SAFE CONNECTION HANDLER =====
def establish_connection():
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        sock = socket.create_connection((AUTHORIZED_C2_SERVER, AUTHORIZED_PORT), timeout=30)
        secure_sock = context.wrap_socket(sock, server_hostname=AUTHORIZED_C2_SERVER)
        
        # Verify server identity
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