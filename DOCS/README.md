# Advanced Ethical Reverse Shell Framework

**Disclaimer**: This tool is for **authorized security testing and educational purposes only**. Unauthorized use against systems you don't own or have permission to test is illegal.

## Overview

A professional-grade security testing tool designed for:
- Authorized penetration testing
- Red team engagements
- Security research
- Defensive countermeasure development

## Key Features

### Stealth & Evasion
- Process name spoofing (Linux/Windows)
- TLS-encrypted C2 channels
- Dynamic PSK authentication
- Time-based activation
- Sandbox detection
- Cover traffic simulation

### Security
- Fernet AES-128 encryption
- Payload compression
- Certificate-pinned TLS
- Challenge-response authentication
- Multiple C2 fallback servers

### Operational Security
- No command history retention
- Environment blending
- Random User-Agent rotation
- Heartbeat monitoring
- Automatic cleanup

## Plugins

### Screenshot Plugin
Capture screenshots of the target system’s desktop in real-time during authorized tests.

- Supports multiple image formats (PNG by default)
- Encrypted transmission of captured images
- Lightweight and optimized for minimal footprint

### Keylogger Plugin
Records keystrokes securely and stealthily during authorized testing sessions.

- Logs keystrokes in encrypted format
- Supports pause/resume functionality
- Automatically clears logs after transmission
- Compatible with Windows and Linux platforms

## Legal Requirements

Before use, you MUST:
1. Obtain written permission from system owners
2. Comply with all applicable laws (CFAA, GDPR, etc.)
3. Disclose usage in security testing agreements
4. Maintain proper documentation of authorization

## Installation

```bash
git clone https://github.com/AR-cyborg/ar-r-shell.git
cd ar-r-shell
pip3 install -r requirements.txt
Configuration
Edit config.py with your testing parameters:

python
Copy
Edit
# Legal testing domains only
C2_SERVERS = [
    "your-test-server.example.com:443",
    "backup-test.example.com:443"
]

# Must match server configuration
DYNAMIC_PSK = "YourOrganizationPSKString"
Usage
Server Setup
Set up your listener with matching PSK

Configure valid SSL certificates

Update firewall rules for your test scope

Client Deployment
bash
Copy
Edit
# On authorized test systems only
python3 client.py --test-mode
Running Plugins
To activate the Screenshot plugin, run the client with --screenshot

To activate the Keylogger plugin, run the client with --keylogger

Testing Workflow
Obtain written authorization

Configure target scope in config.py

Deploy during authorized testing window

Document all test activities

Remove all artifacts post-testing

Defensive Countermeasures
This tool helps test detection of:

Covert C2 channels

Living-off-the-land techniques

Encrypted C2 traffic

Process spoofing

Persistence mechanisms

Responsible Disclosure
Found vulnerabilities? Contact:
alexrida31@gmail.com

License
This tool is released under the Ethical Use License:

Modification allowed for authorized testing

Commercial use prohibited

No liability accepted

Must include this disclaimer in all derivatives