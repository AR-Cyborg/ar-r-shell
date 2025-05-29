# Usage Guide for Advanced Ethical Reverse Shell Framework

## Prerequisites

- Written authorization for all target systems
- Proper configuration of `config.py` with C2 servers and PSK
- Valid SSL certificates installed on the server
- Python 3.10+ installed on client and server machines

---

## Server Setup

1. Place your SSL certificates (`tactical.pem` and `tactical.key`) in the appropriate directory.
2. Set the PSK environment variable (or modify in the server script).
3. Run the server:
   ```bash
   python3 server.py
Confirm the server is listening on the configured IP and port.

Client Setup & Basic Usage
Clone and install dependencies:

bash
Copy
Edit
git clone https://github.com/AR-cyborg/ar-r-shell.git
cd ar-r-shell
pip3 install -r requirements.txt
Edit config.py to specify authorized C2 servers and PSK.

Run the client on authorized systems only:

bash
Copy
Edit
python3 client.py --test-mode
Plugin Usage
Screenshot Plugin
Capture the target machine’s screen:

bash
Copy
Edit
python3 client.py --screenshot
Screenshots will be captured periodically.

Data is encrypted and sent back to the C2 server.

Use only during authorized testing windows.

Keylogger Plugin
Log keystrokes on the target machine:

bash
Copy
Edit
python3 client.py --keylogger
Records keystrokes securely.

Logs are transmitted encrypted.

Supports pausing and resuming logging.

Use strictly within authorized scopes.

Commands Summary
Command	Description
--test-mode	Launch client in interactive mode
--screenshot	Enable Screenshot plugin
--keylogger	Enable Keylogger plugin

Operational Notes
Always ensure you are within the authorized testing window.

Document all test activities for compliance.

Clean up all artifacts after tests.

Never run the client or server as root unless strictly necessary.

Maintain updated PSKs and certificates.

Troubleshooting
Connection issues: Check firewall rules and network configuration.

Authentication errors: Verify PSK consistency on client and server.

Plugin issues: Ensure dependencies for plugins are installed (Pillow for screenshots, pynput for keylogger).

Logs and errors are output on client and server consoles.

Contact & Support
For help, issues, or responsible disclosure, email:
alexrida31@gmail.com