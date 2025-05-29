# SECURITY POLICY

## 🔒 Ethical Use Only

This software is intended **strictly for authorized penetration testing and red team operations**. Any use outside the scope of **legal, documented, and approved security assessments** is prohibited and constitutes a violation of this policy and applicable laws.

## ✅ Authorization Requirements

To legally use this software, you **must**:

1. Have **written authorization** from the system owner or authorized management.
2. Use it only within the **approved testing window**.
3. Operate **only against test or staging environments**, unless explicitly permitted for production.
4. Set the required environment variable `AUTHORIZED_TESTING=TRUE` on the client side.

## 🚫 Prohibited Use

The following activities are strictly forbidden:

- Using the software against third-party infrastructure without consent.
- Engaging in denial-of-service attacks or uncontrolled payload execution.
- Distributing this tool to unverified individuals or groups.
- Running this software on personal machines without explicit permission from administrators (in an organization setting).
- Running the server as root (enforced in `ar_cyborg_server.py`).

## 🔐 Cryptographic & Safety Considerations

- All communication is encrypted using **AES-256-GCM** or **Fernet (AES-based)**.
- Authentication handshakes are enforced on both client and server.
- Certificates and PSKs must be securely generated, rotated, and stored.
- Results are hashed using **SHA3-256** to maintain integrity in logs.

## 🧠 Operator Responsibility

Users of this tool must:

- Follow the **NIST SP 800-115** and **MITRE ATT&CK** frameworks.
- Maintain professional and legal accountability during all operations.
- Be prepared to provide activity logs and test scopes if requested by stakeholders or auditors.

## 📬 Reporting Security Issues

If you discover a bug, vulnerability, or potential abuse risk in the software, please **report it privately and responsibly** to the maintainers or your security team.

---

**Remember**: This tool is a weapon — like any weapon, it must only be used with permission, precision, and purpose.
