#!/usr/bin/env python3
"""
Setup script for Mumbojumbo - Generates config and provides exact commands to run
"""

import sys
import os

def print_section(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")

def main():
    print_section("Mumbojumbo Setup Guide")

    print("This guide will help you set up and run the Mumbojumbo DNS tunnel.\n")

    # Step 1: Generate config
    print_section("STEP 1: Generate Configuration File")
    print("Run this command to generate a configuration skeleton with keys:\n")
    print("  ./venv/bin/python3 mumbojumbo.py --gen-config-skel > config.ini\n")
    print("Then edit config.ini and set:")
    print("  - domain: Your domain (e.g., .example.com)")
    print("  - network-interface: Your network interface (e.g., eth0)")
    print("  - SMTP settings if you want email forwarding\n")
    print("Make sure to secure the config file:")
    print("  chmod 600 config.ini\n")

    # Step 2: Generate password
    print_section("STEP 2: (Optional) Encrypt SMTP Password")
    print("If using SMTP forwarding, encrypt your password:\n")
    print("  ./venv/bin/python3 mumbojumbo.py --encrypt\n")
    print("Copy the encrypted password into config.ini\n")

    # Step 3: Test SMTP
    print_section("STEP 3: (Optional) Test SMTP Configuration")
    print("Test that SMTP is working:\n")
    print("  ./venv/bin/python3 mumbojumbo.py --config config.ini --test-smtp\n")

    # Step 4: Run server
    print_section("STEP 4: Start Mumbojumbo Server")
    print("Start the server to listen for DNS queries:\n")
    print("  sudo ./venv/bin/python3 mumbojumbo.py --config config.ini\n")
    print("Note: Requires sudo for packet capture with tshark\n")

    # Step 5: Client usage
    print_section("STEP 5: Send Data from Client")
    print("Option A - Use the HTML client:")
    print("  1. Open client.html in a web browser")
    print("  2. Type your message")
    print("  3. Click 'Send via DNS'")
    print("  4. Check browser console for generated DNS queries\n")

    print("Option B - Use Python test client:")
    print("  In another terminal, run:")
    print("  ./venv/bin/python3 test.py --test-client\n")

    # Step 6: Test locally
    print_section("STEP 6: Test Server (Local Testing)")
    print("For testing the server without a real client:\n")
    print("  Terminal 1: ./venv/bin/python3 test.py --test-server")
    print("  Terminal 2: ./venv/bin/python3 test.py --test-client\n")

    # Additional commands
    print_section("Additional Commands")
    print("Generate a single key pair:")
    print("  ./venv/bin/python3 mumbojumbo.py --gen-keys\n")

    print("Run tests:")
    print("  ./venv/bin/python3 test.py\n")

    print("Test performance:")
    print("  ./venv/bin/python3 test.py --test-performance\n")

    print("Test DNS queries:")
    print("  ./venv/bin/python3 test.py --test-dns\n")

    # Quick start
    print_section("Quick Start (Minimal Setup)")
    print("For a quick test without SMTP:\n")
    print("1. Generate config:")
    print("   ./venv/bin/python3 mumbojumbo.py --gen-config-skel > config.ini\n")

    print("2. Edit config.ini and remove or comment out the [smtp] section\n")

    print("3. Start server (requires sudo):")
    print("   sudo ./venv/bin/python3 mumbojumbo.py --config config.ini\n")

    print("4. In another terminal, send test data:")
    print("   ./venv/bin/python3 test.py --test-client\n")

    # Architecture
    print_section("How It Works")
    print("1. Client encrypts data using NaCl public key cryptography")
    print("2. Data is fragmented into chunks (default 80 bytes)")
    print("3. Each fragment is encoded as a DNS query subdomain")
    print("4. Server captures DNS queries using tshark")
    print("5. Server decrypts and reassembles fragments")
    print("6. Complete messages are forwarded via SMTP or printed\n")

    # Requirements
    print_section("Requirements")
    print("- Python 3.6+")
    print("- pynacl package (installed in venv)")
    print("- tshark (Wireshark command-line tool)")
    print("  Install on Ubuntu/Debian: apt-get install tshark")
    print("  Install on macOS: brew install wireshark")
    print("- Root/sudo access for packet capture\n")

    # Security notes
    print_section("Security Notes")
    print("⚠️  This is a demonstration implementation!")
    print("- No timestamp protection (vulnerable to replay attacks)")
    print("- HMAC shared secret issues")
    print("- Use only for educational purposes or authorized testing")
    print("- Always use strong, randomly generated keys")
    print("- Protect your config.ini file (chmod 600)\n")

    print_section("Example Configuration File")
    print("""
[main]
domain = .example.com
network-interface = eth0
client-pubkey = <base64-encoded-public-key>
server-privkey = <base64-encoded-private-key>

[smtp]
server = smtp.gmail.com
port = 587
start-tls
username = youruser@gmail.com
encrypted-password = <encrypted-password-from-encrypt-command>
from = youruser@gmail.com
to = recipient@example.com
""")

    print("\n" + "="*70)
    print("  For more information, see README or source code comments")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
