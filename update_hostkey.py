"""Update MT425E3_hostkey.pub — the pinned SSH host key for the device.

Use this ONLY when the device's actual SSH host key has legitimately changed
(e.g. device reflashed, replaced, or SSH host keys regenerated). This script
fetches the key the device is CURRENTLY presenting and, after you confirm the
fingerprint out-of-band (serial console, device display, etc — NOT just
trusting whatever the network handed back), overwrites the pinned key file.

If you did NOT expect the device's host key to change, do NOT run this
script — a mismatch is exactly what the pinning is meant to catch, and could
mean a MITM or a wrong/spoofed device on that IP.

Usage:
    python update_hostkey.py [host] [port]

Defaults to the host/port in settings.ini if omitted.
"""
import base64
import configparser
import os
import sys

import paramiko

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOST_KEY_FILE = os.path.join(_BASE_DIR, "MT425E3_hostkey.pub")
CONFIG_FILE = os.path.join(_BASE_DIR, "settings.ini")


def _default_host_port():
    cfg = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        cfg.read(CONFIG_FILE)
        if cfg.has_section("connection"):
            host = cfg["connection"].get("host", "192.168.1.142")
            port = cfg["connection"].getint("port", fallback=22)
            return host, port
    return "192.168.1.142", 22


def fetch_host_key(host, port, timeout=15):
    """Open a bare Transport (no auth) just to capture the server's host key."""
    sock = paramiko.transport.socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return key
    finally:
        transport.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else None
    port = int(sys.argv[2]) if len(sys.argv) > 2 else None
    if host is None or port is None:
        d_host, d_port = _default_host_port()
        host = host or d_host
        port = port or d_port

    print(f"Fetching SSH host key from {host}:{port} ...")
    try:
        key = fetch_host_key(host, port)
    except Exception as e:
        print(f"Failed to fetch host key: {e}")
        sys.exit(1)

    fingerprint = key.get_fingerprint().hex(":")
    key_type = key.get_name()
    b64 = base64.b64encode(key.asbytes()).decode()

    print()
    print(f"  Host:        {host}")
    print(f"  Key type:    {key_type}")
    print(f"  Fingerprint: {fingerprint}")
    print()
    print("VERIFY this fingerprint against the device itself (serial console /")
    print("device display / other trusted channel) BEFORE accepting — do not")
    print("just trust what the network handed back.")
    print()

    if key_type != "ecdsa-sha2-nistp256":
        print(f"WARNING: expected ecdsa-sha2-nistp256, device offered {key_type}.")
        print("This is unexpected for MT425E3 — double-check before proceeding.")
        print()

    answer = input("Fingerprint confirmed correct — write to MT425E3_hostkey.pub? [y/N] ")
    if answer.strip().lower() != "y":
        print("Aborted. Pinned host key file left unchanged.")
        sys.exit(1)

    line = f"{host} {key_type} {b64}\n"
    with open(HOST_KEY_FILE, "w") as f:
        f.write(line)

    print(f"Updated {HOST_KEY_FILE}")


if __name__ == "__main__":
    main()
