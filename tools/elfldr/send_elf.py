#!/usr/bin/env python3
"""
PS5 ELF Sender — send payloads to the custom ELF loader.

Usage:
    python3 send_elf.py <PS5_IP> <payload.elf> [port]
    python3 send_elf.py 192.168.100.117 ../kdump/kdump.elf
    python3 send_elf.py 192.168.100.117 ../kdump/kdump.elf 9021
"""

import socket
import sys
import os
import time

def send_elf(host, elf_path, port=9021):
    if not os.path.exists(elf_path):
        print(f"[!] File not found: {elf_path}")
        return False

    data = open(elf_path, "rb").read()
    size = len(data)

    if data[:4] != b'\x7fELF':
        print(f"[!] Not an ELF file: {elf_path}")
        return False

    print(f"[*] Sending {os.path.basename(elf_path)} ({size:,} bytes) to {host}:{port}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        sent = 0
        while sent < size:
            chunk = min(65536, size - sent)
            n = sock.send(data[sent:sent+chunk])
            if n <= 0:
                break
            sent += n

        sock.shutdown(socket.SHUT_WR)

        time.sleep(0.5)
        sock.close()

        print(f"[+] Sent {sent:,} / {size:,} bytes")
        return sent == size

    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 send_elf.py <PS5_IP> <payload.elf> [port]")
        print("")
        print("Examples:")
        print("  python3 send_elf.py 192.168.100.117 kdump.elf")
        print("  python3 send_elf.py 192.168.100.117 kdump.elf 9021")
        return

    host = sys.argv[1]
    elf_path = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 9021

    if send_elf(host, elf_path, port):
        print("[+] Done!")
    else:
        print("[!] Failed")

if __name__ == "__main__":
    main()
