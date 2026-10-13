#!/usr/bin/env python3
"""
PS5 Fuzzer Log Receiver
Receives and saves fuzzer output from PS5 payloads.

Usage:
    python3 fuzz_receiver.py [port]

Default port: 9024
Output: fuzz_log_<timestamp>.txt
"""

import socket
import sys
import time
import os

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9024

    print(f"[*] Fuzzer log receiver on 0.0.0.0:{port}")
    print(f"[*] Waiting for PS5...")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    conn, addr = srv.accept()
    print(f"[+] Connected from {addr[0]}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    logfile = f"fuzz_log_{ts}.txt"
    f = open(logfile, "w")
    f.write(f"# PS5 Fuzzer Log — {ts}\n")
    f.write(f"# Source: {addr[0]}\n\n")

    total = 0
    interesting = 0

    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break

            text = data.decode("utf-8", errors="replace")
            f.write(text)
            f.flush()

            for line in text.split("\n"):
                if "[!!!]" in line or "SIGNAL" in line:
                    print(f"\033[91m{line}\033[0m")
                    interesting += 1
                elif "[+]" in line and "syscall" in line.lower():
                    print(f"\033[93m{line}\033[0m")
                elif "[+]" in line and "ioctl" in line.lower():
                    print(f"\033[93m{line}\033[0m")
                elif "===" in line:
                    print(f"\033[96m{line}\033[0m")
                else:
                    print(line, end="" if line.endswith("\n") else "\n")

            total += len(data)

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")

    f.close()
    conn.close()
    srv.close()

    print(f"\n[+] Saved {total:,} bytes to {logfile}")
    print(f"[+] {interesting} signals/crashes detected")

    if interesting > 0:
        print(f"\n[!] INTERESTING RESULTS FOUND!")
        print(f"    Review {logfile} for crash details.")
        print(f"    Each SIGNAL = potential vulnerability.")

if __name__ == "__main__":
    main()
