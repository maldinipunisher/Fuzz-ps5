#!/usr/bin/env python3
"""
PS5 Kernel Dump Receiver v2
Supports kdump v0.4 header format: text_base, text_size, data_base, data_size

Usage:
    python3 kernel_receiver.py [port] [output_prefix]
"""

import socket
import sys
import struct
import time

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9023
    prefix = sys.argv[2] if len(sys.argv) > 2 else "kernel_13.60"

    print(f"[*] Listening on 0.0.0.0:{port}")
    print(f"[*] Waiting for PS5...")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    conn, addr = srv.accept()
    print(f"[+] Connected from {addr[0]}")

    # Read header (32 bytes): text_base, text_size, data_base, data_size
    hdr = b""
    while len(hdr) < 32:
        hdr += conn.recv(32 - len(hdr))

    text_base, text_size, data_base, data_size = struct.unpack("<QQQQ", hdr)
    total_size = text_size + data_size

    print(f"[+] Text: 0x{text_base:x} ({text_size // 1024 // 1024} MB)")
    print(f"[+] Data: 0x{data_base:x} ({data_size // 1024 // 1024} MB)")
    print(f"[+] Total: {total_size // 1024 // 1024} MB")

    start = time.time()
    received = 0
    text_data = bytearray()
    data_data = bytearray()

    while received < total_size:
        chunk = conn.recv(65536)
        if not chunk:
            break

        if received < text_size:
            split = min(len(chunk), text_size - received)
            text_data.extend(chunk[:split])
            if split < len(chunk):
                data_data.extend(chunk[split:])
        else:
            data_data.extend(chunk)

        received += len(chunk)
        mb = received / (1024 * 1024)
        total_mb = total_size / (1024 * 1024)
        elapsed = time.time() - start
        speed = mb / elapsed if elapsed > 0 else 0
        pct = received * 100 // total_size
        print(f"\r[*] {mb:.1f} / {total_mb:.1f} MB ({pct}%) [{speed:.1f} MB/s]", end="", flush=True)

    elapsed = time.time() - start
    print(f"\n[+] Done! {received} bytes in {elapsed:.1f}s")

    # Save text dump
    text_file = f"{prefix}_text.bin"
    with open(text_file, "wb") as f:
        f.write(bytes(text_data))
    print(f"[+] Text saved: {text_file} ({len(text_data)} bytes)")

    # Save data dump
    data_file = f"{prefix}_data.bin"
    with open(data_file, "wb") as f:
        f.write(bytes(data_data))
    print(f"[+] Data saved: {data_file} ({len(data_data)} bytes)")

    # Save combined dump
    combined_file = f"{prefix}_full.bin"
    with open(combined_file, "wb") as f:
        f.write(bytes(text_data))
        # Pad gap between text end and data start
        gap = data_base - (text_base + text_size)
        if gap > 0 and gap < 0x10000000:  # sanity check < 256MB
            f.write(b'\x00' * gap)
            print(f"[*] Gap padded: {gap} bytes (0x{gap:x})")
        f.write(bytes(data_data))
    print(f"[+] Full saved: {combined_file}")

    print()
    print(f"=== Ghidra Import ===")
    print(f"  File:     {combined_file}")
    print(f"  Language: x86:LE:64:default")
    print(f"  Base:     0x{text_base:x}")
    print()
    print(f"  Or import terpisah:")
    print(f"  {text_file} → base 0x{text_base:x}")
    print(f"  {data_file} → base 0x{data_base:x}")

    conn.close()
    srv.close()

if __name__ == "__main__":
    main()
