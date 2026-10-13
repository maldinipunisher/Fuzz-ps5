#!/usr/bin/env python3
"""
PS5 Kernel DATA Section Analyzer
Extracts function pointers, syscall table, and interesting structures
from the DATA dump for security research.
"""

import struct
import sys
import os

def read_u64(data, offset):
    if offset + 8 > len(data):
        return 0
    return struct.unpack("<Q", data[offset:offset+8])[0]

def is_text_ptr(val, text_base, text_end):
    return text_base <= val < text_end

def is_data_ptr(val, data_base, data_end):
    return data_base <= val < data_end

def is_kernel_ptr(val):
    return 0xffffffff80000000 < val < 0xffffffffffffffff

def main():
    data_file = sys.argv[1] if len(sys.argv) > 1 else "kernel_13.60_data.bin"

    # FW 13.60 — offset between text and data is always 0xCC0000
    # Addresses change each boot (KASLR) but layout is fixed
    data_base = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xffffffffc60c0000
    text_size = 0xCC0000
    text_base = data_base - text_size

    if not os.path.exists(data_file):
        print(f"[!] File not found: {data_file}")
        print(f"    Try: python3 {sys.argv[0]} /path/to/kernel_13.60_data.bin")
        return

    data = open(data_file, "rb").read()
    data_size = len(data)
    data_end = data_base + data_size
    text_end = text_base + text_size

    print(f"=== PS5 Kernel DATA Analyzer ===")
    print(f"")
    print(f"DATA file:  {data_file} ({data_size:,} bytes)")
    print(f"TEXT range:  0x{text_base:x} - 0x{text_end:x} ({text_size:,} bytes)")
    print(f"DATA range:  0x{data_base:x} - 0x{data_end:x} ({data_size:,} bytes)")

    # === 1. Scan for function pointers (TEXT pointers in DATA) ===
    print(f"\n{'='*60}")
    print(f"1. FUNCTION POINTERS (DATA → TEXT)")
    print(f"{'='*60}\n")

    text_ptrs = []
    for off in range(0, data_size - 7, 8):
        val = read_u64(data, off)
        if is_text_ptr(val, text_base, text_end):
            text_ptrs.append((off, val))

    print(f"Found {len(text_ptrs)} TEXT pointers in DATA\n")

    # Find consecutive pointer tables (likely vtables or syscall table)
    tables = []
    current_table = []
    for off, val in text_ptrs:
        if current_table and off != current_table[-1][0] + 8:
            if len(current_table) >= 4:
                tables.append(current_table[:])
            current_table = []
        current_table.append((off, val))
    if len(current_table) >= 4:
        tables.append(current_table)

    print(f"Found {len(tables)} function pointer tables (4+ consecutive entries)\n")

    for i, table in enumerate(tables):
        data_off = table[0][0]
        data_addr = data_base + data_off
        count = len(table)

        print(f"  Table {i}: data+0x{data_off:06x} (0x{data_addr:x}), {count} entries")

        # Print first few entries
        show = min(8, count)
        for j in range(show):
            off, val = table[j]
            text_off = val - text_base
            print(f"    [{j:3d}] 0x{val:x}  (text+0x{text_off:x})")
        if count > show:
            print(f"    ... ({count - show} more)")
        print()

    # === 2. Find potential syscall table ===
    print(f"{'='*60}")
    print(f"2. POTENTIAL SYSCALL TABLE")
    print(f"{'='*60}\n")

    # Syscall table (sysent) has entries like:
    # struct sysent { int narg; sy_call_t *sy_call; ... }
    # On FreeBSD, sysent entries are typically 32 bytes
    # Look for the largest function pointer table

    largest_table = max(tables, key=len) if tables else None
    if largest_table:
        data_off = largest_table[0][0]
        print(f"Largest table: {len(largest_table)} entries at data+0x{data_off:06x}")
        print(f"This is likely the syscall table (sysent[])")
        print(f"Ghidra: go to 0x{data_base + data_off:x}\n")

        # Dump first 20 entries
        for j in range(min(20, len(largest_table))):
            off, val = largest_table[j]
            text_off = val - text_base
            # Common syscall numbers
            names = {
                0: "nosys", 1: "sys_exit", 2: "fork", 3: "read",
                4: "write", 5: "open", 6: "close", 7: "wait4",
                9: "link", 10: "unlink", 12: "chdir",
                20: "getpid", 23: "setuid", 24: "getuid",
                33: "access", 37: "kill", 54: "ioctl",
                59: "execve", 73: "munmap", 74: "mprotect",
                97: "socket", 98: "connect", 104: "bind",
                203: "mlock", 477: "mmap",
            }
            name = names.get(j, "")
            print(f"    sysent[{j:3d}] → 0x{val:x} (text+0x{text_off:06x}) {name}")

    # === 3. Known offsets from exploit ===
    print(f"\n{'='*60}")
    print(f"3. KNOWN OFFSETS (from Relapse exploit)")
    print(f"{'='*60}\n")

    # From 13.60.js offsets
    known_offsets = {
        "ALLPROC":    0x03589E80,
        "ROOTVNODE":  0x03E0B510,
    }

    for name, off in known_offsets.items():
        if off < data_size:
            val = read_u64(data, off)
            print(f"  {name:20s} data+0x{off:06x} = 0x{val:x}")
            if is_kernel_ptr(val):
                print(f"    {'→ kernel pointer (valid)':>40s}")
        else:
            # Offset is relative to DATA base
            rel = off
            print(f"  {name:20s} offset 0x{off:x} (beyond data dump)")

    # === 4. Interesting patterns ===
    print(f"\n{'='*60}")
    print(f"4. INTERESTING PATTERNS")
    print(f"{'='*60}\n")

    # Find strings in DATA
    strings_found = []
    i = 0
    while i < data_size:
        if 0x20 <= data[i] < 0x7f:
            start = i
            while i < data_size and 0x20 <= data[i] < 0x7f:
                i += 1
            if i - start >= 8:
                s = data[start:i].decode('ascii', errors='replace')
                strings_found.append((start, s))
        i += 1

    print(f"Found {len(strings_found)} ASCII strings (8+ chars)\n")

    # Print interesting strings (security-related keywords)
    keywords = ['auth', 'cred', 'priv', 'root', 'uid', 'gid', 'cap',
                'perm', 'secur', 'check', 'deny', 'allow', 'sysctl',
                'ioctl', 'mmap', 'exec', 'mount', 'jail', 'mac_',
                'vnode', 'socket', 'pipe', 'kern', 'proc', 'debug',
                'kld', 'module', 'driver', 'dev', 'scsi', 'usb',
                'pfs', 'sandbox', 'encrypt', 'decrypt', 'key', 'hmac',
                'sony', 'sce', 'orbis', 'prospero']

    security_strings = []
    for off, s in strings_found:
        sl = s.lower()
        for kw in keywords:
            if kw in sl:
                security_strings.append((off, s, kw))
                break

    print(f"Security-related strings: {len(security_strings)}\n")
    for off, s, kw in security_strings[:50]:
        print(f"  data+0x{off:06x}: \"{s[:80]}\"")
    if len(security_strings) > 50:
        print(f"  ... ({len(security_strings) - 50} more)")

    # === 5. Zero-to-nonzero transitions (structure boundaries) ===
    print(f"\n{'='*60}")
    print(f"5. DATA SECTION MAP")
    print(f"{'='*60}\n")

    # Show which regions of DATA have content vs zeros
    region_size = 0x10000  # 64KB regions
    for off in range(0, data_size, region_size):
        chunk = data[off:off+region_size]
        nonzero = sum(1 for b in chunk if b != 0)
        density = nonzero / len(chunk) * 100
        bar = '#' * int(density / 5)
        if density > 0:
            # Count pointers in this region
            ptrs = sum(1 for o in range(0, len(chunk)-7, 8)
                      if is_kernel_ptr(read_u64(chunk, o)))
            print(f"  0x{off:06x}: {density:5.1f}% [{bar:20s}] {ptrs} ptrs")

    # === Summary ===
    print(f"\n{'='*60}")
    print(f"SUMMARY — Bug Bounty Targets")
    print(f"{'='*60}\n")
    print(f"  1. Syscall table at data+0x{largest_table[0][0]:06x}" if largest_table else "  1. No syscall table found")
    print(f"     → Each function pointer is a syscall handler to audit")
    print(f"     → Focus on: ioctl, mmap, execve, socket handlers")
    print(f"")
    print(f"  2. {len(tables)} function pointer tables found")
    print(f"     → These are vtables, ops tables, callback arrays")
    print(f"     → Look for missing NULL checks on function pointers")
    print(f"")
    print(f"  3. {len(security_strings)} security-related strings")
    print(f"     → Cross-reference with function pointers")
    print(f"     → Strings near function pointers = named handlers")
    print(f"")
    print(f"  4. Known offsets:")
    for name, off in known_offsets.items():
        print(f"     {name}: data+0x{off:06x}")
    print(f"")
    print(f"  Ghidra import: {data_file} → base 0x{data_base:x}")
    print(f"  Language: x86:LE:64:default")

if __name__ == "__main__":
    main()
