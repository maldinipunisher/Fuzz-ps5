#!/usr/bin/env python3
"""
Exercise 05: Reverse Engineering Challenge

Tujuan: Practice reverse engineering skills pada binary data.
Simulasi analysis yang dilakukan saat RE firmware PS5.

Tasks:
  1. Run: python3 05_re_challenge.py
  2. Analyze the "unknown" binary structures
  3. Identify syscall table entries
  4. Find hidden function pointers
  5. Reconstruct the data structures

Ini simulasi workflow yang sama dengan tools/analyze_data.py
tapi pada data yang kita buat sendiri (controlled environment).
"""

import struct
import os

# Build a simulated kernel DATA section
def build_simulated_data():
    """Create a fake kernel DATA section with known structures."""
    data = bytearray(0x10000)  # 64KB

    TEXT_BASE = 0xffffffff81000000
    DATA_BASE = 0xffffffff81cc0000

    # --- Syscall table (sysent) at offset 0x1000 ---
    # Each entry: 4 bytes nargs + 4 bytes padding + 8 bytes function pointer
    SYSENT_OFF = 0x1000
    syscalls = [
        (0, "nosys",     TEXT_BASE + 0x1000),
        (1, "sys_exit",  TEXT_BASE + 0x2000),
        (2, "fork",      TEXT_BASE + 0x3000),
        (3, "read",      TEXT_BASE + 0x4000),
        (4, "write",     TEXT_BASE + 0x5000),
        (5, "open",      TEXT_BASE + 0x6000),
        (6, "close",     TEXT_BASE + 0x7000),
        (20, "getpid",   TEXT_BASE + 0x8000),
        (33, "access",   TEXT_BASE + 0x9000),
        (54, "ioctl",    TEXT_BASE + 0xA000),
        (59, "execve",   TEXT_BASE + 0xB000),
    ]

    for i, (num, name, addr) in enumerate(syscalls):
        off = SYSENT_OFF + i * 16
        nargs = len(name) % 6 + 1
        struct.pack_into("<I", data, off, nargs)
        struct.pack_into("<Q", data, off + 8, addr)

    # --- Sony custom syscalls at offset 0x2000 ---
    SONY_OFF = 0x2000
    sony_syscalls = [
        (400, "sce_auth_verify",    TEXT_BASE + 0x80000, 2),
        (401, "sce_get_fw_ver",     TEXT_BASE + 0x80100, 1),
        (402, "sce_sandbox_check",  TEXT_BASE + 0x80200, 3),
        (403, "sce_drm_validate",   TEXT_BASE + 0x80300, 4),  # interesting!
        (404, "sce_kern_debug",     TEXT_BASE + 0x80400, 2),  # hidden debug!
        (405, "sce_mem_protect",    TEXT_BASE + 0x80500, 5),
    ]

    for i, (num, name, addr, nargs) in enumerate(sony_syscalls):
        off = SONY_OFF + i * 16
        struct.pack_into("<I", data, off, nargs)
        struct.pack_into("<Q", data, off + 8, addr)

    # --- Strings section at offset 0x4000 ---
    strings = [
        (0x4000, b"sceSblAuthMgrVerifyHeader\x00"),
        (0x4020, b"sceSblAuthMgrIsLoadable\x00"),
        (0x4040, b"orbis_kernel_debug_enable\x00"),
        (0x4060, b"prospero_update_service\x00"),
        (0x4080, b"WARNING: unauthorized access attempt\x00"),
        (0x40B0, b"kern.qa_flags\x00"),
        (0x40C0, b"security.sandbox.exempt\x00"),
        (0x40E0, b"debug.kdb.enabled\x00"),
        (0x40F8, b"HIDDEN_KEY_1234abcd\x00"),  # suspicious!
    ]

    for off, s in strings:
        data[off:off+len(s)] = s

    # --- Function pointer table (vtable) at offset 0x6000 ---
    VTABLE_OFF = 0x6000
    vtable = [
        TEXT_BASE + 0x90000,  # init
        TEXT_BASE + 0x90100,  # open
        TEXT_BASE + 0x90200,  # read
        TEXT_BASE + 0x90300,  # write
        TEXT_BASE + 0x90400,  # ioctl
        TEXT_BASE + 0x90500,  # close
        0,                     # NULL terminator
        TEXT_BASE + 0x90600,  # hidden entry after NULL!
    ]

    for i, addr in enumerate(vtable):
        struct.pack_into("<Q", data, VTABLE_OFF + i * 8, addr)

    # --- allproc pointer at offset 0x8000 ---
    struct.pack_into("<Q", data, 0x8000, DATA_BASE + 0x9000)

    # --- Proc structure at offset 0x9000 ---
    struct.pack_into("<Q", data, 0x9000, DATA_BASE + 0x9100)  # next
    struct.pack_into("<I", data, 0x9008, 0)                    # pid
    data[0x900C:0x900C+6] = b"kernel"

    # Second proc
    struct.pack_into("<Q", data, 0x9100, 0)                    # next (NULL)
    struct.pack_into("<I", data, 0x9108, 42)                   # pid
    data[0x910C:0x910C+9] = b"SceShell"

    return bytes(data), TEXT_BASE, DATA_BASE


def challenge_analyze(data, text_base, data_base):
    """Student should try to discover these structures."""
    data_end = data_base + len(data)
    text_end = text_base + 0xCC0000

    print("=" * 60)
    print("  REVERSE ENGINEERING CHALLENGE")
    print("=" * 60)
    print()
    print(f"You have a {len(data):,} byte kernel DATA dump.")
    print(f"TEXT base: {text_base:#x}")
    print(f"DATA base: {data_base:#x}")
    print()
    print("Your tasks:")
    print("  1. Find all function pointer tables")
    print("  2. Identify the syscall table")
    print("  3. Find Sony-specific syscalls")
    print("  4. Extract interesting strings")
    print("  5. Find the allproc linked list")
    print("  6. Spot anything suspicious")
    print()

    input("Press Enter to see the solution...\n")

    # --- Solution ---
    print("=" * 60)
    print("  SOLUTION")
    print("=" * 60)

    # Scan for TEXT pointers
    print("\n[1] Scanning for TEXT pointers (function pointers)...\n")
    text_ptrs = []
    for off in range(0, len(data) - 7, 8):
        val = struct.unpack_from("<Q", data, off)[0]
        if text_base <= val < text_end:
            text_ptrs.append((off, val))
            print(f"  data+{off:#06x}: {val:#018x}  "
                  f"(text+{val - text_base:#x})")

    # Find tables
    print(f"\n  Total: {len(text_ptrs)} function pointers found")

    # Strings
    print("\n[2] Extracting strings...\n")
    i = 0
    while i < len(data):
        if 0x20 <= data[i] < 0x7f:
            start = i
            while i < len(data) and 0x20 <= data[i] < 0x7f:
                i += 1
            if i - start >= 6:
                s = data[start:i].decode('ascii', errors='replace')
                print(f"  data+{start:#06x}: \"{s}\"")

                # Flag interesting ones
                lower = s.lower()
                if any(kw in lower for kw in
                       ['debug', 'hidden', 'key', 'exempt', 'qa_flag']):
                    print(f"  {'':>14}^^^ INTERESTING! Security-relevant string")
        i += 1

    # allproc
    print("\n[3] Following allproc linked list...\n")
    allproc_off = 0x8000
    allproc_val = struct.unpack_from("<Q", data, allproc_off)[0]
    print(f"  allproc @ data+{allproc_off:#x} = {allproc_val:#x}")

    if data_base <= allproc_val < data_end:
        proc_off = allproc_val - data_base
        print(f"  → First proc at data+{proc_off:#x}")

        while proc_off and proc_off < len(data) - 0x20:
            next_ptr = struct.unpack_from("<Q", data, proc_off)[0]
            pid = struct.unpack_from("<I", data, proc_off + 8)[0]
            name_bytes = data[proc_off + 0xC:proc_off + 0x1C]
            name = name_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
            print(f"    PID {pid}: \"{name}\" (next={next_ptr:#x})")

            if next_ptr == 0:
                break
            if data_base <= next_ptr < data_end:
                proc_off = next_ptr - data_base
            else:
                break

    # Suspicious findings
    print("\n[4] Suspicious findings...\n")
    print("  a) 'HIDDEN_KEY_1234abcd' — looks like a hardcoded key/token")
    print("     → In real RE: could be debug key, test credential, etc.")
    print()
    print("  b) 'kern.qa_flags' — QA flags sysctl")
    print("     → Enables debug features when set")
    print("     → Target for post-exploit system unlock")
    print()
    print("  c) 'security.sandbox.exempt' — sandbox bypass sysctl")
    print("     → Could allow escaping application sandbox")
    print()
    print("  d) 'orbis_kernel_debug_enable' — debug enabler")
    print("     → PS4/PS5 kernel debug functionality")
    print()
    print("  e) vtable has entry AFTER NULL terminator")
    print("     → Hidden/debug function pointer?")
    print("     → Common pattern in Sony firmware")

    print("\n" + "=" * 60)
    print("  LEARNING POINTS")
    print("=" * 60)
    print()
    print("1. Function pointer tables reveal code structure")
    print("2. Strings near pointers often name the handlers")
    print("3. Sony-custom code (sce*, orbis*, prospero*) = priority targets")
    print("4. Debug/QA features = easy post-exploit escalation")
    print("5. Data after NULL terminators can hide functionality")
    print("6. Linked list walking = essential for proc/cred manipulation")
    print()


def main():
    data, text_base, data_base = build_simulated_data()

    # Save for optional offline analysis
    dump_path = "/tmp/claude-0/-home-user-Fuzz-ps5/b3b3af95-1e6b-5497-8c06-8f1b664bc3e5/scratchpad/simulated_data.bin"
    os.makedirs(os.path.dirname(dump_path), exist_ok=True)
    with open(dump_path, "wb") as f:
        f.write(data)
    print(f"[*] Simulated DATA written to: {dump_path}")
    print(f"    (Can analyze with: python3 ../../tools/analyze_data.py {dump_path})\n")

    challenge_analyze(data, text_base, data_base)


if __name__ == "__main__":
    main()
