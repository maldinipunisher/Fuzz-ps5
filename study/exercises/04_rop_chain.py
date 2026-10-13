#!/usr/bin/env python3
"""
Exercise 04: ROP Chain Construction

Tujuan: Pahami bagaimana ROP chain dibangun untuk bypass NX/DEP.

Ini adalah simulator — tidak perlu vulnerable binary.
Kita simulasikan memory layout dan gadget chaining.

Tasks:
  1. Run: python3 04_rop_chain.py
  2. Study bagaimana gadgets dipilih
  3. Pahami stack layout saat ROP chain dieksekusi
  4. Modify chain untuk call fungsi berbeda
  5. Map konsep ini ke Step 3b di learning-roadmap.md
     (ROP chain yang invoke VMMCALL)
"""

import struct

# Simulated memory layout (addresses will be different each time with ASLR)
KERNEL_BASE = 0xffffffff81000000
GADGET_BASE = KERNEL_BASE + 0x100000

# Simulated gadget catalog (found via ROPgadget or ropper)
GADGETS = {
    "pop_rdi":     GADGET_BASE + 0x0042,  # pop rdi; ret
    "pop_rsi":     GADGET_BASE + 0x0089,  # pop rsi; ret
    "pop_rdx":     GADGET_BASE + 0x0156,  # pop rdx; ret
    "pop_rcx":     GADGET_BASE + 0x0234,  # pop rcx; ret
    "pop_r8":      GADGET_BASE + 0x0312,  # pop r8; ret
    "pop_rax":     GADGET_BASE + 0x0445,  # pop rax; ret
    "mov_cr3_rdi": GADGET_BASE + 0x1002,  # mov cr3, rdi; ret (ring 0!)
    "xchg_rsp":    GADGET_BASE + 0x2001,  # xchg rax, rsp; ret (stack pivot)
    "ret":         GADGET_BASE + 0x0001,  # ret (NOP slide for alignment)
}

# Simulated kernel functions
FUNCTIONS = {
    "mprotect":      KERNEL_BASE + 0x50000,
    "copyout":       KERNEL_BASE + 0x50100,
    "kprintf":       KERNEL_BASE + 0x50200,
    "vmmcall":       KERNEL_BASE + 0x60000,  # VMMCALL wrapper
    "commit_creds":  KERNEL_BASE + 0x70000,  # change process creds
}

def p64(val):
    """Pack 64-bit value (little-endian)."""
    return struct.pack("<Q", val)

def build_privilege_escalation_chain():
    """
    ROP chain for privilege escalation.
    Equivalent to: commit_creds(prepare_kernel_cred(0))

    This is what happens after controlling RIP in kernel context.
    """
    chain = b""

    print("=== ROP Chain: Privilege Escalation ===\n")
    print("Stack layout (lowest address first):\n")

    # Step 1: Set RDI = 0 (NULL for prepare_kernel_cred)
    print(f"  RSP+0x00: pop rdi; ret       @ {GADGETS['pop_rdi']:#018x}")
    print(f"  RSP+0x08: 0x0000000000000000  (RDI = NULL)")
    chain += p64(GADGETS["pop_rdi"])
    chain += p64(0)  # RDI = NULL

    # Step 2: Call prepare_kernel_cred(NULL) → returns root cred in RAX
    # (simulated, real addr would differ)
    prepare_cred = KERNEL_BASE + 0x70100
    print(f"  RSP+0x10: prepare_kernel_cred @ {prepare_cred:#018x}")
    chain += p64(prepare_cred)

    # Step 3: Move RAX (returned cred) to RDI for commit_creds
    # Need: mov rdi, rax; ret  (or equivalent)
    mov_rdi_rax = GADGET_BASE + 0x3001
    print(f"  RSP+0x18: mov rdi, rax; ret  @ {mov_rdi_rax:#018x}")
    chain += p64(mov_rdi_rax)

    # Step 4: Call commit_creds(rdi)
    print(f"  RSP+0x20: commit_creds       @ {FUNCTIONS['commit_creds']:#018x}")
    chain += p64(FUNCTIONS["commit_creds"])

    # Step 5: Return to userland (swapgs; iretq)
    # Or use a kernel function that does this safely
    kret = KERNEL_BASE + 0x80000
    print(f"  RSP+0x28: return_to_user     @ {kret:#018x}")
    chain += p64(kret)

    print(f"\n  Total chain size: {len(chain)} bytes ({len(chain)//8} qwords)")
    return chain


def build_vmmcall_chain():
    """
    ROP chain that invokes VMMCALL — from Step 3b of learning-roadmap.md.
    This is what the #DB exception handler executes on S3 resume.

    VMMCALL(0x0f, core=15, RIP=0x3ffff000, CR3=0x68000)

    In AMD SVM, VMMCALL causes a #VMEXIT to the hypervisor.
    The hypervisor reads the arguments and acts on them.
    Hypercall 0x0f = "start AP core" (Sony custom).
    """
    chain = b""

    AP_PAYLOAD_ADDR = 0x3ffff000
    AP_CR3 = 0x68000
    AP_CORE = 15
    HCALL_START_AP = 0x0f

    print("\n=== ROP Chain: VMMCALL (HV Bypass) ===\n")
    print("Goal: VMMCALL(0x0f, core=15, RIP=0x3ffff000, CR3=0x68000)\n")
    print("This chain fires inside the #DB exception handler")
    print("during S3 resume, when cur_npt=0 (root-0).\n")
    print("Stack layout:\n")

    # Set up arguments per AMD VMMCALL convention
    # RAX = hypercall number (0x0f)
    print(f"  RSP+0x00: pop rax; ret       @ {GADGETS['pop_rax']:#018x}")
    print(f"  RSP+0x08: 0x000000000000000f  (RAX = HCALL_START_AP)")
    chain += p64(GADGETS["pop_rax"])
    chain += p64(HCALL_START_AP)

    # RDI = core number (15)
    print(f"  RSP+0x10: pop rdi; ret       @ {GADGETS['pop_rdi']:#018x}")
    print(f"  RSP+0x18: 0x000000000000000f  (RDI = core 15)")
    chain += p64(GADGETS["pop_rdi"])
    chain += p64(AP_CORE)

    # RSI = RIP for AP (0x3ffff000)
    print(f"  RSP+0x20: pop rsi; ret       @ {GADGETS['pop_rsi']:#018x}")
    print(f"  RSP+0x28: 0x000000003ffff000  (RSI = AP payload RIP)")
    chain += p64(GADGETS["pop_rsi"])
    chain += p64(AP_PAYLOAD_ADDR)

    # RDX = CR3 for AP (0x68000)
    print(f"  RSP+0x30: pop rdx; ret       @ {GADGETS['pop_rdx']:#018x}")
    print(f"  RSP+0x38: 0x0000000000068000  (RDX = AP CR3)")
    chain += p64(GADGETS["pop_rdx"])
    chain += p64(AP_CR3)

    # Execute VMMCALL
    print(f"  RSP+0x40: vmmcall wrapper    @ {FUNCTIONS['vmmcall']:#018x}")
    chain += p64(FUNCTIONS["vmmcall"])

    print(f"\n  Total chain size: {len(chain)} bytes ({len(chain)//8} qwords)")
    print(f"\n  After VMMCALL:")
    print(f"    → AP core 15 starts at 0x{AP_PAYLOAD_ADDR:x}")
    print(f"    → cur_npt still 0 (root-0) → HV memory visible!")
    print(f"    → AP can read/modify VMCB, NPT, HV structures")

    return chain


def build_stack_pivot_chain():
    """
    Stack pivot: redirect RSP to attacker-controlled memory.
    Needed when overflow is small but attacker has larger buffer elsewhere.
    """
    chain = b""
    fake_stack = 0x41414000

    print("\n=== ROP Chain: Stack Pivot ===\n")
    print("When overflow space is limited, pivot RSP to a larger buffer.\n")

    # xchg rax, rsp; ret → swap RSP with RAX
    # First set RAX to our fake stack
    print(f"  RSP+0x00: pop rax; ret       @ {GADGETS['pop_rax']:#018x}")
    print(f"  RSP+0x08: 0x{fake_stack:016x}  (RAX = fake stack)")
    chain += p64(GADGETS["pop_rax"])
    chain += p64(fake_stack)

    print(f"  RSP+0x10: xchg rax,rsp; ret  @ {GADGETS['xchg_rsp']:#018x}")
    chain += p64(GADGETS["xchg_rsp"])

    print(f"\n  After pivot: RSP = 0x{fake_stack:x}")
    print(f"  → Continue ROP from the fake stack (larger buffer)")
    print(f"  → Fake stack prepared via heap spray or mmap")

    return chain


def hexdump(data, base_addr=0):
    """Pretty print a ROP chain as hex dump."""
    print(f"\nRaw bytes (for payload construction):\n")
    for i in range(0, len(data), 8):
        val = struct.unpack("<Q", data[i:i+8])[0]
        print(f"  offset {i:3d}: {val:#018x}  "
              f"({data[i:i+8].hex()})")


def main():
    print("=" * 60)
    print("  ROP Chain Construction Exercise")
    print("=" * 60)
    print()
    print("ROP = Return-Oriented Programming")
    print("Chain together existing code snippets ('gadgets')")
    print("Each gadget ends in RET → pops next addr from stack")
    print()

    chain1 = build_privilege_escalation_chain()
    hexdump(chain1)

    chain2 = build_vmmcall_chain()
    hexdump(chain2)

    chain3 = build_stack_pivot_chain()
    hexdump(chain3)

    print("\n" + "=" * 60)
    print("  Key Takeaways")
    print("=" * 60)
    print()
    print("1. ROP chains exploit existing code — no shellcode needed")
    print("2. Each 'pop X; ret' gadget loads a register from the stack")
    print("3. Stack layout = the 'program' you write as attacker")
    print("4. Finding gadgets: ROPgadget, ropper, or manual search")
    print("5. KASLR makes addresses unknown → need info leak first")
    print("6. In PS5: ROP chain in #DB handler calls VMMCALL")
    print("   to start AP core in root-0 (HV bypass)")
    print()

    # Finding gadgets cheat sheet
    print("Finding gadgets in a binary:")
    print("  ROPgadget --binary kernel.bin --only 'pop|ret'")
    print("  ropper -f kernel.bin --search 'pop rdi'")
    print("  objdump -d kernel.bin | grep -A1 'pop.*rdi'")
    print()


if __name__ == "__main__":
    main()
