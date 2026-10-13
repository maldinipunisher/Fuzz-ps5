# Cybersecurity Fundamentals — Study Guide

Panduan belajar cybersecurity dari dasar hingga advanced,
fokus pada offensive security research (exploit dev, reverse engineering, fuzzing).

---

## Bagian 1: Memory & CPU Fundamentals

### 1.1 Memory Layout (x86-64)

```
Program Memory Layout (Virtual Address Space):

┌─────────────────────────┐ 0xFFFFFFFFFFFFFFFF
│     Kernel Space        │ ← Ring 0 only
│  (kernel text, data,    │
│   page tables, drivers) │
├─────────────────────────┤ 0xFFFF800000000000
│        ...              │ ← Non-canonical gap
├─────────────────────────┤ 0x00007FFFFFFFFFFF
│        Stack            │ ← Grows downward ↓
│          ↓              │
│        ...              │
│          ↑              │
│        Heap             │ ← Grows upward ↑ (malloc/mmap)
├─────────────────────────┤
│        BSS              │ ← Uninitialized globals (zeroed)
│        Data             │ ← Initialized globals
│        Text             │ ← Executable code (read-only)
└─────────────────────────┘ 0x0000000000000000
```

Penting untuk exploit development:
- **Stack**: tempat return address, local variables, saved registers
- **Heap**: dynamic allocation — UAF, double-free, overflow
- **Kernel space**: target privilege escalation

### 1.2 x86-64 Register Map

```
General Purpose (64-bit):
RAX  ← return value / syscall number
RBX  ← callee-saved (preserved across calls)
RCX  ← 4th arg (syscall: used for return addr)
RDX  ← 3rd argument
RSI  ← 2nd argument
RDI  ← 1st argument
RBP  ← base pointer (frame pointer)
RSP  ← stack pointer
R8   ← 5th argument
R9   ← 6th argument
R10  ← used in syscalls (replaces RCX)
R11  ← scratch (clobbered by syscall)
R12-R15 ← callee-saved

Special:
RIP  ← instruction pointer (target for hijack!)
RFLAGS ← status flags (ZF, CF, OF, etc.)

Segment (mostly legacy, but important):
CS, DS, SS, ES, FS, GS
FS/GS ← used for TLS, kernel per-CPU data (GSBASE)

Control (Ring 0 only):
CR0  ← protection enable, paging enable
CR2  ← page fault linear address
CR3  ← page table root (PML4 base) ← penting untuk NPT!
CR4  ← extensions (SMAP, SMEP, FSGSBASE)

Debug:
DR0-DR3  ← hardware breakpoint addresses
DR6      ← debug status
DR7      ← debug control (enable/type/length)
```

### 1.3 Calling Convention (System V AMD64 ABI)

```
Function call:  func(a1, a2, a3, a4, a5, a6, ...)
Registers:       RDI  RSI  RDX  RCX  R8   R9   stack

Syscall:        syscall(num, a1, a2, a3, a4, a5, a6)
Registers:       RAX   RDI  RSI  RDX  R10  R8   R9

Return:         RAX (both)

Caller-saved:   RAX, RCX, RDX, RSI, RDI, R8-R11
Callee-saved:   RBX, RBP, R12-R15, RSP
```

Ini critical untuk:
- Menulis ROP chains (kontrol register = kontrol args)
- Memahami syscall fuzzer (lihat `sony_syscall_fuzzer.c`)
- Debugging dengan GDB

---

## Bagian 2: Vulnerability Classes

### 2.1 Stack Buffer Overflow

Paling klasik. Terjadi saat data di-write melewati batas buffer di stack.

```c
// VULNERABLE: no bounds check
void process_input(char *user_data) {
    char buf[64];
    strcpy(buf, user_data);  // ← overflow jika len > 64
}

// Stack layout saat process_input() dipanggil:
// ┌──────────────┐ High address
// │  Return Addr │ ← TARGET: overwrite ini!
// │  Saved RBP   │
// │  buf[63]     │
// │  ...         │
// │  buf[0]      │ ← strcpy mulai dari sini
// └──────────────┘ Low address (RSP)
```

Mitigasi modern:
- **Stack canary**: random value antara buffer dan return addr
- **ASLR**: randomize stack address
- **NX/DEP**: stack non-executable → butuh ROP
- **SMEP/SMAP** (kernel): prevent kernel executing/accessing user pages

### 2.2 Use-After-Free (UAF)

Object dipakai setelah di-free. Tipe bug yang dipakai di Relapse exploit
(`aio_multi_wait` UAF).

```c
// Pattern UAF:
struct victim {
    void (*callback)(void);
    int data;
};

struct victim *obj = malloc(sizeof(struct victim));
obj->callback = safe_function;
obj->data = 42;

free(obj);           // ← object freed

// ... attacker allocates same-size object here ...
// spray heap to reclaim the freed chunk

obj->callback();     // ← BOOM: calls attacker-controlled pointer!
```

Kenapa powerful:
1. Attacker spray heap dengan data terkontrol
2. Freed object di-reclaim dengan data attacker
3. Function pointer di-overwrite → arbitrary code execution
4. Di kernel: UAF pada kernel object = kernel code execution

Relapse exploit chain menggunakan pola ini:
- `aio_multi_wait` punya race condition → UAF
- Spray kernel heap untuk reclaim freed object
- Hijack function pointer → kernel r/w primitive

### 2.3 Type Confusion

Object diakses sebagai tipe yang salah. WebKit exploit di Relapse
menggunakan "structured clone object pool mismatch" — variant dari ini.

```c
// Simplified type confusion:
struct TypeA {
    int type_tag;       // offset 0
    char data[32];      // offset 4
};

struct TypeB {
    int type_tag;       // offset 0
    void (*func_ptr)(); // offset 4  ← overlaps TypeA.data!
    size_t length;      // offset 12
};

// Jika TypeA di-cast ke TypeB:
struct TypeA *a = create_type_a();
a->data[0] = 0x41;  // attacker controls

struct TypeB *b = (struct TypeB *)a;  // ← type confusion!
b->func_ptr();  // calls 0x41414141... → crash or code exec
```

### 2.4 Integer Overflow

```c
// Vulnerable allocation:
size_t count = user_input;        // e.g., 0x100000001
size_t elem_size = 16;
size_t total = count * elem_size; // wraps to 0x10! (32-bit wrap)

char *buf = malloc(total);        // tiny allocation
for (size_t i = 0; i < count; i++) {
    read_element(buf + i * elem_size);  // massive heap overflow
}
```

### 2.5 Race Condition

Dua thread/proses mengakses shared state tanpa proper synchronization.
`aio_multi_wait` bug di Relapse termasuk race condition.

```
Thread A (normal)              Thread B (attacker)
─────────────────              ────────────────────
obj = alloc()
obj->refcount = 1
                               // trigger: refcount--
                               // refcount = 0 → free(obj)
use(obj)                       // ← UAF! Thread A uses freed obj
```

TOCTOU (Time-of-Check to Time-of-Use):
```c
// Kernel vulnerability pattern:
if (copyin(user_ptr, &val, 8) == 0) {   // CHECK: read from user
    // attacker changes *user_ptr here!
    if (val < ARRAY_SIZE) {              // CHECK passes
        copyin(user_ptr, &val, 8);       // USE: read again — different!
        array[val] = data;               // OUT OF BOUNDS
    }
}
```

---

## Bagian 3: Exploitation Techniques

### 3.1 Return-Oriented Programming (ROP)

Setelah NX/DEP, stack tidak bisa execute code. Solusi: chain existing code
"gadgets" (instructions ending in `ret`).

```
Gadget = short instruction sequence ending in RET:

Gadget 1: pop rdi; ret        ← load RDI dari stack
Gadget 2: pop rsi; ret        ← load RSI dari stack
Gadget 3: call mprotect       ← make memory executable

ROP Chain on stack:
┌───────────────────────┐
│ addr of "pop rdi; ret"│ ← RSP points here after overflow
│ 0x7fff00000000        │ ← value for RDI (address)
│ addr of "pop rsi; ret"│
│ 0x1000                │ ← value for RSI (size)
│ addr of "pop rdx; ret"│
│ 0x7                   │ ← value for RDX (PROT_RWX)
│ addr of mprotect()    │ ← call mprotect(addr, size, rwx)
│ addr of shellcode     │ ← after mprotect, jump to shellcode
└───────────────────────┘
```

Relevansi di PS5:
- Step 3b di learning-roadmap.md: ROP chain yang invoke VMMCALL
- `#DB exception handler berisi ROP chain`
- `ROP chain akan execute VMMCALL(0x0f, core, RIP, CR3)`

### 3.2 Kernel Exploitation Primitives

Apa yang kamu butuhkan dari kernel exploit:

```
Level 1: Information Leak
  → Leak kernel base address (bypass KASLR)
  → Leak kernel object addresses (heap feng shui)

Level 2: Arbitrary Read
  → Baca data kernel dari userland
  → Dump kernel structures, credentials, keys

Level 3: Arbitrary Write
  → Tulis data ke kernel memory dari userland
  → Modify credentials, bypass checks

Level 4: Code Execution
  → Execute arbitrary code di ring 0
  → Via ROP, JOP, or direct function call

Privilege escalation pattern (FreeBSD):
  1. Leak kernel base → find proc structure
  2. Walk allproc list → find our process
  3. Read ucred from our proc
  4. Overwrite ucred.cr_uid = 0 (root)
  5. Overwrite ucred.cr_groups[0] = 0 (wheel)
  → Process is now root!
```

### 3.3 Heap Feng Shui (Heap Spray/Shaping)

Kontrol layout heap supaya freed object di-reclaim dengan data kita.

```
Strategy:
1. Understand allocator slab sizes (e.g., 64, 128, 256 bytes)
2. Allocate many objects of TARGET size → fill slab
3. Free the target object → creates hole
4. Allocate CONTROLLED object of same size → fills the hole
5. Target object's memory now contains our data

Kernel heap spray (FreeBSD):
  - Use sendmsg() with controlled data
  - Use pipe buffers
  - Use knotes (kevent)
  - Any syscall that allocates kernel memory of known size
```

### 3.4 KASLR Bypass

Kernel Address Space Layout Randomization: kernel base address acak tiap boot.

```
Bypass techniques:
1. Info leak:
   - Side channel (timing, cache)
   - Kernel pointer leaked to userland (proc info, error msg)
   - Use-after-read (read freed kernel object)

2. Brute force (limited):
   - Kernel entropy biasanya 16-24 bits
   - Tapi crash = reboot di PS5

3. Known offset:
   - Jika punya 1 leaked kernel address
   - Semua offset relatif terhadap base tetap
   - text_to_data offset = 0xCC0000 (fixed di FW 13.60)
```

---

## Bagian 4: Fuzzing Deep Dive

### 4.1 Apa itu Fuzzing?

Automated testing: kirim input random/semi-random ke target,
monitor untuk crash/hang/unexpected behavior.

```
                    ┌──────────┐
 Test cases ──────► │  Target  │ ──────► Monitor
 (generated)        │ Program  │         (crash? hang? leak?)
                    └──────────┘
                         │
                    ┌────┴────┐
                    │ Crash!  │ → Analyze → Bug report
                    └─────────┘
```

### 4.2 Fuzzing Strategies

```
1. Dumb Fuzzing (Black-box):
   - Random mutations pada valid input
   - No knowledge of target internals
   - Contoh: tools/fuzz/sony_syscall_fuzzer.c
     → Kirim edge-case values ke setiap syscall

2. Coverage-guided (Grey-box):
   - Instrument target untuk track code coverage
   - Mutate inputs yang trigger new code paths
   - Tools: AFL++, libFuzzer, honggfuzz
   - Best for: file parsers, protocol handlers

3. Grammar-based (Smart):
   - Generate valid inputs berdasarkan grammar/spec
   - Mutate di level semantik, bukan byte
   - Best for: compilers, interpreters, WebKit JS

4. Stateful:
   - Maintain state antara test cases
   - Penting untuk: protocol fuzzing, ioctl sequences
   - Contoh: tools/fuzz/ioctl_fuzzer.c
```

### 4.3 Target Selection untuk Fuzzing

```
High-value targets (paling likely punya bugs):

1. Parser code:
   ├── File format parsers (ELF, PKG, PFS, image)
   ├── Protocol parsers (USB descriptors, network)
   └── Serialization (JSON, XML, structured clone)

2. Sony-custom code:
   ├── Syscalls 400-676 (lihat sony_syscall_fuzzer.c)
   ├── Proprietary ioctl handlers
   └── Custom kernel modules
   Kenapa? Kurang di-audit dibanding upstream FreeBSD.

3. Privilege boundaries:
   ├── Syscall handlers (user → kernel boundary)
   ├── Hypercall handlers (guest → host boundary)
   ├── Sandbox escape paths
   └── Auth/crypto verification code

4. Error handling paths:
   ├── Unusual error conditions (ENOMEM, EIO)
   ├── Timeout handling
   └── Cleanup/teardown code (sering ada bugs)
```

---

## Bagian 5: Reverse Engineering

### 5.1 Tools & Workflow

```
Static Analysis (tanpa run):
├── Ghidra (free, NSA) — decompiler + disassembler
│   └── Lihat tools/ghidra_export.py
├── IDA Pro (commercial) — industry standard
├── Binary Ninja — modern alternative
├── radare2/rizin (free CLI) — scriptable
└── objdump, readelf — quick ELF inspection

Dynamic Analysis (saat run):
├── GDB + pwndbg/GEF — debugger
├── strace/dtrace — syscall tracing
├── Frida — dynamic instrumentation
├── QEMU — full system emulation
└── Valgrind — memory error detection

Workflow:
1. Load binary di Ghidra → auto-analysis
2. Identify entry points (main, syscall handlers)
3. Find interesting functions (string xrefs, imports)
4. Decompile → understand logic
5. Annotate (rename vars, add types, comments)
6. Cross-reference dengan source (FreeBSD for PS5)
7. Identify bugs → write exploit
```

### 5.2 Binary Diffing

Bandingkan dua versi firmware untuk cari patches (= bugs yang di-fix).

```
BinDiff workflow:
1. Export IDB/BinExport dari Ghidra untuk kedua versi
2. Run BinDiff: match functions antara versi
3. Focus pada:
   ├── Modified functions → patch = dulu ada bug
   ├── New functions → new attack surface
   └── Removed functions → deprecated, tapi mungkin masih callable

N-day hunting:
  FW 13.60 (exploited) ─────► FW 14.10 (target)
  BinDiff shows:                                
  ├── aio_multi_wait: CHANGED ← known bug patched
  ├── sce_new_handler: CHANGED ← potential new fix!
  └── Check FreeBSD advisories untuk N-days
```

### 5.3 PS5 Specifics

```
PS5 kernel = FreeBSD 11 fork + Sony modifications:

Sony additions to look for:
├── Prefix "sce" → Sony Computer Entertainment functions
├── Prefix "orbis" → PS4 codename, still in PS5
├── Prefix "prospero" → PS5 codename
├── Syscalls 400-676 → not in FreeBSD upstream
├── Hypervisor → AMD SVM-based, Sony custom
└── Secure processor → ARM TrustZone co-processor

Key structures (from Relapse offsets):
├── allproc (data+0x03589E80) → linked list of all processes
├── rootvnode (data+0x03E0B510) → filesystem root
├── sysent[] → syscall dispatch table
└── ucred → user credentials (uid, gid, caps)
```

---

## Bagian 6: Defense & Mitigations

Harus paham defenses supaya bisa bypass mereka.

### 6.1 Memory Safety Mitigations

```
┌─────────────────┬──────────────────────┬──────────────────────┐
│ Mitigation       │ What it does         │ Bypass technique     │
├─────────────────┼──────────────────────┼──────────────────────┤
│ ASLR/KASLR       │ Randomize addresses  │ Info leak, side chan │
│ Stack Canary     │ Detect stack smash   │ Leak canary, format  │
│ NX/DEP           │ Non-executable stack │ ROP/JOP chains       │
│ SMEP             │ No user-exec in kern │ Kernel ROP, remap    │
│ SMAP             │ No user-access kern  │ copy_from_user       │
│ CFI              │ Check call targets   │ Valid-target reuse   │
│ PAC (ARM)        │ Pointer auth codes   │ Signing gadgets      │
│ Sandbox          │ Restrict syscalls    │ Escape bugs          │
│ Hypervisor       │ Isolate kernel       │ HV bugs (Relapse!)   │
└─────────────────┴──────────────────────┴──────────────────────┘
```

### 6.2 PS5 Security Architecture

```
┌─────────────────────────────────────────┐
│            Secure Processor             │ ← ARM, handles keys
│          (sceAuthMgr, fSELF)            │    & signature verify
├─────────────────────────────────────────┤
│            Hypervisor (HV)              │ ← AMD SVM, NPT
│          (memory isolation)             │    Step 4: race bug
├─────────────────────────────────────────┤
│         FreeBSD Kernel (Ring 0)         │ ← Step 2: UAF → r/w
│     (process mgmt, drivers, fs)         │
├─────────────────────────────────────────┤
│            Sandbox (userland)           │ ← WebKit sandbox
├─────────────────────────────────────────┤
│        Application (Ring 3)             │ ← Step 1: WebKit bug
│     (browser, games, apps)              │
└─────────────────────────────────────────┘

Exploit chain attacks bottom-up:
  WebKit RCE → Sandbox Escape → Kernel Exploit → HV Bypass
```

---

## Bagian 7: Networking & Protocols

### 7.1 Network Attack Surface

```
PS5 exposed services (dari research-methodology.md):

Protocol        Port     Attack Vector
─────────────────────────────────────────
UPnP/SSDP       1900 UDP  XML parsing, command injection
mDNS             5353 UDP  Name resolution, buffer overflow
DLNA             varies    Media metadata parsing
Remote Play      varies    Stream protocol, auth bypass
PSN              443 TCP   TLS, API logic bugs
System Update    443 TCP   Update verification bypass
```

### 7.2 USB Attack Surface

```
USB attack vectors:
1. Malformed descriptors → parser crash
2. Bad filesystem on USB mass storage
3. Oversized control transfers
4. Gadget emulation (Facedancer, Pi Zero)
5. BadUSB-style HID injection

Fuzzing: see research-methodology.md Section 3C
```

---

## Bagian 8: Cryptography Basics

### 8.1 Crypto Used in PS5

```
Signature verification:
├── RSA (for SELF signing, firmware updates)
├── ECDSA (for content licenses)
└── SHA-256 (hashing for integrity)

Encryption:
├── AES-128/256 (PFS filesystem, saves)
├── AES-XTS (storage encryption)
└── ChaCha20 (potentially in newer FW)

Key hierarchy:
├── Root keys (in secure processor, hardware fused)
├── Per-console keys (derived from root + console ID)
├── Per-game keys (from license)
└── Session keys (ephemeral)

Attack points:
├── Bypass verification (Step 6: patch sceSblAuthMgr)
├── Key extraction (need secure processor access)
├── Downgrade attacks (use old signed firmware)
└── Fault injection (glitching, voltage)
```

---

## Bagian 9: Legal & Ethical Framework

### 9.1 Responsible Disclosure

```
ALWAYS:
✓ Test only on devices YOU own
✓ Report bugs via official channels (HackerOne)
✓ Wait for patch before publishing
✓ Document impact accurately
✓ Follow coordinated disclosure timeline (90 days)

NEVER:
✗ Distribute tools that enable piracy
✗ Attack production infrastructure
✗ Sell exploits on black market
✗ Bypass DRM for distribution purposes
✗ Test on other people's devices/accounts
```

### 9.2 Bug Bounty Process

```
1. Find bug → document reproduction steps
2. Assess impact (RCE? LPE? Info leak?)
3. Write clear report:
   ├── Summary (1 paragraph)
   ├── Technical details
   ├── Steps to reproduce
   ├── Impact assessment
   ├── Proof of concept (if safe)
   └── Suggested fix (optional)
4. Submit to Sony via HackerOne
5. Respond to questions from security team
6. Receive bounty after verification
7. Wait for fix before any publication
```

---

## Recommended Study Path

```
Week 1-2:  Assembly & Memory
  ├── Write x86-64 assembly (nasm)
  ├── Understand stack frames, calling conventions
  ├── Study ELF format (readelf, objdump)
  └── Exercise: study/exercises/01_buffer_overflow.c

Week 3-4:  OS Internals
  ├── FreeBSD kernel basics (proc, thread, ucred)
  ├── Virtual memory, page tables
  ├── Syscalls (how they work, how to fuzz them)
  └── Exercise: study/exercises/02_kernel_structures.c

Week 5-6:  Vulnerability Classes
  ├── UAF, type confusion, integer overflow
  ├── Study Relapse exploit code
  ├── Practice on CTF challenges
  └── Exercise: study/exercises/03_uaf_demo.c

Week 7-8:  Exploitation
  ├── ROP chain construction
  ├── Heap exploitation (feng shui)
  ├── KASLR bypass techniques
  └── Exercise: study/exercises/04_rop_chain.py

Week 9-10: Reverse Engineering
  ├── Ghidra: load binary, analyze, decompile
  ├── Binary diffing between FW versions
  ├── Identify Sony-custom code
  └── Exercise: study/exercises/05_re_challenge.py

Week 11-12: Fuzzing
  ├── Study existing fuzzers (tools/fuzz/)
  ├── Write custom fuzzers
  ├── Triage crashes
  └── Exercise: write fuzzer for new target

Week 13+: Specialization
  ├── Hypervisor internals (AMD SVM)
  ├── Secure processor research
  ├── Advanced exploitation techniques
  └── Bug bounty submissions
```

---

## Key References

- AMD64 Architecture Programmer's Manual (APM) Vol. 1-5
- FreeBSD Design & Implementation (McKusick)
- The Art of Exploitation (Erickson)
- A Guide to Kernel Exploitation (Perla & Oldani)
- Hacking: The Art of Exploitation, 2nd Ed
- CTF resources: pwn.college, exploit.education, OverTheWire
- PS5 security talks: CCC, DEF CON, Black Hat archives
