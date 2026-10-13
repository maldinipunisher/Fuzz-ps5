# PS5 Firmware Security — Learning Roadmap

## Prerequisites

Sebelum masuk ke exploit chain, kamu perlu fondasi ini:

### 1. x86-64 Assembly
- Instruksi dasar: mov, push, pop, call, ret, jmp
- Addressing modes: RIP-relative, indirect
- Calling convention: System V AMD64 (RDI, RSI, RDX, RCX, R8, R9)
- Menulis position-independent code (PIC)
- Tools: nasm, objdump, ndisasm

### 2. OS Internals
- Virtual memory & page tables (4-level paging: PML4 → PDPT → PD → PT)
- Kernel vs userland (ring 0 vs ring 3)
- System calls, interrupts, exceptions
- ACPI & power management (S3 suspend/resume)
- ELF binary format

### 3. AMD Virtualization (AMD-V / SVM)
- VMRUN, VMEXIT, VMMCALL instruksi
- VMCB (Virtual Machine Control Block) layout
- Nested Page Tables (NPT) — host vs guest physical address
- Referensi: AMD APM Vol. 2, Chapter 15 (SVM)

---

## Step-by-Step: Exploit Chain Architecture

### Step 0 — Environment Setup (PC, bukan PS5)

Tujuan: bangun lab untuk eksperimen aman.

```
Tools yang dibutuhkan:
├── QEMU + KVM         → emulasi x86-64 dengan SVM support
├── nasm                → assembler untuk shellcode
├── gcc/clang           → compiler C untuk payload
├── gdb + pwndbg/GEF   → debugger
├── radare2 / Ghidra    → reverse engineering
├── Python 3 + pwntools → scripting & exploit dev
└── FreeBSD VM          → PS5 OS berbasis FreeBSD, jadi familiar
```

Latihan:
- Boot FreeBSD di QEMU
- Compile kernel module sederhana (hello world)
- Pelajari FreeBSD kernel structure (proc, thread, ucred)

---

### Step 1 — Memahami Entry Point (Userland Exploit)

Ini bukan bagian dari bug HV, tapi ini adalah pintu masuk.

Konsep:
- PS5 punya browser berbasis WebKit (Chromium-based)
- Vulnerability di WebKit → arbitrary code execution di userland
- Dari sini bisa pivot ke kernel exploit

Yang dipelajari:
- WebKit exploitation basics
- Use-After-Free, type confusion, JIT spraying
- Sandbox escape concepts

Latihan di lab:
- Setup WebKit build lokal
- Pelajari CVE publik yang sudah di-patch
- Buat simple exploit untuk vulnerable binary (CTF-style)

---

### Step 2 — Kernel Read/Write Primitive

Tujuan: dapat kemampuan baca/tulis arbitrary kernel memory.

Konsep pada PS5 (FreeBSD-based):
- Kernel vulnerability → arbitrary read/write
- Teknik umum: corrupted pipe, UAF di kernel object
- Dengan kernel r/w, bisa:
  - Leak kernel base (bypass KASLR)
  - Modify ucred → escalate privileges
  - Map physical memory via /dev/mem equivalent
  - Execute arbitrary kernel code via ROP

Yang dipelajari:
- FreeBSD kernel structures
- Kernel heap exploitation
- Return-Oriented Programming (ROP)
- Kernel code execution via stack pivot

Latihan di lab:
- Tulis vulnerable kernel module di FreeBSD
- Exploit sendiri di QEMU (controlled environment)
- Bangun kernel r/w primitive
- Praktik ROP chain construction

---

### Step 3 — Pre-S3 Preparation (Staging)

Ini adalah setup sebelum trigger S3 suspend.
Butuh: kernel r/w dari Step 2.

#### 3a. Stage AP Bootstrap Payload

```
Apa yang terjadi:
1. Gunakan kernel r/w untuk map physical address 0x3ffff000
2. Tulis 4KB position-independent payload ke sana
3. Payload ini adalah "bootstrap" — bukan ELF loader sendiri,
   tapi code yang akan jalan di root-0 AP
```

Yang dipelajari:
- Physical memory mapping dari kernel context
- Menulis position-independent shellcode x86-64
- Memory regions yang survive S3 suspend

Latihan:
- Tulis PIC shellcode sederhana (< 4KB) dengan nasm
- Test di QEMU: map physical memory dari kernel module
- Verifikasi shellcode bisa jalan standalone

#### 3b. Setup Debug Trap (#DB)

```
Apa yang terjadi:
1. Set hardware breakpoint (DR0-DR3) di acpi_sleep_machdep+0x18e
2. Setup #DB exception handler yang berisi ROP chain
3. ROP chain akan execute VMMCALL(0x0f, core, RIP, CR3)
```

Yang dipelajari:
- x86 Debug Registers (DR0-DR7)
- Hardware breakpoint mechanism
- Exception handling di kernel
- ROP chain yang invoke hypercall

Latihan:
- Tulis kernel module yang set hardware breakpoint
- Handle #DB exception
- Trigger dan verifikasi di QEMU

#### 3c. Trigger S3 Suspend

```
Apa yang terjadi:
1. Invoke ACPI S3 sleep dari kernel
2. Sistem suspend ke RAM
3. Saat resume, #DB akan fire di target address
```

---

### Step 4 — S3 Resume: The HV Bypass

Ini adalah inti dari bug. Terjadi otomatis saat resume.

```
Timeline saat resume:
                                                    
t0: Hardware resume, firmware reinit               
t1: Hypervisor reinit                              
    ├── startup_mp bitmap = 0 (cleared!)           
    └── semua vcore: cur_npt = 0 (root-0!)         
t2: BSP resume, fetch kernel text → cur_npt = 1    
t3: #DB fires di acpi_sleep_machdep+0x18e  ◄── TRIGGER
    └── ROP chain executes:                        
        VMMCALL(0x0f, core=15, RIP=0x3ffff000, CR3=0x68000)
t4: AP core 15 starts at 0x3ffff000               
    └── cur_npt masih 0 → root-0 → HV memory visible!
t5: acpi_wakeup_cpus() ← terlambat, AP sudah jalan
```

Yang dipelajari:
- ACPI S3 resume flow
- Hypervisor initialization sequence
- Race condition / timing window exploitation
- AMD SVM: cur_npt dan NPT root switching

---

### Step 5 — AP Payload: Root-0 Execution

AP sekarang jalan di root-0 dengan HV memory visible.

```
AP payload tasks:
1. Setup minimal CPU state
   - Load temporary GDT
   - Setup stack di area yang aman
   - Enable basic features (kalau perlu)

2. Locate hypervisor structures
   - Find pcpus[] array base
   - Read hv_heap_offset global
   - Calculate: VMCB_phys = pcpu[i].m_vmcb - hv_heap_offset

3. Walk semua 16 VMCB
   - Untuk setiap core (0-15):
     - Baca VMCB+0x90 (NESTED_CTRL) → verify == 9
     - Baca VMCB+0xB0 (NESTED_CR3) → NPT root address
     - Baca VMCB+0xB8 (Control2) → verify == 1

4. Modify NPT atau VMCB
   - Option A: Modify NESTED_CR3 → point ke crafted page table
   - Option B: Modify NPT entries → map HV pages ke guest view
   - Option C: Flip permission bits di existing NPT

5. Signal BSP bahwa bypass selesai
   - Write ke shared memory location
   - BSP polls location ini

6. Park AP
   - cli; hlt (infinite halt loop)
```

Yang dipelajari:
- Bare-metal x86-64 programming (tanpa OS)
- VMCB structure (AMD APM Vol. 2, Appendix B)
- NPT page table walking
- Physical-to-virtual address translation di HV context

---

### Step 6 — Post-HV: Unlocking the System

Sekarang BSP tahu HV sudah di-bypass. Kembali ke kernel context.

```
Dengan NPT yang sudah dimodifikasi:

1. Kernel sekarang bisa akses physical memory yang sebelumnya blocked
2. Patch kernel checks:
   ├── sceSblAuthMgrVerifyHeader → return success always
   ├── sceSblAuthMgrIsLoadable   → return true always
   └── Signature verification    → bypass
3. Enable debug/QA flags
4. Patch package installer untuk terima unsigned PKG
```

---

### Step 7 — ELF Loader Implementation

Sekarang bisa load arbitrary code.

```
ELF Loader simplified flow:

1. Receive ELF binary (via network/USB/memory)
2. Parse ELF header:
   - Verify magic: 0x7f 'E' 'L' 'F'
   - Check class: ELFCLASS64
   - Check machine: EM_X86_64
   - Read e_entry (entry point)
   - Read e_phoff (program header offset)
   - Read e_phnum (number of program headers)

3. Process Program Headers:
   for each PT_LOAD segment:
     - Allocate memory at p_vaddr with size p_memsz
     - Set permissions from p_flags (PF_R, PF_W, PF_X)
     - Copy p_filesz bytes from file offset p_offset
     - Zero remaining (p_memsz - p_filesz) bytes (BSS)

4. Setup execution environment:
   - Allocate stack
   - Setup auxiliary vector (AT_BASE, AT_ENTRY, etc.)
   - Initialize TLS if needed

5. Transfer control:
   - Jump to e_entry
```

---

### Step 8 — FPKG Support

Layer terakhir: user-friendly package installation.

```
FPKG toolchain:

PC-side (tools):
├── orbis-pub-gen (atau equivalent)
│   └── Buat .pkg file dengan structure yang valid
├── SELF maker
│   └── Convert ELF → fake SELF (tanpa real signature)
└── PFS image builder
    └── Buat encrypted filesystem image (dengan known keys)

Console-side (patches dari Step 6):
├── Package installer menerima unsigned PKG
├── Auth manager menerima unsigned SELF
├── PFS layer bisa decrypt dengan patched keys
└── Content license check di-bypass
```

FPKG install flow:
```
User creates .pkg on PC
        │
        ▼
Transfer ke PS5 (USB atau network)
        │
        ▼
PS5 package installer (patched) ──► Install tanpa signature check
        │
        ▼
Game/app muncul di home screen
        │
        ▼
Launch → SELF loader (patched) ──► Load tanpa auth check
        │
        ▼
Application berjalan
```

---

## Recommended Learning Order

```
Phase 1 - Foundations (2-4 minggu)
├── x86-64 assembly basics
├── ELF format deep dive
├── FreeBSD kernel basics
└── Setup QEMU lab

Phase 2 - Virtualization (2-3 minggu)
├── Baca AMD APM Vol. 2 Ch. 15
├── Tulis mini hypervisor di QEMU
├── Pahami VMCB, NPT, VMRUN
└── Experiment: guest ↔ host transition

Phase 3 - Exploitation Basics (3-4 minggu)
├── Kernel exploitation di CTF
├── ROP chain construction
├── Shellcode writing (PIC)
└── Kernel module exploitation di FreeBSD

Phase 4 - Integration (2-3 minggu)
├── Gabungkan semua: kernel exploit + HV interaction
├── S3 suspend/resume di QEMU
├── Physical memory mapping
└── ELF loader implementation

Phase 5 - Deep Study (ongoing)
├── Baca PS5 security research papers
├── Ikuti conference talks (CCC, DEF CON, Black Hat)
├── Kontribusi ke open-source security tools
└── Responsible disclosure practices
```

---

## Key References

- AMD APM Vol. 2 — Secure Virtual Machine (SVM) specification
- FreeBSD Kernel Developer's Manual
- ELF specification (System V ABI)
- ACPI specification — S3 sleep states
- Conference talks: PS4/PS5 security (fail0verflow, SpecterDev, etc.)
