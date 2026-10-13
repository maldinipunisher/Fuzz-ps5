# PS5 Security Research Methodology
# Tujuan: Mencari Bug untuk Sony (Bug Bounty / Responsible Disclosure)

## 1. Sony Bug Bounty Program

Sony menjalankan bug bounty via HackerOne:
- URL: https://hackerone.com/playstation
- Scope: PlayStation hardware dan firmware
- Rewards: hingga $50,000+ untuk critical bugs (kernel/HV level)
- Tipe bug: memory corruption, privilege escalation, sandbox escape, HV bypass

Yang diterima:
- Kernel vulnerabilities
- Hypervisor escape
- Secure boot bypass
- Sandbox escape
- WebKit RCE

Yang TIDAK diterima:
- Social engineering
- Physical attacks yang butuh disassembly hardware
- Bugs di game/app third-party

## 2. Research Setup — Tanpa Harus Update

### Masalah Utama
```
Kamu butuh test di firmware terbaru,
TAPI kalau update PS5, exploit lama hilang.

Solusi: Multi-device atau multi-approach strategy
```

### Pendekatan A: Dual Console
```
PS5 #1 (FW ≤13.60)          PS5 #2 (FW terbaru)
├── Exploited               ├── Target testing
├── Dump firmware            ├── Test attack surface
├── Extract keys             ├── Verify bugs
├── RE kernel & HV           └── Black-box testing
└── Reference device
```

### Pendekatan B: Single Console + Offline Analysis
```
Kalau hanya punya 1 PS5 di FW terbaru (14.10):

1. Black-box testing (tanpa exploit)
   ├── Fuzz dari luar (network, USB, Bluetooth)
   ├── Observe error messages & crash behavior
   ├── Timing side-channels
   └── Browser-based testing (WebKit attack surface)

2. Offline firmware analysis (kalau punya keys)
   ├── Decrypt PUP → extract binaries
   ├── RE di Ghidra tanpa perlu PS5
   ├── Cari bugs di disassembly
   └── Verify di PS5 nanti
```

### Pendekatan C: Emulation (Terbatas)
```
Saat ini tidak ada full PS5 emulator untuk security research.
Yang bisa dipakai:
├── QEMU + FreeBSD → test kernel-level bugs di OS yang sama
├── Custom SVM hypervisor di QEMU → test HV attack surface
└── WebKit build lokal → test browser bugs tanpa PS5
```

## 3. Step-by-Step: Mencari Bug Baru

### Phase 1: Reconnaissance (1-2 minggu)

```
Tujuan: Pahami attack surface firmware terbaru

A. Diff firmware versions
   1. Dapatkan decrypted binaries FW 13.60 (dari community/keys)
   2. Dapatkan decrypted binaries FW 14.10 (butuh keys)
   3. BinDiff kernel 13.60 vs 14.10
   4. Identifikasi:
      ├── Fungsi yang berubah → kemungkinan patch
      ├── Fungsi baru → attack surface baru
      └── Fungsi yang TIDAK berubah → bug lama mungkin masih ada

B. Audit patch gaps
   1. Cek FreeBSD security advisories terbaru
   2. Cek WebKit security advisories
   3. Bandingkan: apakah Sony sudah merge semua patch?
   4. N-day: bug yang sudah di-fix upstream tapi belum di PS5

C. Map attack surface
   1. List semua syscall (terutama Sony custom: 0x200+)
   2. List semua hypercall (HCALL 0x00-0x1F)
   3. List semua ioctl handlers
   4. List network-facing services
   5. List USB device handlers
```

### Phase 2: Target Selection (1 minggu)

```
Pilih target berdasarkan:

                    Impact
                      ↑
    HV escape         │  ★★★★★
    Kernel exploit    │  ★★★★
    Sandbox escape    │  ★★★
    WebKit RCE        │  ★★
    Info leak         │  ★
                      └──────────→ Difficulty

Untuk pemula, mulai dari:
1. WebKit bugs (paling accessible, source terbuka)
2. Network stack (fuzzable dari luar)
3. File parser bugs (USB mounted files)

Untuk advanced:
1. Kernel syscall bugs (butuh code audit)
2. Hypercall bugs (butuh HV binary)
3. Race conditions (butuh deep understanding)
```

### Phase 3: Bug Hunting (berminggu-minggu)

#### 3A. WebKit Research (tanpa exploit, tanpa keys)

```
WebKit source = open source (webkit.org)
PS5 WebKit = modified WebKit (Sony version)

Strategi:
1. Build WebKit versi yang dipakai PS5
   - Identify version dari User-Agent string
   - git checkout ke commit yang tepat
   
2. Fuzz WebKit lokal
   - Setup libFuzzer atau AFL++ 
   - Target: JSC (JavaScript Core), DOM, Layout
   - Generate test cases otomatis
   
3. Audit recent WebKit commits
   - Baca security fixes di WebKit changelog
   - Cek apakah PS5 sudah update ke versi itu
   - Kalau belum → potential n-day
   
4. Test di PS5 browser
   - Serve HTML test cases via HTTP
   - Observe: crash? hang? unexpected behavior?
   - Crash = potential bug → investigate root cause

Tools:
├── WebKit source: git clone https://github.com/nicot/WebKit
├── Fuzzer: AFL++, libFuzzer
├── PS5 testing: simple HTTP server + PS5 browser
└── Crash analysis: Address Sanitizer pada local build
```

#### 3B. Network Fuzzing (tanpa exploit)

```
PS5 punya network services yang bisa di-fuzz dari luar:

Target:
├── UPnP/SSDP (port 1900 UDP)
├── mDNS (port 5353 UDP)
├── PSN protocol (various ports)
├── Remote Play protocol
├── Media streaming (DLNA)
└── System update checker

Tools:
├── Scapy (Python) → craft custom packets
├── boofuzz → protocol fuzzer
├── Wireshark → capture & analyze PS5 traffic
└── nmap → enumerate open ports

Langkah:
1. Connect PS5 dan PC ke network yang sama
2. Scan PS5: nmap -sV <ps5-ip>
3. Capture traffic: tcpdump / Wireshark
4. Identify protocols
5. Fuzz setiap protocol handler
6. Monitor PS5 behavior (crash → reboot = kernel panic)
```

#### 3C. USB Fuzzing (tanpa exploit)

```
PS5 memproses USB devices → potential attack surface

Target:
├── USB mass storage (filesystem parsing)
├── USB HID (keyboard, controller)
├── USB audio
└── USB descriptors

Tools:
├── Facedancer (USB emulation hardware)
├── Raspberry Pi Zero W (USB gadget mode)
└── Custom USB descriptors

Langkah:
1. Setup Facedancer atau Pi Zero sebagai USB gadget
2. Emulasi USB device dengan descriptors malformed
3. Plug ke PS5
4. Monitor: crash? unexpected behavior?
5. Jika crash → investigate descriptor yang menyebabkan
```

#### 3D. Kernel Audit (butuh decrypted binary)

```
Kalau punya decrypted kernel binary:

1. Load di Ghidra
2. Focus areas:
   ├── Sony custom syscalls (0x200+)
   │   └── Cari: missing bounds check, integer overflow
   ├── AIO subsystem
   │   └── Race conditions, UAF
   ├── Pipe operations
   │   └── Buffer management bugs
   ├── ioctl handlers
   │   └── Missing validation
   └── Memory management
       └── Double free, use-after-free

3. Cross-reference dengan exploit yang sudah ada:
   - Relapse pakai aio_multi_wait UAF
   - Apakah ada syscall serupa yang punya pattern sama?
   - Sony custom code = lebih likely ada bug
     (karena kurang di-audit dibanding FreeBSD upstream)
```

### Phase 4: Exploit Development (berminggu-minggu)

```
Setelah menemukan bug:

1. Determine exploitability
   ├── Bisa trigger reliably?
   ├── Bisa kontrol data setelah corruption?
   ├── Ada mitigasi (ASLR, stack canary, etc)?
   └── Crash = DoS only, atau bisa escalate?

2. Write proof-of-concept
   ├── Minimal trigger code
   ├── Demonstrate impact
   └── Document preconditions

3. Test di PS5 (kalau applicable)
   ├── WebKit bugs: test via browser
   ├── Network bugs: test via network
   ├── Kernel bugs: butuh userland exploit dulu
   └── HV bugs: butuh kernel exploit dulu
```

### Phase 5: Responsible Disclosure

```
PENTING: Jangan publish bug tanpa koordinasi dengan Sony

1. Submit ke Sony via HackerOne
   - Deskripsi lengkap
   - Steps to reproduce
   - Impact assessment
   - Proof of concept (jika ada)

2. Tunggu response (biasanya 1-4 minggu)

3. Sony assess dan tentukan bounty

4. Sony patch di firmware update berikutnya

5. Setelah patch di-release (biasanya 90 hari),
   kamu boleh publish writeup

Bounty estimates:
├── WebKit RCE:        $10,000 - $20,000
├── Kernel LPE:        $20,000 - $40,000  
├── Sandbox escape:    $15,000 - $30,000
├── HV escape:         $40,000 - $50,000+
└── Secure boot:       $50,000+
```

## 4. Cara Test Exploit di Firmware Terbaru

### Tanpa Exploit Sebelumnya (Black-box)

```
WebKit bugs:
  PC → HTTP server → PS5 browser → test payload
  ✅ Bisa test langsung

Network bugs:
  PC → send packets → PS5 network stack
  ✅ Bisa test langsung

USB bugs:
  USB gadget → PS5 USB port
  ✅ Bisa test langsung

Kernel bugs:
  ❌ Butuh code execution dulu (WebKit exploit)
  
HV bugs:
  ❌ Butuh kernel exploit dulu
```

### Dengan Exploit Chain Partial

```
Punya WebKit exploit untuk FW terbaru?
  → Test kernel bugs via syscall dari userland
  
Punya kernel exploit untuk FW terbaru?
  → Test HV bugs via hypercall dari kernel
  
Ini mengapa exploit chain dibangun bottom-up:
  WebKit → Kernel → HV → Secure Processor
```

### Offline Verification (tanpa PS5)

```
Untuk bugs yang ditemukan via RE:

1. Verify logic bug di disassembly
   - Trace code path yang vulnerable
   - Confirm preconditions terpenuhi
   
2. Test di FreeBSD VM (untuk kernel bugs)
   - Port vulnerable code ke FreeBSD VM
   - Test apakah bug trigger
   - CAVEAT: Sony modifications mungkin berbeda

3. Test di QEMU (untuk HV bugs)
   - Buat mini hypervisor yang replicate vulnerable path
   - Test exploit logic
   - Port ke PS5 kalau berhasil
```

## 5. Quick Start: Mulai Dari Mana?

```
Minggu 1-2: Setup
├── Install Ghidra, nasm, QEMU
├── Build WebKit dari source
├── Setup FreeBSD VM
├── Setup HTTP server untuk PS5 testing
└── Baca Relapse exploit code (sudah ada!)

Minggu 3-4: WebKit Fuzzing
├── Identify PS5 WebKit version
├── Setup fuzzer lokal
├── Generate dan test cases
├── Test di PS5 browser
└── Triage crashes

Minggu 5-8: Deeper Analysis
├── Jika punya keys: decrypt FW, audit kernel
├── Jika tidak: focus pada WebKit + network
├── Study Relapse exploit patterns
├── Cari pattern serupa di area lain
└── Network fuzzing parallel

Minggu 9+: Exploit Development
├── Develop PoC untuk bugs yang ditemukan
├── Test di PS5
├── Submit ke Sony via HackerOne
└── Dokumentasi untuk writeup
```
