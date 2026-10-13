# PS5 Kernel Dumper - Build & Usage Guide

## Prerequisites

### 1. Install ps5-payload-dev Toolchain

```bash
# Clone toolchain
git clone https://github.com/john-tornblom/ps5-payload-dev
cd ps5-payload-dev

# Build (butuh waktu ~10-20 menit)
make

# Install ke /opt (atau lokasi lain)
sudo make install PREFIX=/opt/ps5-payload-dev
```

### 2. Sesuaikan Config

Edit `kdump.c`, ubah:

```c
#define PC_IP       "192.168.1.100"   // ← IP PC kamu
#define PC_PORT     9023              // ← Port receiver  
#define DUMP_MODE   1                 // 1=TCP, 2=USB, 3=keduanya
```

## Build

```bash
# Compile
make

# Atau kalau SDK di lokasi lain:
make PS5_PAYLOAD_SDK=/path/to/ps5-payload-dev
```

Output: `kdump.elf`

## Usage

### Step 1: Jalankan Receiver di PC

```bash
cd /Users/macbookairm1/Data/Hypervisor-ps5/tools
python3 kernel_receiver.py 9023
```

### Step 2: Jalankan Relapse Exploit di PS5

```bash
# Di PC, serve Relapse exploit via HTTP
cd /Users/macbookairm1/Data/Hypervisor-ps5/Relapse-Exploit/github
python3 -m http.server 8080

# Di PS5:
# Settings → User Guide → browser terbuka
# Navigate ke: http://<PC-IP>:8080
# Tunggu: "elfldr is listening on port 9021"
```

### Step 3: Kirim Kernel Dumper ke PS5

```bash
# Dari PC
nc <PS5-IP> 9021 < kdump.elf

# Atau pakai make:
make send PS5_IP=<PS5-IP>
```

### Step 4: Tunggu Dump Selesai

- Di receiver (PC) akan terlihat progress download
- ~64MB, biasanya 1-3 menit via WiFi
- Output: `kernel_13.60_dump.bin`

### Step 5: Buka di Ghidra

1. File → Import File → `kernel_13.60_dump.bin`
2. Language: **x86:LE:64:default** (Processor: x86, Size: 64, Endian: Little)
3. Options → Base Address: `0xffffffff80000000`
4. OK → Yes to analyze
5. Tunggu Auto Analysis selesai (~5-10 menit)

## Troubleshooting

**"Cannot open /dev/dmem"**
- etaHEN/kstuff belum loaded, atau versi tidak support
- Coba jalankan exploit ulang
- Pastikan kstuffw.elf loaded sebelum kdump

**"Kernel base not found"**  
- KASLR scan range mungkin perlu diperluas
- Coba hardcode base dari Relapse exploit output (log "base 0x...")

**"connect() failed"**
- Pastikan PC dan PS5 di network yang sama
- Pastikan firewall PC tidak block port 9023
- Pastikan receiver sudah jalan sebelum kirim payload

**USB dump gagal**
- Format USB ke exFAT
- Colok ke PS5 sebelum jalankan payload
- Mount point biasanya /mnt/usb0/

## Alternatif: Tanpa Compile Sendiri

Kalau tidak mau setup toolchain, ada opsi lain:

1. **ps5debug** - GDB server, dump via `(gdb) dump binary memory`
2. **ProsperoMgr** - Sudah ada di Relapse optional payloads
3. **Community dumps** - Cari "PS5 13.60 kernel dump" di forum scene
