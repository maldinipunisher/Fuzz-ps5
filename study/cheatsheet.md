# Cybersecurity Quick Reference Cheatsheet

## GDB Commands (Debugging)

```bash
# Basic
gdb ./binary                    # start debugger
run ARGS                        # run with arguments
break *0x401000                 # breakpoint at address
break function_name             # breakpoint at function
continue                        # resume execution
stepi / nexti                   # step one instruction
step / next                     # step one source line

# Inspection
info registers                  # show all registers
info frame                      # show stack frame
x/20gx $rsp                    # examine 20 qwords at RSP
x/10i $rip                     # disassemble 10 instructions at RIP
x/s 0x401000                   # print string at address
print $rax                      # print register value
vmmap                           # show memory mappings (pwndbg)

# Breakpoints & watchpoints
watch *0x7fffffffe000           # break on write to address
rwatch *0x7fffffffe000          # break on read
awatch *0x7fffffffe000          # break on read or write
info breakpoints                # list breakpoints
delete 1                        # delete breakpoint #1

# Stack
backtrace / bt                  # show call stack
frame 2                         # switch to frame #2

# Memory
find /b 0x400000, +0x1000, 0x41  # search for byte
dump memory out.bin 0x400000 0x401000  # dump to file
```

## Assembly Quick Reference (x86-64)

```nasm
; Data movement
mov rax, rbx        ; rax = rbx
mov rax, [rbx]      ; rax = *(uint64_t*)rbx
mov [rax], rbx      ; *(uint64_t*)rax = rbx
lea rax, [rbx+8]    ; rax = rbx + 8 (no dereference)
push rax             ; RSP-=8; [RSP]=RAX
pop rax              ; RAX=[RSP]; RSP+=8
xchg rax, rsp       ; swap RAX and RSP (stack pivot!)

; Arithmetic
add rax, 1           ; rax += 1
sub rax, 1           ; rax -= 1
xor rax, rax         ; rax = 0 (fast zero)
and rax, 0xFFF       ; rax &= 0xFFF (page offset mask)

; Control flow
call func            ; push RIP; jmp func
ret                  ; pop RIP; jmp RIP  ← ROP uses this!
jmp label            ; unconditional jump
je / jz              ; jump if equal/zero
jne / jnz            ; jump if not equal
syscall              ; invoke syscall (RAX=num)

; System
cli                  ; disable interrupts (ring 0)
sti                  ; enable interrupts (ring 0)
hlt                  ; halt CPU (ring 0)
lgdt [addr]          ; load GDT register (ring 0)
vmrun rax            ; enter VM (AMD SVM, ring 0)
vmmcall              ; call hypervisor from guest
```

## Python Exploit Dev (pwntools)

```python
from pwn import *

# Connect
p = process('./binary')         # local
p = remote('host', port)        # TCP

# Pack/unpack addresses
p64(0xdeadbeef)                 # 64-bit little-endian
u64(b'\xef\xbe\xad\xde\x00\x00\x00\x00')  # unpack

# Build payload
payload = b'A' * 72             # fill buffer
payload += p64(0x401234)        # overwrite return address

# Send
p.sendline(payload)
p.interactive()                 # interact with shell

# ELF analysis
elf = ELF('./binary')
elf.symbols['main']             # address of main
elf.got['printf']               # GOT entry
elf.plt['system']               # PLT entry

# ROP
rop = ROP(elf)
rop.call('system', ['/bin/sh'])
print(rop.dump())

# Shellcode
shellcode = asm(shellcraft.sh())  # spawn shell
```

## Ghidra Quick Reference

```
# Keyboard shortcuts
G           → Go to address
L           → Label/rename
T           → Set type
;           → Add comment
D           → Disassemble
F           → Create function
Ctrl+Shift+E → Decompile

# Analysis tips
1. Window → Defined Strings → search "sce", "orbis", "prospero"
2. Search → For Scalars → search 0xdeadbeef or known offsets
3. Select → Forward Refs → find callers of a function
4. Select → Back Refs → find what function calls

# Script (Python/Java)
# File → Script Manager → filter "search"
# Or Tools → Ghidra Script → write custom
```

## Common Syscall Numbers

```
FreeBSD (PS5):          Linux:
1   sys_exit            1   write
3   read                2   open
4   write               3   close
5   open                9   mmap
6   close               10  mprotect
20  getpid              57  fork
54  ioctl               59  execve
59  execve              60  exit
73  munmap              62  kill
74  mprotect            231 exit_group
477 mmap

Sony custom: 400-676 (see tools/fuzz/sony_syscall_fuzzer.c)
```

## Network Recon Commands

```bash
# Scan target
nmap -sV <target>               # service detection
nmap -sU -p 1900,5353 <target>  # UDP scan

# Capture traffic
tcpdump -i eth0 host <target> -w capture.pcap
wireshark capture.pcap

# Craft packets
scapy                           # interactive
>>> send(IP(dst="<target>")/UDP(dport=1900)/Raw("fuzz"))

# Listen for connections
nc -l -p 9024 | tee log.txt    # receive fuzzer logs
nc -l -p 9021 < payload.elf    # send ELF to loader
```

## File Format Quick Checks

```bash
# ELF
readelf -h binary               # ELF header
readelf -l binary               # program headers (segments)
readelf -S binary               # section headers
objdump -d binary               # disassemble

# Generic
file unknown_file               # identify type
xxd file.bin | head             # hex dump
strings -a file.bin             # extract strings
binwalk file.bin                # find embedded files
```

## Security Mitigations Check

```bash
# Binary protections
checksec --file=binary
# Shows: RELRO, Stack Canary, NX, PIE, RPATH, Fortify

# Kernel protections
cat /proc/sys/kernel/randomize_va_space    # ASLR (0/1/2)
cat /proc/sys/kernel/kptr_restrict         # hide kernel ptrs
dmesg | grep -i smep                       # SMEP enabled?
```
