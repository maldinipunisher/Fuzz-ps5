; ============================================================
; Shellcode Basics — Position-Independent Code (PIC)
; ============================================================
;
; Tujuan: Pahami cara menulis shellcode x86-64
; yang bisa berjalan di address mana pun (PIC).
;
; Ini relevan untuk:
;   - Step 3a: AP bootstrap payload (4KB PIC di 0x3ffff000)
;   - Step 5: AP payload yang jalan di root-0
;   - Payload yang dikirim via ELF loader
;
; Assemble:
;   nasm -f bin -o shellcode.bin shellcode_basics.asm
;
; Disassemble (verify):
;   ndisasm -b 64 shellcode.bin
;
; Test (Linux):
;   nasm -f elf64 -o shellcode.o shellcode_basics.asm
;   ld -o shellcode shellcode.o
;   ./shellcode
;
; ============================================================

BITS 64

; --- Example 1: Hello World syscall (Linux) ---
; Demonstrates basic syscall invocation.
; On PS5/FreeBSD, syscall numbers are different.

section .text
global _start

_start:
    ; write(1, msg, len)
    ; syscall number for write = 1 (Linux), 4 (FreeBSD)
    mov rax, 1          ; syscall: write (Linux)
    mov rdi, 1          ; fd: stdout
    lea rsi, [rel msg]  ; RIP-relative addressing (PIC!)
    mov rdx, msg_len    ; length
    syscall

    ; exit(0)
    mov rax, 60         ; syscall: exit (Linux)
    xor rdi, rdi        ; status: 0
    syscall

msg: db "Hello from shellcode!", 0x0a
msg_len equ $ - msg


; ============================================================
; NOTES ON POSITION-INDEPENDENT CODE (PIC)
; ============================================================
;
; WRONG (not PIC):
;   mov rsi, msg        ; absolute address — breaks at different address
;
; RIGHT (PIC):
;   lea rsi, [rel msg]  ; RIP-relative — works at any address
;   call get_rip        ; or use call/pop trick
;   get_rip: pop rsi    ; RSI = address of get_rip
;
; Rules for PIC shellcode:
;   1. Never use absolute addresses
;   2. Use RIP-relative (lea reg, [rel label])
;   3. Or use call/pop to get current RIP
;   4. Avoid .data section — embed data after code
;   5. Keep it small (< 4KB for AP payload)
;   6. No external dependencies (no libc)
;
; ============================================================
; FREEBSD DIFFERENCES (relevant for PS5)
; ============================================================
;
; FreeBSD syscall numbers (partial):
;   1  = sys_exit
;   3  = read
;   4  = write
;   5  = open
;   6  = close
;   20 = getpid
;   54 = ioctl
;   59 = execve
;   73 = munmap
;   74 = mprotect
;   477 = mmap
;
; FreeBSD syscall convention:
;   Same as Linux: RAX=num, RDI,RSI,RDX,R10,R8,R9
;   But uses 'syscall' instruction (same as Linux on x86-64)
;
; Sony-custom syscalls: 400-676 (see sony_syscall_fuzzer.c)
;
; ============================================================
; AP PAYLOAD STRUCTURE (Step 5 from learning-roadmap.md)
; ============================================================
;
; The AP payload runs in root-0 (no NPT = full physical access).
; It needs to:
;   1. Setup minimal CPU state (GDT, stack)
;   2. Find hypervisor structures (pcpus[], VMCB)
;   3. Modify NPT/VMCB
;   4. Signal BSP (write to shared memory)
;   5. Park (cli; hlt loop)
;
; Skeleton (pseudocode as ASM):
;
;   ap_entry:
;       ; 1. Setup
;       lgdt [rel ap_gdt_ptr]
;       mov rsp, 0x3fffe000      ; temp stack below payload
;
;       ; 2. Find structures
;       mov rdi, PCPUS_PHYS_ADDR
;       ; ... read pcpus[0].m_vmcb ...
;
;       ; 3. Modify VMCB
;       mov rax, [rdi + VMCB_NESTED_CR3_OFF]
;       ; ... modify NPT entries ...
;
;       ; 4. Signal BSP
;       mov dword [SIGNAL_ADDR], 0xDEADBEEF
;
;       ; 5. Park
;       cli
;   .halt:
;       hlt
;       jmp .halt
