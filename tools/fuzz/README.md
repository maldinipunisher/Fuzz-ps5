# PS5 Kernel Vulnerability Fuzzing Results — FW 13.60

**Date:** 2026-10-13
**Target:** PS5 FW 13.60, via Relapse exploit (kernel R/W active)
**Method:** Systematic fuzzing of 134 Sony-specific syscalls
**Purpose:** HackerOne bug bounty (Sony PlayStation)

---

## Summary

**9 vulnerabilities found** in Sony-custom kernel syscalls:
- 2 Kernel Information Leaks
- 7 Kernel Panic (NULL pointer dereference / DoS)

---

## Vulnerability Details

### BUG #1 — Syscall 421: Kernel Info Leak + KASLR Bypass [HIGH]

- **Syscall:** 421 (nargs=1)
- **Trigger:** `syscall(421, output_buffer)`
- **Impact:** Leaks **1216 bytes** of kernel data to userspace, including:
  - **Kernel pointer at offset 0x70:** `0xffff8b8703313a50` (KASLR bypass)
  - Userspace pointers at offsets 0x48, 0x88, 0xF8
  - ~736 bytes uninitialized kernel stack memory (includes residue from prior syscalls like `write()`)
  - Call counters at offsets 0xA8, 0xB0, 0xB8 (increment each call)
- **Stability:** 100% reproducible, ret=0 every call
- **Size arg ignored:** Always writes 1216 bytes regardless of arg2
- **String residue found:** `"buffer) ---"` at offset 0x200 — kernel stack data from prior `write()` syscall
- **Exploit value:** Independent KASLR bypass (no routing socket needed). Could replace Relapse's KASLR leak step.
- **PoC:** `target421.elf`

### BUG #2 — Syscall 618: Kernel Info Leak [MEDIUM]

- **Syscall:** 618 (nargs=3)
- **Trigger:** `syscall(618, output_buffer, arg2, arg3)` — all args succeed (0, buf, -1)
- **Impact:** Leaks **56 bytes** kernel data to buffer
- **Data:** Includes `01 00 00 00` at offset 0x10, `18 00 00 00 00 02 00 00` at offset 0x20
- **PoC:** `sony_fuzz_safe.elf` log at idx=80

### BUG #3 — Syscall 622: Kernel Panic + Controlled Output Write [HIGH]

- **Syscall:** 622 (nargs=6)
- **Trigger (crash):** `syscall(622, 0, 0, 0, 0, 0, 0)` → kernel panic
- **Trigger (survive):** `syscall(622, buf0, buf1, buf_out, buf3, buf4, buf5)` → ret=0
- **Key finding:** Kernel writes 4 bytes (`01 00 0e 80`) to **arg3** (3rd argument)
- **Output is ONLY on arg2 (0-indexed):** Confirmed by testing each arg as output
- **Crash cause:** NULL pointer dereference when arg3 (output buffer) = 0
- **Potential:** If kernel writes to arg3 address without proper copyout validation, this could be an **arbitrary kernel write primitive**
- **Status:** Deep analysis in progress — testing minimal args, input control, crash at (0,0,buf_out,0,0,0)
- **PoC:** `target622.elf`, `crash_deep.elf CIDX=2`

### BUG #4 — Syscall 522: Conditional Kernel Panic [MEDIUM-HIGH]

- **Syscall:** 522 (nargs=6)
- **Trigger (crash):** `syscall(522, 0, 0, 0, 0, 0, 0)` AND `syscall(522, 1, 0, 0, 0, 0, 0)` → crash
- **Trigger (survive):** `syscall(522, 1, 1, 1, 1, 1, 1)` → ret=14 EFAULT
- **Trigger (survive):** `syscall(522, buf_ptrs, buf2, ...)` → ret=9 EBADF
- **Pattern:** Crash when arg1≠0 AND arg2=0. Handler reads arg1, then dereferences arg2
- **Potential:** Conditional NULL deref — if arg2 is controllable pointer, could be exploitable
- **PoC:** `crash_deep.elf CIDX=1`

### BUG #5 — Syscall 55: Kernel Panic (Always Crash) [MEDIUM]

- **Syscall:** 55 (nargs=1)
- **Trigger:** `syscall(55, ANY_VALUE)` — crashes with 0, 1, buffer, valid pointers
- **Impact:** Unconditional kernel panic / DoS
- **Analysis:** Handler appears broken — dereferences uninitialized/invalid state before checking args
- **Not exploitable:** DoS only — no controlled input accepted
- **PoC:** `target55.elf`, `target55_v4.elf`

### BUG #6 — Syscall 429: Kernel Panic (Buffer Crash) [MEDIUM]

- **Syscall:** 429 (nargs=2)
- **Trigger (survive):** `syscall(429, 0, 0)` → ret=14 EFAULT
- **Trigger (crash):** `syscall(429, buffer, 0x1000)` → kernel panic
- **Pattern:** Survives NULL arg (returns EFAULT), crashes when given valid buffer
- **Deep test:** Crashes even with buffer filled with valid pointers
- **PoC:** `crash_deep.elf CIDX=0`

### BUG #7 — Syscall 661: Kernel Panic [MEDIUM]

- **Syscall:** 661 (nargs=4)
- **Trigger:** `syscall(661, 0, 0, 0, 0)` → kernel panic
- **PoC:** `sony_fuzz_safe.elf` log at idx=117

### BUG #8 — Syscall 665: Kernel Panic [MEDIUM]

- **Syscall:** 665 (nargs=2)
- **Trigger:** `syscall(665, 0, 0)` → kernel panic
- **PoC:** `sony_fuzz_safe.elf` log at idx=121

### BUG #9 — Syscall 668: Kernel Panic [MEDIUM]

- **Syscall:** 668 (nargs=2)
- **Trigger:** `syscall(668, 0, 0)` → kernel panic
- **PoC:** `sony_fuzz_safe.elf` log at idx=124

---

## Successful Syscalls (ret=0, no crash)

These accepted input without errors — worth deeper investigation for logic bugs:

```
65(buf), 404(buf), 421(buf), 431(0/buf/-1),
548(0/-1), 560(buf), 563(0), 565(0), 566(0),
585(0/buf/-1), 586(0/-1), 587(0),
596(0/buf/-1), 599(0/buf/-1), 600(buf), 602(0/buf),
606(0/buf/-1), 617(0/buf/-1), 618(0/buf/-1), 620(0/buf/-1),
622(valid_ptrs), 623(buf),
638(0/-1), 639(0/buf/-1), 640(0/buf/-1), 643(0/buf/-1),
646(buf), 657(0/-1), 670(0/buf/-1), 675(0/buf/-1)
```

---

## Exploit Chain Potential

For a NEW jailbreak exploit (independent of Relapse):

1. **KASLR Bypass:** Syscall 421 leaks kernel pointer → calculate kernel base
2. **Kernel Write:** Syscall 622 writes to arg3 address — needs validation that it bypasses copyout checks
3. **Alternative Write:** Syscall 522 conditional crash — if arg2 controllable, potential write primitive
4. **Privilege Escalation:** Once kernel R/W achieved → patch ucred (uid=0, caps=0xFF), sandbox escape, authid override
5. **ELF Loader:** Load elfldr, listen on port 9021

**Missing piece:** Confirmed arbitrary kernel write primitive. Syscall 622 is the strongest candidate.

---

## Files

| File | Description |
|------|-------------|
| `sony_fuzz_safe.c` | Main fuzzer — 133 syscalls, SKIP resume support |
| `target421.c` | Deep analysis of info leak syscall 421 |
| `target622.c` | Deep analysis of write-capable syscall 622 |
| `crash_deep.c` | Configurable crash analysis (CIDX=0-5) |
| `target55.c` | Original syscall 55 crash confirmation |
| `target55_v2.c` | Syscall 55 buffer analysis |
| `target55_v3.c` | Syscall 55 struct layout analysis |
| `target55_v4.c` | Syscall 55 raw integer test |
| `ioctl_fuzzer.c` | Device driver IOCTL fuzzer (not yet run) |
| `fuzz_receiver.py` | TCP log receiver (port 9024) |
| `Makefile` | Build all fuzzers |

### Build

```bash
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
export PS5_PAYLOAD_SDK="/Users/macbookairm1/Data/Hypervisor-ps5/ps5sdk"

make                           # build all
make target622.elf             # single target
make sony_fuzz_safe.elf SKIP=N # resume from index N
make crash_deep.elf CIDX=N     # test crash target N (0-5)
```

### Run

```bash
# PC Terminal 1:
python3 fuzz_receiver.py

# PC Terminal 2 (after Relapse exploit):
nc <PS5_IP> 9021 < <payload>.elf
```

---

## Log Files

| Log File | Content |
|----------|---------|
| `fuzz_log_20261013_202014.txt` | First fuzzer run, crashed at syscall 55 |
| `fuzz_log_20261013_202317.txt` | Target55 v1, confirmed syscall(55,0)=crash |
| `fuzz_log_20261013_203540.txt` | Safe fuzzer idx 0-19, found sc421 leak + sc429 crash |
| `fuzz_log_20261013_203825.txt` | Target421 deep analysis — 1216 bytes + kernel ptr |
| `fuzz_log_20261013_204250.txt` | Safe fuzzer idx 26-83, found sc618 leak + sc622 crash |
| `fuzz_log_20261013_204401.txt` | Safe fuzzer idx 84-117, found sc661 crash |
| `fuzz_log_20261013_204439.txt` | Safe fuzzer idx 118-121, found sc665 crash |
| `fuzz_log_20261013_204526.txt` | Safe fuzzer idx 125-132, scan complete |
| `fuzz_log_20261013_204831.txt` | Crash deep sc429 |
| `fuzz_log_20261013_204917.txt` | Crash deep sc522 — conditional crash found! |
| `fuzz_log_20261013_205009.txt` | Crash deep sc622 — survived + wrote to arg3! |
| `fuzz_log_20261013_205234.txt` | Target622 deep — confirmed arg2 is output |

---

## Next Steps

1. **Finish target622 deep analysis** — test (0,0,buf_out,0,0,0) to find minimal args
2. **Test if syscall 622 writes to kernel addresses** — if arg3 can be kernel ptr = arbitrary write
3. **Deep fuzz remaining crash syscalls** (661, 665, 668) with valid pointers
4. **Run ioctl_fuzzer.elf** — scan device drivers (72 /dev nodes, untested)
5. **If write primitive confirmed** — build full exploit chain: sc421 KASLR + sc622 write + privesc + elfldr
6. **Submit to HackerOne** — all 9 bugs with PoC payloads
