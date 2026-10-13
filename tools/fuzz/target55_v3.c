/*
 * PS5 Targeted Fuzzer — Syscall 55 v3
 *
 * FINDINGS:
 *   syscall(55, 0)         = kernel panic (NULL deref)
 *   syscall(55, buf_zeros) = kernel panic (secondary NULL deref)
 *
 * THEORY: kernel reads a pointer FROM the buffer and dereferences it.
 * This version tries to find the struct layout by:
 *   1. Filling buffer with valid self-pointer → should survive
 *   2. Testing which qword offset is the pointer field
 *   3. If we find the layout, test controlled read/write
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <ps5/kernel.h>

#define PC_IP       "192.168.100.24"
#define PC_PORT     9024
#define TARGET      55

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

static int log_fd = -1;
static sigjmp_buf fuzz_jmp;
static volatile int caught_signal = 0;

static void notify(const char *fmt, ...) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static void log_flush(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (log_fd >= 0 && n > 0) {
        write(log_fd, buf, n);
        fsync(log_fd);
    }
    printf("%s", buf);
    fflush(stdout);
}

static void hexdump(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        if (i > 0 && (i % 16) == 0) log_flush("\n    ");
        log_flush("%02x ", data[i]);
    }
    log_flush("\n");
}

static void sig_handler(int sig) {
    caught_signal = sig;
    siglongjmp(fuzz_jmp, 1);
}

static int connect_logger(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PC_PORT);
    inet_pton(AF_INET, PC_IP, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    notify("Target55 v3: struct layout analysis");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== PS5 Syscall 55 v3: Struct Layout ===\n");
    log_flush("KNOWN: zeroed buffer = crash (secondary NULL deref)\n");
    log_flush("THEORY: kernel reads pointer from struct\n\n");

    /*
     * Allocate a large mmap region so we have a known valid address range.
     * Fill struct fields with pointer to a secondary buffer.
     */
    size_t region_sz = 0x10000;
    uint8_t *region = mmap(NULL, region_sz, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        log_flush("[!] mmap failed\n");
        return 1;
    }
    memset(region, 0, region_sz);

    uint8_t *input = region;              /* first 4096 = input struct */
    uint8_t *secondary = region + 0x1000; /* secondary buffer the pointer points to */
    uint8_t *tertiary = region + 0x2000;  /* third level if needed */

    /* Fill secondary with recognizable pattern */
    memset(secondary, 0x42, 0x1000);
    /* Fill tertiary with valid pointers back to region */
    for (int i = 0; i < 0x1000; i += 8) {
        *(uint64_t *)(tertiary + i) = (uint64_t)(uintptr_t)secondary;
    }

    /*
     * Test 1: Fill ALL qwords in the input with a valid pointer
     * If the kernel reads ANY field as a pointer, this should survive
     */
    log_flush("--- Test 1: All qwords = valid pointer ---\n\n");

    for (int i = 0; i < 256; i += 8) {
        *(uint64_t *)(input + i) = (uint64_t)(uintptr_t)secondary;
    }

    log_flush("[1] BEFORE syscall(%d, buf_all_ptrs)\n", TARGET);
    log_flush("    buf[0..7]  = %p (-> secondary)\n", (void *)secondary);

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[1] SIGNAL %d! Even all-valid-ptrs crashes\n", caught_signal);
        log_flush("    Theory: kernel expects specific struct, not just pointer\n\n");
    } else {
        long ret = syscall(TARGET, input);
        int err = errno;
        log_flush("[1] ret=%ld errno=%d (%s)\n", ret, err, strerror(err));
        log_flush("[1] *** SURVIVED! Kernel accepted valid pointer struct ***\n");

        /* Check if secondary buffer was modified */
        int changed = 0;
        for (int i = 0; i < 0x1000; i++) {
            if (secondary[i] != 0x42) changed++;
        }
        if (changed > 0) {
            log_flush("[1] *** KERNEL MODIFIED SECONDARY BUFFER: %d bytes ***\n", changed);
            log_flush("    ");
            hexdump(secondary, 128);
        }

        /* Check if input was modified */
        int input_changed = 0;
        for (int i = 0; i < 256; i++) {
            uint8_t *p = input + i;
            uint8_t expected = ((uint8_t *)&secondary)[i % 8];
            if (*p != expected) input_changed++;
        }
        if (input_changed > 0) {
            log_flush("[1] *** KERNEL MODIFIED INPUT BUFFER: %d bytes ***\n", input_changed);
            log_flush("    ");
            hexdump(input, 128);
        }
    }

    usleep(200000);

    /*
     * Test 2: Find which qword is the pointer field
     * Set one qword at a time to valid pointer, rest to 1 (non-zero, non-ptr)
     * The one that crashes when set to 1 but survives with ptr = the pointer field
     */
    log_flush("\n--- Test 2: Isolate pointer field ---\n");
    log_flush("    Strategy: set each qword to valid ptr, others to 0x1\n\n");

    for (int off = 0; off < 64; off += 8) {
        /* Reset input: fill with 0x01 (non-zero, non-pointer) */
        memset(input, 0, 256);
        for (int i = 0; i < 256; i += 8) {
            *(uint64_t *)(input + i) = 1;
        }

        /* Set THIS qword to valid pointer */
        *(uint64_t *)(input + off) = (uint64_t)(uintptr_t)secondary;

        /* Reset secondary */
        memset(secondary, 0x42, 0x1000);

        log_flush("[2.%d] BEFORE syscall(%d, {off%d=ptr, rest=1})\n",
                  off/8, TARGET, off);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[2.%d] SIGNAL %d! off=%d is NOT enough alone\n",
                      off/8, caught_signal, off);
        } else {
            long ret = syscall(TARGET, input);
            int err = errno;
            log_flush("[2.%d] ret=%ld errno=%d (%s)\n", off/8, ret, err, strerror(err));
            log_flush("[2.%d] *** off=%d MIGHT be the pointer field ***\n", off/8, off);

            int changed = 0;
            for (int i = 0; i < 0x1000; i++) {
                if (secondary[i] != 0x42) changed++;
            }
            if (changed > 0) {
                log_flush("[2.%d] *** SECONDARY MODIFIED: %d bytes ***\n", off/8, changed);
                log_flush("    ");
                hexdump(secondary, 64);
            }
        }

        usleep(200000);
    }

    /*
     * Test 3: Two-pointer struct
     * Maybe the struct has TWO pointer fields. Try pairs.
     */
    log_flush("\n--- Test 3: Two-pointer combinations ---\n\n");

    int ptr_offsets[][2] = {
        {0, 8}, {0, 16}, {0, 24}, {8, 16}, {8, 24}, {16, 24},
        {0, 32}, {8, 32}, {16, 32}, {24, 32}
    };
    int num_pairs = sizeof(ptr_offsets) / sizeof(ptr_offsets[0]);

    for (int pi = 0; pi < num_pairs; pi++) {
        int o1 = ptr_offsets[pi][0];
        int o2 = ptr_offsets[pi][1];

        memset(input, 0, 256);
        for (int i = 0; i < 256; i += 8) {
            *(uint64_t *)(input + i) = 1;
        }

        *(uint64_t *)(input + o1) = (uint64_t)(uintptr_t)secondary;
        *(uint64_t *)(input + o2) = (uint64_t)(uintptr_t)tertiary;

        memset(secondary, 0x42, 0x1000);

        log_flush("[3.%d] BEFORE syscall(%d, {off%d=sec, off%d=ter, rest=1})\n",
                  pi, TARGET, o1, o2);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[3.%d] SIGNAL %d!\n", pi, caught_signal);
        } else {
            long ret = syscall(TARGET, input);
            int err = errno;
            log_flush("[3.%d] ret=%ld errno=%d (%s)\n", pi, ret, err, strerror(err));
            log_flush("[3.%d] *** SURVIVED with off%d+off%d ***\n", pi, o1, o2);

            int changed = 0;
            for (int i = 0; i < 0x1000; i++) {
                if (secondary[i] != 0x42) changed++;
            }
            if (changed > 0) {
                log_flush("[3.%d] *** DATA WRITTEN TO SECONDARY: %d bytes ***\n", pi, changed);
                log_flush("    ");
                hexdump(secondary, 128);
            }
        }

        usleep(200000);
    }

    /*
     * Test 4: Integer + pointer combos
     * Maybe first field is a command/size, second is pointer
     */
    log_flush("\n--- Test 4: cmd + pointer combos ---\n\n");

    uint32_t cmds[] = {0, 1, 2, 3, 4, 5, 8, 16, 32, 64, 128, 256};
    int num_cmds = sizeof(cmds) / sizeof(cmds[0]);

    for (int ci = 0; ci < num_cmds; ci++) {
        memset(input, 0, 256);

        /* Layout: u32 cmd at +0, ptr at +8 */
        *(uint32_t *)(input + 0) = cmds[ci];
        *(uint64_t *)(input + 8) = (uint64_t)(uintptr_t)secondary;
        /* Also fill +16 with another valid ptr just in case */
        *(uint64_t *)(input + 16) = (uint64_t)(uintptr_t)tertiary;
        *(uint64_t *)(input + 24) = (uint64_t)(uintptr_t)secondary;

        memset(secondary, 0x42, 0x1000);

        log_flush("[4.%02d] BEFORE syscall(%d, {cmd=%u, ptr@8, ptr@16, ptr@24})\n",
                  ci, TARGET, cmds[ci]);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[4.%02d] SIGNAL %d on cmd=%u\n", ci, caught_signal, cmds[ci]);
        } else {
            long ret = syscall(TARGET, input);
            int err = errno;
            log_flush("[4.%02d] ret=%ld errno=%d (%s)\n", ci, ret, err, strerror(err));

            if (ret == 0) {
                log_flush("[4.%02d] *** SUCCESS ret=0 on cmd=%u! ***\n", ci, cmds[ci]);

                /* Check ALL regions for modifications */
                int sec_changed = 0, ter_changed = 0, in_changed = 0;
                for (int i = 0; i < 0x1000; i++) {
                    if (secondary[i] != 0x42) sec_changed++;
                }
                for (int i = 0; i < 0x1000; i += 8) {
                    if (*(uint64_t *)(tertiary + i) != (uint64_t)(uintptr_t)secondary)
                        ter_changed++;
                }
                log_flush("    secondary: %d bytes changed\n", sec_changed);
                log_flush("    tertiary: %d qwords changed\n", ter_changed);

                if (sec_changed > 0) {
                    log_flush("    secondary data:\n    ");
                    hexdump(secondary, 128);
                }

                /* Dump input to see if kernel wrote back */
                log_flush("    input dump:\n    ");
                hexdump(input, 64);
            }
        }

        usleep(200000);
    }

    /*
     * Test 5: Maybe first qword IS the pointer (no command field)
     * And it needs to point to a struct with more pointers
     */
    log_flush("\n--- Test 5: Nested struct (ptr -> struct with ptrs) ---\n\n");

    /* secondary contains struct with valid pointers */
    memset(secondary, 0, 0x1000);
    for (int i = 0; i < 256; i += 8) {
        *(uint64_t *)(secondary + i) = (uint64_t)(uintptr_t)tertiary;
    }

    /* input[0] = ptr to secondary struct */
    memset(input, 0, 256);
    *(uint64_t *)(input + 0) = (uint64_t)(uintptr_t)secondary;

    log_flush("[5.1] BEFORE syscall(%d, {[0]=ptr_to_struct})\n", TARGET);

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[5.1] SIGNAL %d!\n", caught_signal);
    } else {
        long ret = syscall(TARGET, input);
        int err = errno;
        log_flush("[5.1] ret=%ld errno=%d (%s)\n", ret, err, strerror(err));
        if (ret == 0) {
            log_flush("[5.1] *** SURVIVED with nested struct ***\n");
            log_flush("    input: "); hexdump(input, 64);
            log_flush("    secondary: "); hexdump(secondary, 64);
        }
    }

    usleep(200000);

    /* Test 5.2: qword[0] = small int, qword[1] = ptr to secondary struct */
    memset(input, 0, 256);
    *(uint64_t *)(input + 0) = 1;
    *(uint64_t *)(input + 8) = (uint64_t)(uintptr_t)secondary;

    log_flush("[5.2] BEFORE syscall(%d, {[0]=1, [8]=ptr_to_struct})\n", TARGET);

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[5.2] SIGNAL %d!\n", caught_signal);
    } else {
        long ret = syscall(TARGET, input);
        int err = errno;
        log_flush("[5.2] ret=%ld errno=%d (%s)\n", ret, err, strerror(err));
    }

    /*
     * Test 6: Alternative - maybe the arg is NOT a pointer at all
     * Maybe it's a file descriptor or small ID
     * v2 crashed because buf address happened to be treated as bad fd?
     * Re-test with actual fd values
     */
    log_flush("\n--- Test 6: File descriptor / ID values ---\n\n");

    /* Open some real fds first */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int pair[2];
    int has_pair = (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);

    int fd_vals[] = {0, 1, 2, sock, -1};
    if (has_pair) {
        fd_vals[3] = pair[0];
    }
    int num_fds = 5;

    for (int fi = 0; fi < num_fds; fi++) {
        int fd = fd_vals[fi];
        if (fd < 0 && fi != 4) continue;

        log_flush("[6.%d] BEFORE syscall(%d, fd=%d)\n", fi, TARGET, fd);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[6.%d] SIGNAL %d on fd=%d\n", fi, caught_signal, fd);
        } else {
            long ret = syscall(TARGET, (uint64_t)(long)fd);
            int err = errno;
            log_flush("[6.%d] ret=%ld errno=%d (%s)\n", fi, ret, err, strerror(err));
            if (ret == 0) {
                log_flush("[6.%d] *** SUCCESS on fd=%d! ***\n", fi, fd);
            }
        }

        usleep(100000);
    }

    /* Cleanup */
    if (sock >= 0) close(sock);
    if (has_pair) { close(pair[0]); close(pair[1]); }

    /*
     * Test 7: Direct integer values that v2 missed
     * Small positive values 1-20 (v2 tested buffer pointers, not raw ints)
     * NOTE: v2 crashed at test 1.1 (buffer), so tests with raw ints
     *       may actually work if the arg isn't a pointer at all
     */
    log_flush("\n--- Test 7: Raw integer args 1-20 ---\n\n");

    for (int v = 1; v <= 20; v++) {
        log_flush("[7.%02d] BEFORE syscall(%d, %d)\n", v, TARGET, v);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[7.%02d] SIGNAL %d on val=%d\n", v, caught_signal, v);
            continue;
        }

        long ret = syscall(TARGET, (uint64_t)v);
        int err = errno;
        log_flush("[7.%02d] ret=%ld errno=%d (%s)\n", v, ret, err, strerror(err));

        if (ret == 0) {
            log_flush("[7.%02d] *** SUCCESS ret=0 on val=%d! ***\n", v, v);
            notify("Syscall55: val=%d returned 0!", v);
        }

        usleep(100000);
    }

    log_flush("\n=== v3 Analysis complete ===\n");
    log_flush("Key findings:\n");
    log_flush("  - If Test 1 survived: struct needs valid pointers\n");
    log_flush("  - If Test 2 found the field: we know the struct layout\n");
    log_flush("  - If Test 4 cmd worked: it's a command dispatcher\n");
    log_flush("  - If Test 6/7 worked: arg is fd/int, not pointer\n");

    notify("Target55 v3: analysis complete");

    munmap(region, region_sz);
    if (log_fd >= 0) close(log_fd);
    return 0;
}
