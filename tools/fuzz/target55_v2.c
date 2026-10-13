/*
 * PS5 Targeted Fuzzer — Syscall 55 v2
 *
 * CONFIRMED: syscall(55, 0) = kernel panic (NULL deref)
 *
 * This version:
 *  - Skips 0/NULL (known crash)
 *  - Tests with valid buffer pointers to understand what the syscall does
 *  - Checks if kernel writes data back (info leak?)
 *  - Tries different struct layouts
 *  - Tests if callable before jailbreak (pre-escalation)
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
    notify("Target55 v2: analyzing syscall 55");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== PS5 Syscall 55 Deep Analysis ===\n");
    log_flush("KNOWN: syscall(55, 0) = kernel panic (NULL deref)\n");
    log_flush("GOAL: understand what this syscall does\n\n");

    /*
     * Test 1: Valid buffer, all zeros
     * If syscall expects a struct pointer, this tests with empty struct
     */
    log_flush("--- Test 1: Zeroed buffer (various sizes) ---\n\n");

    int sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024, 4096};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int si = 0; si < num_sizes; si++) {
        int sz = sizes[si];
        uint8_t *buf = calloc(1, sz);
        if (!buf) continue;

        uint8_t *before = malloc(sz);
        memcpy(before, buf, sz);

        log_flush("[1.%d] BEFORE syscall(%d, buf[%d]=zeros)\n", si+1, TARGET, sz);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[1.%d] SIGNAL %d!\n", si+1, caught_signal);
            free(buf);
            free(before);
            continue;
        }

        long ret = syscall(TARGET, buf);
        int err = errno;

        log_flush("[1.%d] ret=%ld errno=%d (%s)\n", si+1, ret, err, strerror(err));

        /* Check if kernel wrote anything to our buffer */
        int changed = 0;
        for (int i = 0; i < sz; i++) {
            if (buf[i] != before[i]) changed++;
        }

        if (changed > 0) {
            log_flush("[1.%d] *** KERNEL WROTE %d BYTES TO BUFFER! ***\n", si+1, changed);
            log_flush("    ");
            hexdump(buf, sz < 128 ? sz : 128);
        }

        free(buf);
        free(before);
        usleep(50000);
    }

    /*
     * Test 2: Buffer with various first-qword values
     * Many Sony syscalls take a struct where first field = command/subcommand
     */
    log_flush("\n--- Test 2: First qword as command ID ---\n\n");

    for (uint64_t cmd = 0; cmd <= 32; cmd++) {
        uint8_t buf[256];
        memset(buf, 0, sizeof(buf));
        *(uint64_t *)buf = cmd;

        log_flush("[2.%02lu] BEFORE syscall(%d, {cmd=%lu, ...})\n",
                  (unsigned long)cmd, TARGET, (unsigned long)cmd);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[2.%02lu] SIGNAL %d!\n", (unsigned long)cmd, caught_signal);
            continue;
        }

        long ret = syscall(TARGET, buf);
        int err = errno;

        log_flush("[2.%02lu] ret=%ld errno=%d (%s)\n",
                  (unsigned long)cmd, ret, err, strerror(err));

        /* Check output */
        int nonzero = 0;
        for (int i = 8; i < 256; i++) {
            if (buf[i] != 0) nonzero++;
        }
        if (nonzero > 0) {
            log_flush("[2.%02lu] *** OUTPUT: %d non-zero bytes ***\n",
                      (unsigned long)cmd, nonzero);
            log_flush("    ");
            hexdump(buf, 128);
        }

        usleep(50000);
    }

    /*
     * Test 3: Buffer with first dword as command (32-bit)
     * Some ioctls use 32-bit command codes
     */
    log_flush("\n--- Test 3: First dword as 32-bit cmd ---\n\n");

    uint32_t cmds32[] = {0, 1, 2, 3, 4, 5, 10, 100, 0xFF, 0xFFFF, 0x80000000, 0xFFFFFFFF};
    int num_cmds32 = sizeof(cmds32) / sizeof(cmds32[0]);

    for (int ci = 0; ci < num_cmds32; ci++) {
        uint8_t buf[256];
        memset(buf, 0, sizeof(buf));
        *(uint32_t *)buf = cmds32[ci];

        log_flush("[3.%02d] BEFORE syscall(%d, {u32_cmd=0x%x, ...})\n",
                  ci+1, TARGET, cmds32[ci]);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[3.%02d] SIGNAL %d!\n", ci+1, caught_signal);
            continue;
        }

        long ret = syscall(TARGET, buf);
        int err = errno;

        log_flush("[3.%02d] ret=%ld errno=%d (%s)\n", ci+1, ret, err, strerror(err));

        int nonzero = 0;
        for (int i = 4; i < 256; i++) {
            if (buf[i] != 0) nonzero++;
        }
        if (nonzero > 0) {
            log_flush("[3.%02d] *** OUTPUT: %d bytes ***\n", ci+1, nonzero);
            log_flush("    ");
            hexdump(buf, 128);
        }

        usleep(50000);
    }

    /*
     * Test 4: Two-arg test (maybe it takes 2 args despite sysent saying 1)
     * Some FreeBSD syscalls have nargs=1 but actually use more via copyin
     */
    log_flush("\n--- Test 4: Multi-arg variations ---\n\n");

    uint8_t buf_a[256], buf_b[256];
    memset(buf_a, 0, sizeof(buf_a));
    memset(buf_b, 0, sizeof(buf_b));

    log_flush("[4.1] BEFORE syscall(%d, buf_a, buf_b)\n", TARGET);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[4.1] SIGNAL %d!\n", caught_signal);
    } else {
        long ret = syscall(TARGET, buf_a, buf_b);
        log_flush("[4.1] ret=%ld errno=%d (%s)\n", ret, errno, strerror(errno));
    }

    log_flush("[4.2] BEFORE syscall(%d, buf_a, 0x1000)\n", TARGET);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[4.2] SIGNAL %d!\n", caught_signal);
    } else {
        long ret = syscall(TARGET, buf_a, 0x1000);
        log_flush("[4.2] ret=%ld errno=%d (%s)\n", ret, errno, strerror(errno));
    }

    log_flush("[4.3] BEFORE syscall(%d, buf_a, 256, buf_b)\n", TARGET);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[4.3] SIGNAL %d!\n", caught_signal);
    } else {
        long ret = syscall(TARGET, buf_a, 256, buf_b);
        log_flush("[4.3] ret=%ld errno=%d (%s)\n", ret, errno, strerror(errno));
    }

    /*
     * Test 5: mmap'd page (in case kernel expects page-aligned or mapped memory)
     */
    log_flush("\n--- Test 5: mmap'd page ---\n\n");

    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page != MAP_FAILED) {
        memset(page, 0, 4096);

        log_flush("[5.1] BEFORE syscall(%d, mmap_page=%p)\n", TARGET, page);
        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[5.1] SIGNAL %d!\n", caught_signal);
        } else {
            long ret = syscall(TARGET, page);
            int err = errno;
            log_flush("[5.1] ret=%ld errno=%d (%s)\n", ret, err, strerror(err));

            int changed = 0;
            uint8_t *p = (uint8_t *)page;
            for (int i = 0; i < 4096; i++) {
                if (p[i] != 0) changed++;
            }
            if (changed > 0) {
                log_flush("[5.1] *** KERNEL WROTE %d BYTES TO MMAP PAGE! ***\n", changed);
                log_flush("    ");
                hexdump(p, 256);
            }
        }

        munmap(page, 4096);
    }

    /*
     * Test 6: Non-zero integer args (skip 0 which crashes)
     */
    log_flush("\n--- Test 6: Non-zero integer args ---\n\n");

    uint64_t int_vals[] = {1, 2, 3, 4, 8, 16, 0xFF, 0x1000, 0xFFFF,
                           0x10000, 0x7FFFFFFF, 0xFFFFFFFF, 0x100000000ULL};
    int num_int_vals = sizeof(int_vals) / sizeof(int_vals[0]);

    for (int i = 0; i < num_int_vals; i++) {
        log_flush("[6.%02d] BEFORE syscall(%d, 0x%lx)\n",
                  i+1, TARGET, (unsigned long)int_vals[i]);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[6.%02d] SIGNAL %d! *** CRASH on 0x%lx ***\n",
                      i+1, caught_signal, (unsigned long)int_vals[i]);
            notify("Syscall55: CRASH on 0x%lx!", (unsigned long)int_vals[i]);
            continue;
        }

        long ret = syscall(TARGET, int_vals[i]);
        int err = errno;
        log_flush("[6.%02d] ret=%ld errno=%d (%s)\n",
                  i+1, ret, err, strerror(err));

        usleep(50000);
    }

    log_flush("\n=== Analysis complete ===\n");
    log_flush("Summary:\n");
    log_flush("  - syscall(55, 0) = KERNEL PANIC (confirmed)\n");
    log_flush("  - See above for behavior with valid inputs\n");
    log_flush("  - Any SIGNAL or output data = further investigation needed\n");

    notify("Target55 v2: analysis complete");

    if (log_fd >= 0) close(log_fd);
    return 0;
}
