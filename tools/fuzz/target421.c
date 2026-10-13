/*
 * PS5 Targeted Fuzzer — Syscall 421
 *
 * CONFIRMED: syscall(421, buf) = SUCCESS, writes 139 bytes to buffer
 * This is a potential KERNEL INFO LEAK.
 *
 * Goals:
 *   1. Dump ALL 139+ bytes (previous fuzzer only showed first 64)
 *   2. Look for kernel pointers (0xffffffff... pattern)
 *   3. Test different buffer sizes to find max leak
 *   4. Call multiple times to see if data changes (randomized?)
 *   5. Test with different struct layouts
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
#define TARGET      421

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
    char buf[4096];
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

static void hexdump_full(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        if (i > 0 && (i % 16) == 0) log_flush("\n");
        if ((i % 16) == 0) log_flush("  %04x: ", i);
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
    notify("Target421: info leak analysis");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== PS5 Syscall 421 — Info Leak Analysis ===\n");
    log_flush("CONFIRMED: syscall(421, buf) writes 139 bytes\n");
    log_flush("nargs=1, takes pointer to output buffer\n\n");

    /*
     * Test 1: Full dump — large buffer, complete hexdump
     */
    log_flush("--- Test 1: Full data dump (4KB buffer) ---\n\n");

    uint8_t *buf = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        log_flush("[!] mmap failed\n");
        return 1;
    }

    memset(buf, 0xCC, 0x2000); /* fill with 0xCC sentinel */

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[1] SIGNAL %d!\n", caught_signal);
        goto test2;
    }

    long ret = syscall(TARGET, buf);
    int err = errno;
    log_flush("[1] ret=%ld errno=%d (%s)\n", ret, err, strerror(err));

    if (ret == 0) {
        /* Find exact size of data written (where 0xCC sentinel starts) */
        int data_end = 0;
        for (int i = 0; i < 0x2000; i++) {
            if (buf[i] != 0xCC) data_end = i + 1;
        }
        log_flush("[1] Kernel wrote %d bytes (last non-0xCC at offset %d)\n",
                  data_end, data_end - 1);

        /* Full hexdump of ALL written data */
        log_flush("[1] FULL HEXDUMP:\n");
        hexdump_full(buf, data_end < 1024 ? data_end : 1024);

        /* Look for potential kernel pointers */
        log_flush("\n[1] Scanning for kernel pointers (0xffffffff...):\n");
        for (int i = 0; i <= data_end - 8; i += 8) {
            uint64_t val = *(uint64_t *)(buf + i);
            if ((val & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                log_flush("  [KPTR?] offset 0x%03x: 0x%016lx\n",
                          i, (unsigned long)val);
            }
            /* Also check for userspace-range pointers */
            if (val > 0x100000 && val < 0x800000000000ULL) {
                log_flush("  [UPTR?] offset 0x%03x: 0x%016lx\n",
                          i, (unsigned long)val);
            }
        }

        /* Look for ASCII strings */
        log_flush("\n[1] Scanning for strings:\n");
        int str_start = -1;
        for (int i = 0; i < data_end; i++) {
            if (buf[i] >= 0x20 && buf[i] < 0x7F) {
                if (str_start < 0) str_start = i;
            } else {
                if (str_start >= 0 && (i - str_start) >= 4) {
                    log_flush("  [STR] offset 0x%03x: \"", str_start);
                    for (int j = str_start; j < i; j++)
                        log_flush("%c", buf[j]);
                    log_flush("\"\n");
                }
                str_start = -1;
            }
        }
    }

test2:
    /*
     * Test 2: Call multiple times — does the data change?
     * If it changes, it might contain timestamps, pids, or random values
     */
    log_flush("\n--- Test 2: Stability check (5 calls) ---\n\n");

    uint8_t copies[5][512];

    for (int run = 0; run < 5; run++) {
        memset(buf, 0, 512);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[2.%d] SIGNAL %d!\n", run+1, caught_signal);
            continue;
        }

        ret = syscall(TARGET, buf);
        err = errno;

        if (ret == 0) {
            memcpy(copies[run], buf, 512);
            log_flush("[2.%d] ret=0, first 8 qwords:\n  ", run+1);
            for (int i = 0; i < 64; i += 8) {
                log_flush("%016lx ", *(unsigned long *)(buf + i));
            }
            log_flush("\n");
        } else {
            log_flush("[2.%d] ret=%ld errno=%d\n", run+1, ret, err);
            memset(copies[run], 0xFF, 512);
        }

        usleep(500000);
    }

    /* Compare runs to find changing fields */
    log_flush("\n[2] Comparing runs — changing offsets:\n");
    for (int off = 0; off < 256; off += 8) {
        uint64_t v0 = *(uint64_t *)&copies[0][off];
        int differs = 0;
        for (int r = 1; r < 5; r++) {
            uint64_t vr = *(uint64_t *)&copies[r][off];
            if (vr != v0) differs++;
        }
        if (differs > 0) {
            log_flush("  offset 0x%03x CHANGES: ", off);
            for (int r = 0; r < 5; r++) {
                log_flush("%016lx ", *(unsigned long *)&copies[r][off]);
            }
            log_flush("\n");
        }
    }

    /*
     * Test 3: Test with arg2 = different sizes
     * Maybe nargs=1 but it secretly reads arg2 as buffer size
     */
    log_flush("\n--- Test 3: With size argument ---\n\n");

    int sizes[] = {0, 8, 64, 128, 256, 512, 1024, 4096};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int si = 0; si < num_sizes; si++) {
        memset(buf, 0xCC, 0x2000);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[3.%d] SIGNAL %d on size=%d\n", si+1, caught_signal, sizes[si]);
            continue;
        }

        ret = syscall(TARGET, buf, sizes[si]);
        err = errno;

        int written = 0;
        for (int i = 0; i < 0x2000; i++) {
            if (buf[i] != 0xCC) written = i + 1;
        }

        log_flush("[3.%d] size=%d ret=%ld errno=%d written=%d\n",
                  si+1, sizes[si], ret, err, written);
    }

    /*
     * Test 4: Buffer with pre-filled command IDs
     * Maybe first field selects what info to return
     */
    log_flush("\n--- Test 4: Command ID in buffer ---\n\n");

    for (uint32_t cmd = 0; cmd <= 16; cmd++) {
        memset(buf, 0xCC, 0x2000);
        *(uint32_t *)buf = cmd;

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[4.%02u] SIGNAL %d on cmd=%u\n", cmd, caught_signal, cmd);
            continue;
        }

        ret = syscall(TARGET, buf);
        err = errno;

        int written = 0;
        for (int i = 4; i < 0x2000; i++) {
            if (buf[i] != 0xCC) written++;
        }

        log_flush("[4.%02u] cmd=%u ret=%ld errno=%d extra_bytes=%d\n",
                  cmd, cmd, ret, err, written);

        if (ret == 0 && written > 0) {
            log_flush("[4.%02u] DATA with cmd=%u:\n", cmd, cmd);
            int end = 0;
            for (int i = 0; i < 0x2000; i++) {
                if (buf[i] != 0xCC) end = i + 1;
            }
            hexdump_full(buf, end < 256 ? end : 256);
        }

        usleep(200000);
    }

    log_flush("\n=== Syscall 421 analysis complete ===\n");
    notify("Target421: done");

    munmap(buf, 0x2000);
    if (log_fd >= 0) close(log_fd);
    return 0;
}
