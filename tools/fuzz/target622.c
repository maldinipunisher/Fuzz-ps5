/*
 * PS5 Targeted Fuzzer — Syscall 622
 *
 * CONFIRMED:
 *   (0,0,0,0,0,0) = CRASH (NULL write to arg3)
 *   (buf_ptrs, buf2, buf3, ...) = SURVIVED, kernel wrote to buf3!
 *   Output: 01 00 0e 80 at buf3
 *
 * GOAL: Map all 6 args, find if we can control:
 *   1. WHAT the kernel writes (controlled write value)
 *   2. WHERE it writes (arbitrary address → kernel write primitive)
 *
 * nargs=6 from sysent
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
#define SC          622

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

/* Helper: call sc622 and check all buffers */
static int do_test(const char *label,
                   uint64_t a1, uint64_t a2, uint64_t a3,
                   uint64_t a4, uint64_t a5, uint64_t a6,
                   uint8_t *check_buf, int check_sz, uint8_t sentinel) {
    log_flush("[*] BEFORE %s\n", label);

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[!] SIGNAL %d on %s\n", caught_signal, label);
        return -1;
    }

    long ret = syscall(SC, a1, a2, a3, a4, a5, a6);
    int err = errno;
    log_flush("    ret=%ld errno=%d (%s)\n", ret, err, strerror(err));

    if (check_buf && check_sz > 0) {
        int changed = 0;
        int first = -1, last = -1;
        for (int i = 0; i < check_sz; i++) {
            if (check_buf[i] != sentinel) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }
        if (changed > 0) {
            log_flush("    OUTPUT: %d bytes changed (off %d-%d)\n",
                      changed, first, last);
            log_flush("    ");
            hexdump(check_buf + (first & ~0xF),
                    (last - (first & ~0xF) + 16 < 256) ?
                    last - (first & ~0xF) + 16 : 256);
        }
    }

    return (int)ret;
}

int main(void) {
    notify("Target622: deep analysis");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== PS5 Syscall 622 Deep Analysis ===\n");
    log_flush("CONFIRMED: (buf_ptrs, buf2, buf3, ...) → ret=0, wrote to buf3\n");
    log_flush("Output was: 01 00 0e 80\n\n");

    /* Allocate 8 separate buffers */
    size_t bsz = 0x1000;
    uint8_t *b[8];
    for (int i = 0; i < 8; i++) {
        b[i] = mmap(NULL, bsz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (b[i] == MAP_FAILED) {
            log_flush("[!] mmap %d failed\n", i);
            return 1;
        }
    }

    int test = 0;

    /*
     * Test 1: Reproduce original finding
     * All bufs zeroed, arg1=b0, arg3=b2 (output)
     */
    log_flush("--- Test 1: Reproduce (zeroed bufs) ---\n\n");

    for (int i = 0; i < 8; i++) memset(b[i], 0, bsz);
    memset(b[2], 0xCC, bsz); /* sentinel on output buf */

    test++;
    do_test("sc622(b0, b1, b2_out, b3, b4, b5)",
            (uint64_t)(uintptr_t)b[0], (uint64_t)(uintptr_t)b[1],
            (uint64_t)(uintptr_t)b[2], (uint64_t)(uintptr_t)b[3],
            (uint64_t)(uintptr_t)b[4], (uint64_t)(uintptr_t)b[5],
            b[2], bsz, 0xCC);

    usleep(200000);

    /*
     * Test 2: Which arg is the output? Test each.
     */
    log_flush("\n--- Test 2: Find all output args ---\n\n");

    for (int out = 0; out < 6; out++) {
        for (int i = 0; i < 6; i++) memset(b[i], 0, bsz);
        memset(b[out], 0xCC, bsz); /* sentinel on test buf */

        char label[128];
        snprintf(label, sizeof(label), "output=arg%d", out);
        test++;
        do_test(label,
                (uint64_t)(uintptr_t)b[0], (uint64_t)(uintptr_t)b[1],
                (uint64_t)(uintptr_t)b[2], (uint64_t)(uintptr_t)b[3],
                (uint64_t)(uintptr_t)b[4], (uint64_t)(uintptr_t)b[5],
                b[out], bsz, 0xCC);

        usleep(100000);
    }

    /*
     * Test 3: Minimal args — which args are required?
     * Set each arg to buf one at a time, others to 0
     */
    log_flush("\n--- Test 3: Minimal required args ---\n\n");

    /* First: just arg3 = buf (output only) */
    memset(b[0], 0xCC, bsz);
    test++;
    do_test("sc622(0, 0, buf_out, 0, 0, 0)",
            0, 0,
            (uint64_t)(uintptr_t)b[0], 0, 0, 0,
            b[0], bsz, 0xCC);
    usleep(200000);

    /* arg1=buf, arg3=buf_out */
    memset(b[0], 0, bsz);
    memset(b[1], 0xCC, bsz);
    test++;
    do_test("sc622(buf, 0, buf_out, 0, 0, 0)",
            (uint64_t)(uintptr_t)b[0], 0,
            (uint64_t)(uintptr_t)b[1], 0, 0, 0,
            b[1], bsz, 0xCC);
    usleep(200000);

    /* arg1=buf, arg2=size, arg3=buf_out */
    memset(b[0], 0, bsz);
    memset(b[1], 0xCC, bsz);
    test++;
    do_test("sc622(buf, 256, buf_out, 0, 0, 0)",
            (uint64_t)(uintptr_t)b[0], 256,
            (uint64_t)(uintptr_t)b[1], 0, 0, 0,
            b[1], bsz, 0xCC);
    usleep(200000);

    /* arg1=buf, arg2=size, arg3=buf_out, arg4=out_size */
    memset(b[0], 0, bsz);
    memset(b[1], 0xCC, bsz);
    test++;
    do_test("sc622(buf, 256, buf_out, 4096, 0, 0)",
            (uint64_t)(uintptr_t)b[0], 256,
            (uint64_t)(uintptr_t)b[1], 4096, 0, 0,
            b[1], bsz, 0xCC);
    usleep(200000);

    /*
     * Test 4: Control input data, see if output changes
     * Change buf[0] struct content
     */
    log_flush("\n--- Test 4: Vary input, check output ---\n\n");

    for (uint32_t cmd = 0; cmd <= 8; cmd++) {
        for (int i = 0; i < 6; i++) memset(b[i], 0, bsz);
        *(uint32_t *)(b[0]) = cmd;
        memset(b[2], 0xCC, bsz);

        char label[128];
        snprintf(label, sizeof(label), "cmd=%u in b0, all bufs valid", cmd);
        test++;
        int ret = do_test(label,
                (uint64_t)(uintptr_t)b[0], (uint64_t)(uintptr_t)b[1],
                (uint64_t)(uintptr_t)b[2], (uint64_t)(uintptr_t)b[3],
                (uint64_t)(uintptr_t)b[4], (uint64_t)(uintptr_t)b[5],
                b[2], bsz, 0xCC);

        /* Also check b0 for modifications */
        if (ret == 0 && *(uint32_t *)(b[0]) != cmd) {
            log_flush("    b0 input CHANGED: was %u now %u\n",
                      cmd, *(uint32_t *)(b[0]));
        }

        usleep(100000);
    }

    /*
     * Test 5: Use arg2 as various integer values
     * Maybe arg2 is a size, cmd, or fd
     */
    log_flush("\n--- Test 5: arg2 as size/cmd ---\n\n");

    uint64_t arg2_vals[] = {0, 1, 4, 8, 16, 32, 64, 128, 256, 0x1000};
    int n_arg2 = sizeof(arg2_vals) / sizeof(arg2_vals[0]);

    for (int i = 0; i < n_arg2; i++) {
        for (int j = 0; j < 6; j++) memset(b[j], 0, bsz);
        memset(b[2], 0xCC, bsz);

        char label[128];
        snprintf(label, sizeof(label), "arg2=0x%lx", (unsigned long)arg2_vals[i]);
        test++;
        do_test(label,
                (uint64_t)(uintptr_t)b[0], arg2_vals[i],
                (uint64_t)(uintptr_t)b[2], (uint64_t)(uintptr_t)b[3],
                (uint64_t)(uintptr_t)b[4], (uint64_t)(uintptr_t)b[5],
                b[2], bsz, 0xCC);

        usleep(100000);
    }

    /*
     * Test 6: What about arg4, arg5, arg6?
     * arg4=size of output? arg5=flags? arg6=?
     */
    log_flush("\n--- Test 6: arg4/arg5/arg6 variations ---\n\n");

    for (int i = 0; i < 6; i++) memset(b[i], 0, bsz);
    memset(b[2], 0xCC, bsz);
    test++;
    do_test("args=(b0, b1, b2_out, 4096, 1, 0)",
            (uint64_t)(uintptr_t)b[0], (uint64_t)(uintptr_t)b[1],
            (uint64_t)(uintptr_t)b[2], 4096, 1, 0,
            b[2], bsz, 0xCC);
    usleep(100000);

    for (int i = 0; i < 6; i++) memset(b[i], 0, bsz);
    memset(b[2], 0xCC, bsz);
    test++;
    do_test("args=(b0, b1, b2_out, 4096, 0, 1)",
            (uint64_t)(uintptr_t)b[0], (uint64_t)(uintptr_t)b[1],
            (uint64_t)(uintptr_t)b[2], 4096, 0, 1,
            b[2], bsz, 0xCC);
    usleep(100000);

    /* arg4=buf, maybe it's also an output */
    for (int i = 0; i < 6; i++) memset(b[i], 0, bsz);
    memset(b[2], 0xCC, bsz);
    memset(b[3], 0xDD, bsz);
    test++;
    do_test("args=(b0, b1, b2_out, b3_out, b4, b5)",
            (uint64_t)(uintptr_t)b[0], (uint64_t)(uintptr_t)b[1],
            (uint64_t)(uintptr_t)b[2], (uint64_t)(uintptr_t)b[3],
            (uint64_t)(uintptr_t)b[4], (uint64_t)(uintptr_t)b[5],
            NULL, 0, 0);

    /* Check both b2 and b3 */
    int nz2 = 0, nz3 = 0;
    for (int i = 0; i < (int)bsz; i++) {
        if (b[2][i] != 0xCC) nz2++;
        if (b[3][i] != 0xDD) nz3++;
    }
    if (nz2) { log_flush("    b2 modified: %d bytes\n    ", nz2); hexdump(b[2], 64); }
    if (nz3) { log_flush("    b3 modified: %d bytes\n    ", nz3); hexdump(b[3], 64); }

    log_flush("\n=== Syscall 622 analysis complete ===\n");
    notify("Target622: done");

    for (int i = 0; i < 8; i++) munmap(b[i], bsz);
    if (log_fd >= 0) close(log_fd);
    return 0;
}
