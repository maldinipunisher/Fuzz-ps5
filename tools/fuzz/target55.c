/*
 * PS5 Targeted Fuzzer — Syscall 55
 *
 * Tests syscall 55 one value at a time with logging between each call.
 * Goal: identify exactly which input causes kernel panic.
 *
 * Each test is logged BEFORE the syscall is called, so the last
 * logged line = the value that crashed the kernel.
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <ps5/kernel.h>

#define PC_IP       "192.168.100.24"
#define PC_PORT     9024

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
    char buf[1024];
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

#define TARGET_SYSCALL 55

int main(void) {
    notify("Target55: testing syscall 55");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== PS5 Targeted Fuzzer: Syscall %d ===\n\n", TARGET_SYSCALL);
    log_flush("Each line logged BEFORE the syscall.\n");
    log_flush("Last line = crash trigger.\n\n");

    /*
     * Phase 1: single-arg tests, one value at a time.
     * Log BEFORE each syscall so we know which one crashed.
     */
    static const struct {
        uint64_t val;
        const char *name;
    } tests[] = {
        { 0x0000000000000000ULL, "NULL/zero" },
        { 0x0000000000000001ULL, "1" },
        { 0x0000000000000002ULL, "2" },
        { 0x000000000000000FULL, "15" },
        { 0x00000000000000FFULL, "255" },
        { 0x0000000000000100ULL, "256" },
        { 0x0000000000001000ULL, "4096/page" },
        { 0x0000000000010000ULL, "64K" },
        { 0x00000000000FFFFFULL, "1M-1" },
        { 0x000000007FFFFFFFULL, "INT_MAX" },
        { 0x0000000080000000ULL, "INT_MIN_u" },
        { 0x00000000FFFFFFFFULL, "UINT32_MAX" },
        { 0x0000000100000000ULL, "4GB" },
        { 0x00007FFFFFFFFFFFULL, "user_max" },
        { 0xFFFF800000000000ULL, "kern_min" },
        { 0xFFFFFFFF80000000ULL, "kern_typical" },
        { 0xFFFFFFFFFFFFFFFFULL, "-1" },
        { 0x4141414141414141ULL, "AAAA_canary" },
    };

    int num_tests = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < num_tests; i++) {
        log_flush("[%02d/%02d] BEFORE syscall(%d, 0x%lx) [%s]\n",
                  i+1, num_tests, TARGET_SYSCALL,
                  (unsigned long)tests[i].val, tests[i].name);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[%02d/%02d] SIGNAL %d caught!\n", i+1, num_tests, caught_signal);
            notify("Syscall 55: SIGNAL %d on 0x%lx", caught_signal,
                   (unsigned long)tests[i].val);
            continue;
        }

        long ret = syscall(TARGET_SYSCALL, tests[i].val);
        int err = errno;

        log_flush("[%02d/%02d] AFTER  ret=%ld errno=%d (%s)\n",
                  i+1, num_tests, ret, err, strerror(err));

        usleep(100000); /* 100ms between tests */
    }

    /*
     * Phase 2: if we get here, single args didn't crash.
     * Try with valid buffer pointer.
     */
    log_flush("\n--- Phase 2: buffer pointer arg ---\n\n");

    uint8_t *buf = malloc(0x1000);
    if (buf) {
        memset(buf, 0, 0x1000);

        log_flush("BEFORE syscall(%d, buf=%p) [zeroed 4K]\n",
                  TARGET_SYSCALL, (void *)buf);
        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("SIGNAL %d on buf arg\n", caught_signal);
        } else {
            long ret = syscall(TARGET_SYSCALL, buf);
            log_flush("AFTER  ret=%ld errno=%d\n", ret, errno);
        }

        usleep(100000);

        memset(buf, 0x41, 0x1000);
        log_flush("BEFORE syscall(%d, buf=%p) [0x41 filled 4K]\n",
                  TARGET_SYSCALL, (void *)buf);
        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("SIGNAL %d on 0x41 buf\n", caught_signal);
        } else {
            long ret = syscall(TARGET_SYSCALL, buf);
            log_flush("AFTER  ret=%ld errno=%d\n", ret, errno);
        }

        free(buf);
    }

    log_flush("\n[*] All tests completed without kernel panic.\n");
    log_flush("[*] Syscall 55 is safe with these inputs.\n");
    notify("Target55: done, no crash");

    if (log_fd >= 0) close(log_fd);
    return 0;
}
