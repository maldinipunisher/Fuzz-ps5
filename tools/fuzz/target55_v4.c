/*
 * PS5 Targeted Fuzzer — Syscall 55 v4
 *
 * FINDINGS SO FAR:
 *   syscall(55, 0)          = CRASH (NULL deref)
 *   syscall(55, buf_zeros)  = CRASH (secondary deref)
 *   syscall(55, buf_ptrs)   = CRASH (even with valid pointers)
 *
 * PROBLEM: We've never tested raw non-zero integers!
 * Every version crashed at its FIRST test.
 *
 * v4 STRATEGY: Start with the SAFEST values first.
 *   - Raw integer 1 (might be fd, id, or enum)
 *   - If that works, try more integers
 *   - Only then try pointer-based
 *
 * ONE TEST PER RUN to maximize info per reboot.
 * Change TEST_PHASE to select which test to run.
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
    notify("Target55 v4: raw integer test");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== PS5 Syscall 55 v4: Raw Integer Test ===\n");
    log_flush("KNOWN: 0, buf_zeros, buf_ptrs ALL crash\n");
    log_flush("NEW: testing raw non-zero integers first\n\n");

    /*
     * Phase 1: Raw integers 1-10
     * These are the values we've NEVER tested because every prior
     * version crashed at its first test before reaching these.
     *
     * If arg is a file descriptor: small ints might work (0=stdin, etc)
     * If arg is a command ID: small ints might be valid commands
     * If arg is a pointer: small ints will crash with EFAULT or panic
     */
    log_flush("--- Phase 1: Raw integers 1-10 ---\n\n");

    for (int v = 1; v <= 10; v++) {
        log_flush("[1.%02d] BEFORE syscall(%d, %d)\n", v, TARGET, v);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[1.%02d] SIGNAL %d on val=%d\n", v, caught_signal, v);
            notify("S55: SIGNAL %d on val=%d", caught_signal, v);
            continue;
        }

        long ret = syscall(TARGET, (uint64_t)v);
        int err = errno;
        log_flush("[1.%02d] ret=%ld errno=%d (%s)\n", v, ret, err, strerror(err));

        if (ret == 0) {
            log_flush("[1.%02d] *** SUCCESS ret=0! ***\n", v);
            notify("S55: val=%d SUCCESS ret=0!", v);
        } else if (ret > 0) {
            log_flush("[1.%02d] *** POSITIVE ret=%ld! ***\n", v, ret);
            notify("S55: val=%d ret=%ld!", v, ret);
        }

        usleep(100000);
    }

    /*
     * Phase 2: If we get here, integers 1-10 didn't crash!
     * Try more values to understand the pattern.
     */
    log_flush("\n--- Phase 2: Wider integer range ---\n\n");

    uint64_t wider[] = {
        16, 32, 64, 100, 128, 255, 256, 512, 1000, 1024,
        4096, 0x7FFF, 0xFFFF, 0x10000, 0x7FFFFFFF,
        0xFFFFFFFF, 0x100000000ULL, (uint64_t)-1
    };
    int num_wider = sizeof(wider) / sizeof(wider[0]);

    for (int i = 0; i < num_wider; i++) {
        log_flush("[2.%02d] BEFORE syscall(%d, 0x%lx)\n",
                  i+1, TARGET, (unsigned long)wider[i]);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[2.%02d] SIGNAL %d on 0x%lx\n",
                      i+1, caught_signal, (unsigned long)wider[i]);
            continue;
        }

        long ret = syscall(TARGET, wider[i]);
        int err = errno;
        log_flush("[2.%02d] ret=%ld errno=%d (%s)\n", i+1, ret, err, strerror(err));

        usleep(100000);
    }

    /*
     * Phase 3: If integers work, try with a SECOND argument
     * Maybe nargs=1 but it actually uses arg2 internally
     */
    log_flush("\n--- Phase 3: Two-arg with working integer ---\n\n");

    uint8_t *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf != MAP_FAILED) {
        memset(buf, 0, 4096);

        /* (1, buf) */
        log_flush("[3.1] BEFORE syscall(%d, 1, buf)\n", TARGET);
        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[3.1] SIGNAL %d\n", caught_signal);
        } else {
            long ret = syscall(TARGET, 1, buf);
            log_flush("[3.1] ret=%ld errno=%d\n", ret, errno);
            /* Check if kernel wrote to buf */
            int nz = 0;
            for (int i = 0; i < 4096; i++) if (buf[i]) nz++;
            if (nz) {
                log_flush("[3.1] *** BUF MODIFIED: %d bytes ***\n", nz);
                for (int i = 0; i < 64; i++) {
                    if (i > 0 && (i%16)==0) log_flush("\n    ");
                    log_flush("%02x ", buf[i]);
                }
                log_flush("\n");
            }
        }

        /* (1, buf, 4096) */
        memset(buf, 0, 4096);
        log_flush("[3.2] BEFORE syscall(%d, 1, buf, 4096)\n", TARGET);
        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[3.2] SIGNAL %d\n", caught_signal);
        } else {
            long ret = syscall(TARGET, 1, buf, 4096);
            log_flush("[3.2] ret=%ld errno=%d\n", ret, errno);
        }

        munmap(buf, 4096);
    }

    /*
     * Phase 4: Use open fd as argument
     * Maybe syscall 55 operates on a file descriptor
     */
    log_flush("\n--- Phase 4: File descriptor args ---\n\n");

    int fds_to_test[8];
    int nfds = 0;

    /* stdin/stdout/stderr */
    fds_to_test[nfds++] = 0;
    fds_to_test[nfds++] = 1;
    fds_to_test[nfds++] = 2;

    /* socket */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) fds_to_test[nfds++] = s;

    /* socketpair */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0) {
        fds_to_test[nfds++] = sp[0];
        fds_to_test[nfds++] = sp[1];
    }

    for (int fi = 0; fi < nfds; fi++) {
        log_flush("[4.%d] BEFORE syscall(%d, fd=%d)\n", fi+1, TARGET, fds_to_test[fi]);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[4.%d] SIGNAL %d on fd=%d\n", fi+1, caught_signal, fds_to_test[fi]);
            continue;
        }

        long ret = syscall(TARGET, (uint64_t)(long)fds_to_test[fi]);
        int err = errno;
        log_flush("[4.%d] ret=%ld errno=%d (%s)\n", fi+1, ret, err, strerror(err));

        if (ret == 0) {
            log_flush("[4.%d] *** SUCCESS on fd=%d ***\n", fi+1, fds_to_test[fi]);
            notify("S55: fd=%d works!", fds_to_test[fi]);
        }

        usleep(100000);
    }

    log_flush("\n=== v4 complete ===\n");
    notify("Target55 v4: complete");

    if (s >= 0) close(s);
    if (nfds > 4) { close(sp[0]); close(sp[1]); }
    if (log_fd >= 0) close(log_fd);
    return 0;
}
