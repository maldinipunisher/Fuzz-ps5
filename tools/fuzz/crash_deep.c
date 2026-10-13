/*
 * PS5 Deep Crash Analysis — Test crash syscalls with valid pointers
 *
 * These syscalls crash with (0,0,0). If they survive with valid
 * pointers, the crash is a NULL deref on arg, not a broken handler.
 * That means: controlled input → potential exploitation.
 *
 * Build with TARGET_IDX to select which crash to test (0-5).
 * One crash = one reboot, so we test one at a time.
 *
 * Crash table:
 *   0 = sc429 (survived 0, crashed buf) — MOST PROMISING
 *   1 = sc522 (nargs=6, crashed 0)
 *   2 = sc622 (nargs=6, crashed 0)
 *   3 = sc661 (nargs=4, crashed 0)
 *   4 = sc665 (nargs=2, crashed 0)
 *   5 = sc668 (nargs=2, crashed 0)
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

#ifndef TARGET_IDX
#define TARGET_IDX  0
#endif

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

static const struct {
    int num;
    int nargs;
    const char *name;
} crash_targets[] = {
    { 429, 2, "429 (survived 0, crashed buf)" },
    { 522, 6, "522 (crashed 0, nargs=6)" },
    { 622, 6, "622 (crashed 0, nargs=6)" },
    { 661, 4, "661 (crashed 0, nargs=4)" },
    { 665, 2, "665 (crashed 0, nargs=2)" },
    { 668, 2, "668 (crashed 0, nargs=2)" },
};

#define NUM_CRASH_TARGETS (sizeof(crash_targets)/sizeof(crash_targets[0]))

int main(void) {
    if (TARGET_IDX >= (int)NUM_CRASH_TARGETS) {
        printf("TARGET_IDX %d out of range (0-%d)\n",
               TARGET_IDX, (int)NUM_CRASH_TARGETS - 1);
        return 1;
    }

    int sc = crash_targets[TARGET_IDX].num;
    int nargs = crash_targets[TARGET_IDX].nargs;
    const char *name = crash_targets[TARGET_IDX].name;

    notify("CrashDeep: sc=%d", sc);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== Deep Crash Analysis: syscall %s ===\n", name);
    log_flush("nargs=%d, TARGET_IDX=%d\n\n", nargs, TARGET_IDX);

    size_t rsz = 0x10000;
    uint8_t *region = mmap(NULL, rsz, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        log_flush("[!] mmap failed\n");
        return 1;
    }

    uint8_t *buf1 = region;
    uint8_t *buf2 = region + 0x1000;
    uint8_t *buf3 = region + 0x2000;
    uint8_t *buf4 = region + 0x3000;
    uint8_t *buf5 = region + 0x4000;
    uint8_t *buf6 = region + 0x5000;
    int test = 0;

    /*
     * Test 1: Valid buffer filled with valid pointers
     * All qwords point to buf2 (also valid memory)
     */
    memset(region, 0, rsz);
    for (int i = 0; i < 0x1000; i += 8)
        *(uint64_t *)(buf1 + i) = (uint64_t)(uintptr_t)buf2;
    for (int i = 0; i < 0x1000; i += 8)
        *(uint64_t *)(buf2 + i) = (uint64_t)(uintptr_t)buf3;

    log_flush("[%02d] BEFORE sc=%d(buf_ptrs, buf2, buf3, buf4, buf5, buf6)\n",
              ++test, sc);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[%02d] SIGNAL %d!\n", test, caught_signal);
    } else {
        long ret = syscall(sc, buf1, buf2, buf3, buf4, buf5, buf6);
        int err = errno;
        log_flush("[%02d] ret=%ld errno=%d (%s)\n", test, ret, err, strerror(err));
        if (ret == 0) {
            log_flush("[%02d] *** SURVIVED WITH VALID PTRS! ***\n", test);
            notify("sc%d: SURVIVED ptrs!", sc);
            /* Check for data written */
            int nz1 = 0, nz2 = 0;
            for (int i = 0; i < 0x1000; i++) {
                if (buf2[i] != ((uint8_t *)&buf3)[i % 8]) nz1++;
            }
            /* buf3-6 were zeroed */
            for (int i = 0; i < 0x1000; i++) if (buf3[i]) nz2++;
            if (nz1) log_flush("[%02d] buf2 modified: %d bytes\n", test, nz1);
            if (nz2) {
                log_flush("[%02d] buf3 modified: %d bytes\n", test, nz2);
                log_flush("    "); hexdump(buf3, 64);
            }
        }
    }
    usleep(200000);

    /*
     * Test 2: Small integers as all args
     * Maybe args are IDs/fds, not pointers
     */
    log_flush("\n[%02d] BEFORE sc=%d(1, 1, 1, 1, 1, 1)\n", ++test, sc);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[%02d] SIGNAL %d!\n", test, caught_signal);
    } else {
        long ret = syscall(sc, 1, 1, 1, 1, 1, 1);
        int err = errno;
        log_flush("[%02d] ret=%ld errno=%d (%s)\n", test, ret, err, strerror(err));
        if (ret == 0) {
            log_flush("[%02d] *** SURVIVED with (1,1,1,1,1,1)! ***\n", test);
            notify("sc%d: val=1 works!", sc);
        }
    }
    usleep(200000);

    /*
     * Test 3: arg1=buf (zeroed), other args=valid sizes/ptrs
     * For sc429 specifically: crashed with (buf,0x1000,0)
     * Maybe it needs non-zero content in buf
     */
    memset(buf1, 0, 0x1000);
    /* Fill first qwords with small integers */
    *(uint64_t *)(buf1 + 0) = 1;
    *(uint64_t *)(buf1 + 8) = 0x100;
    *(uint64_t *)(buf1 + 16) = (uint64_t)(uintptr_t)buf2;
    *(uint64_t *)(buf1 + 24) = 0x1000;

    log_flush("\n[%02d] BEFORE sc=%d(buf{1,0x100,ptr,0x1000}, 0x100, buf2, ...)\n",
              ++test, sc);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[%02d] SIGNAL %d!\n", test, caught_signal);
    } else {
        long ret = syscall(sc, buf1, 0x100, buf2, 0x1000, buf3, buf4);
        int err = errno;
        log_flush("[%02d] ret=%ld errno=%d (%s)\n", test, ret, err, strerror(err));
        if (ret == 0) {
            log_flush("[%02d] *** SURVIVED! ***\n", test);
            notify("sc%d: struct+size works!", sc);
        }
    }
    usleep(200000);

    /*
     * Test 4: arg1=valid_fd, others=buf/size
     * Maybe first arg is a file descriptor
     */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(buf1, 0, 0x1000);

    log_flush("\n[%02d] BEFORE sc=%d(fd=%d, buf, 0x1000, ...)\n",
              ++test, sc, sock);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[%02d] SIGNAL %d!\n", test, caught_signal);
    } else {
        long ret = syscall(sc, sock, buf1, 0x1000, buf2, 0x1000, 0);
        int err = errno;
        log_flush("[%02d] ret=%ld errno=%d (%s)\n", test, ret, err, strerror(err));
        if (ret == 0) {
            log_flush("[%02d] *** SURVIVED with fd! ***\n", test);
            notify("sc%d: fd works!", sc);
            int nz = 0;
            for (int i = 0; i < 0x1000; i++) if (buf1[i]) nz++;
            if (nz) {
                log_flush("[%02d] buf modified: %d bytes\n", test, nz);
                log_flush("    "); hexdump(buf1, 128);
            }
        }
    }
    usleep(200000);

    /*
     * Test 5: Progressively non-zero args
     * Test (1,0,0), (0,1,0), (0,0,1) etc to find which arg causes crash
     */
    log_flush("\n--- Test 5: Isolate crash arg ---\n\n");

    for (int a = 0; a < nargs && a < 6; a++) {
        uint64_t args[6] = {0};
        args[a] = 1;

        log_flush("[%02d] BEFORE sc=%d(", ++test, sc);
        for (int i = 0; i < nargs && i < 6; i++)
            log_flush("%s%lu", i ? "," : "", (unsigned long)args[i]);
        log_flush(")\n");

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[%02d] SIGNAL %d! arg%d=1 crashes\n", test, caught_signal, a);
            continue;
        }

        long ret = syscall(sc, args[0], args[1], args[2], args[3], args[4], args[5]);
        int err = errno;
        log_flush("[%02d] ret=%ld errno=%d (%s)\n", test, ret, err, strerror(err));

        if (ret == 0) {
            log_flush("[%02d] *** arg%d=1 → SUCCESS ***\n", test, a);
        }

        usleep(100000);
    }

    /*
     * Test 6: Each arg = valid buffer pointer, others = 0
     */
    log_flush("\n--- Test 6: Each arg = buf ptr ---\n\n");

    uint8_t *bufs[] = {buf1, buf2, buf3, buf4, buf5, buf6};

    for (int a = 0; a < nargs && a < 6; a++) {
        uint64_t args[6] = {0};
        memset(bufs[a], 0, 0x1000);
        args[a] = (uint64_t)(uintptr_t)bufs[a];

        log_flush("[%02d] BEFORE sc=%d(arg%d=buf, rest=0)\n", ++test, sc, a);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[%02d] SIGNAL %d! arg%d=buf crashes\n", test, caught_signal, a);
            continue;
        }

        long ret = syscall(sc, args[0], args[1], args[2], args[3], args[4], args[5]);
        int err = errno;
        log_flush("[%02d] ret=%ld errno=%d (%s)\n", test, ret, err, strerror(err));

        if (ret == 0) {
            log_flush("[%02d] *** arg%d=buf → SUCCESS ***\n", test, a);
            int nz = 0;
            for (int i = 0; i < 0x1000; i++) if (bufs[a][i]) nz++;
            if (nz) {
                log_flush("[%02d] *** DATA WRITTEN: %d bytes ***\n", test, nz);
                log_flush("    "); hexdump(bufs[a], 128);
            }
        }

        usleep(100000);
    }

    /*
     * Test 7: (buf_with_ptrs, size, out_buf, out_size, 0, 0)
     * Common Sony pattern: (input, input_size, output, output_size)
     */
    log_flush("\n--- Test 7: in/out buffer pattern ---\n\n");

    memset(buf1, 0, 0x1000);
    *(uint64_t *)(buf1 + 0) = 1;
    memset(buf2, 0xCC, 0x1000);

    log_flush("[%02d] BEFORE sc=%d(in_buf, 256, out_buf, 4096, 0, 0)\n", ++test, sc);
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_flush("[%02d] SIGNAL %d!\n", test, caught_signal);
    } else {
        long ret = syscall(sc, buf1, 256, buf2, 4096, 0, 0);
        int err = errno;
        log_flush("[%02d] ret=%ld errno=%d (%s)\n", test, ret, err, strerror(err));

        if (ret == 0) {
            log_flush("[%02d] *** in/out WORKED! ***\n", test);
            int nz = 0;
            for (int i = 0; i < 0x1000; i++) if (buf2[i] != 0xCC) nz++;
            if (nz) {
                log_flush("[%02d] *** OUTPUT: %d bytes ***\n", test, nz);
                log_flush("    "); hexdump(buf2, 128);
            }
        }
    }

    log_flush("\n=== Deep analysis complete for sc=%d ===\n", sc);
    notify("CrashDeep sc%d: done", sc);

    if (sock >= 0) close(sock);
    munmap(region, rsz);
    if (log_fd >= 0) close(log_fd);
    return 0;
}
