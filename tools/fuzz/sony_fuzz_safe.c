/*
 * PS5 Sony Syscall Fuzzer — Safe Sequential Version
 *
 * Logs BEFORE each syscall so we know exactly which one crashes.
 * Skips syscall 55 (confirmed always-crash, DoS only).
 *
 * Strategy: test each syscall with SAFE values first (small ints),
 * then buffer pointers. One crash = one reboot, but we know which.
 *
 * The fuzzer saves progress via the SKIP count mechanism:
 * After a crash, rebuild with SKIP_COUNT set to the last completed
 * syscall index to resume from where we left off.
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

/* Change this to skip already-tested syscalls after a crash */
#ifndef SKIP_COUNT
#define SKIP_COUNT  0
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

/* Nargs from sysent analysis */
static int get_nargs(int num) {
    static const struct { int num; int nargs; } tbl[] = {
        {65,3},{99,4},{101,2},{102,4},{113,4},{114,1},{125,3},
        {400,1},{401,1},{402,1},{403,1},{404,2},{405,5},{406,1},{407,2},{408,1},
        {421,1},{422,1},{423,2},{429,2},{430,3},{431,1},
        {476,4},{499,4},{515,3},{522,6},{534,2},{535,4},{536,3},{538,3},{539,1},
        {541,1},{542,5},{543,4},{544,2},{546,3},{547,2},{548,5},{549,4},
        {550,1},{551,1},{552,1},{553,3},{554,2},{555,2},{556,3},{560,1},{563,1},
        {565,3},{566,3},{567,3},{572,4},
        {585,0},{586,1},{587,2},{588,3},
        {591,3},{592,3},{593,2},{594,4},{595,3},{596,0},{598,2},{599,0},
        {600,1},{601,3},{602,3},{603,2},{604,5},{605,1},{606,0},{607,2},{608,3},
        {610,1},{611,3},{612,1},{613,3},{615,3},{616,2},{617,1},{618,3},{619,5},
        {620,0},{622,6},{623,1},{624,0},{625,4},{626,5},{627,2},{628,6},{629,4},
        {630,1},{632,1},{633,1},{634,2},{635,2},{636,2},{637,2},{638,4},{639,5},
        {640,8},{641,2},{642,4},{643,1},{646,1},{647,1},{648,1},{649,3},
        {652,2},{653,1},{654,5},{655,3},{656,2},{657,4},{658,1},{659,3},{660,2},
        {661,4},{662,3},{663,5},{664,3},{665,2},{666,3},{667,2},{668,2},
        {669,5},{670,4},{671,4},{672,3},{673,4},{674,5},{675,2},{676,0},
    };
    for (int i = 0; i < (int)(sizeof(tbl)/sizeof(tbl[0])); i++) {
        if (tbl[i].num == num) return tbl[i].nargs;
    }
    return 1;
}

/*
 * Sony syscalls EXCLUDING 55 (confirmed always-crash DoS)
 */
static const int targets[] = {
    65, 99, 101, 102, 113, 114, 125,
    400, 401, 402, 403, 404, 405, 406, 407, 408,
    421, 422, 423, 429, 430, 431,
    476, 499, 515, 522, 534, 535, 536, 538, 539,
    541, 542, 543, 544, 546, 547, 548, 549,
    550, 551, 552, 553, 554, 555, 556, 560, 563,
    565, 566, 567, 572,
    585, 586, 587, 588,
    591, 592, 593, 594, 595, 596, 598, 599,
    600, 601, 602, 603, 604, 605, 606, 607, 608,
    610, 611, 612, 613, 615, 616, 617, 618, 619,
    620, 622, 623, 624, 625, 626, 627, 628, 629, 630,
    632, 633, 634, 635, 636, 637, 638, 639, 640,
    641, 642, 643, 646, 647, 648, 649,
    652, 653, 654, 655, 656, 657, 658, 659, 660,
    661, 662, 663, 664, 665, 666, 667, 668,
    669, 670, 671, 672, 673, 674, 675, 676,
};

#define NUM_TARGETS (sizeof(targets) / sizeof(targets[0]))

static long safe_syscall(int num, int nargs, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)nargs;
    return syscall(num, a1, a2, a3, a4, a5, a6);
}

int main(void) {
    notify("Safe Fuzzer: skip=%d", SKIP_COUNT);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();

    log_flush("=== PS5 Sony Syscall Safe Fuzzer ===\n");
    log_flush("Total targets: %zu (excluding syscall 55)\n", NUM_TARGETS);
    log_flush("Skipping first %d (already tested)\n", SKIP_COUNT);
    log_flush("Each line logged BEFORE syscall\n\n");

    void *buf = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        log_flush("[!] mmap failed\n");
        return 1;
    }
    memset(buf, 0, 0x10000);

    int crashes = 0;
    int success = 0;

    for (int idx = SKIP_COUNT; idx < (int)NUM_TARGETS; idx++) {
        int num = targets[idx];
        int nargs = get_nargs(num);

        /*
         * Test A: all zeros (safest - most syscalls just return EINVAL)
         */
        log_flush("[%03d] idx=%d sc=%d nargs=%d BEFORE(0,0,0)\n",
                  idx, idx, num, nargs);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[%03d] !!! SIGNAL %d on sc=%d(0,0,0) !!!\n",
                      idx, caught_signal, num);
            crashes++;
            notify("CRASH sc=%d val=0 sig=%d", num, caught_signal);
            usleep(200000);
            continue;
        }

        long ret = safe_syscall(num, nargs, 0, 0, 0, 0, 0, 0);
        int err = errno;

        if (ret == 0) {
            log_flush("[%03d] *** sc=%d(0) = SUCCESS ret=0 ***\n", idx, num);
            success++;
            notify("OK sc=%d ret=0", num);
        } else if (err != 78 && err != 22 && err != 1 && err != 14 && err != 2) {
            /* Not ENOSYS/EINVAL/EPERM/EFAULT/ENOENT - interesting */
            log_flush("[%03d] sc=%d(0) ret=%ld errno=%d (%s) INTERESTING\n",
                      idx, num, ret, err, strerror(err));
        } else {
            log_flush("[%03d] sc=%d(0) ret=%ld errno=%d\n", idx, num, ret, err);
        }

        usleep(50000);

        /*
         * Test B: buffer pointer as arg1
         */
        memset(buf, 0, 0x1000);

        log_flush("[%03d] idx=%d sc=%d BEFORE(buf,0x1000,0)\n", idx, idx, num);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[%03d] !!! SIGNAL %d on sc=%d(buf) !!!\n",
                      idx, caught_signal, num);
            crashes++;
            usleep(200000);
            continue;
        }

        ret = safe_syscall(num, nargs,
                          (uint64_t)(uintptr_t)buf, 0x1000, 0, 0, 0, 0);
        err = errno;

        if (ret == 0) {
            log_flush("[%03d] *** sc=%d(buf) = SUCCESS ret=0 ***\n", idx, num);

            /* Check if kernel wrote data (info leak!) */
            int nz = 0;
            uint8_t *p = (uint8_t *)buf;
            for (int i = 0; i < 0x1000; i++) if (p[i]) nz++;
            if (nz > 0) {
                log_flush("[%03d] *** INFO LEAK? %d non-zero bytes ***\n", idx, nz);
                log_flush("    ");
                for (int i = 0; i < 64 && i < nz + 16; i++) {
                    if (i > 0 && (i%16)==0) log_flush("\n    ");
                    log_flush("%02x ", p[i]);
                }
                log_flush("\n");
                notify("LEAK? sc=%d %d bytes", num, nz);
            }
        } else if (err != 78 && err != 22 && err != 1 && err != 14 && err != 2) {
            log_flush("[%03d] sc=%d(buf) ret=%ld errno=%d (%s)\n",
                      idx, num, ret, err, strerror(err));
        }

        usleep(50000);

        /*
         * Test C: -1 as arg1 (trigger integer overflow paths)
         */
        log_flush("[%03d] idx=%d sc=%d BEFORE(-1,0,0)\n", idx, idx, num);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_flush("[%03d] !!! SIGNAL %d on sc=%d(-1) !!!\n",
                      idx, caught_signal, num);
            crashes++;
            notify("CRASH sc=%d val=-1 sig=%d", num, caught_signal);
            usleep(200000);
            continue;
        }

        ret = safe_syscall(num, nargs,
                          0xFFFFFFFFFFFFFFFFULL, 0, 0, 0, 0, 0);
        err = errno;

        if (ret == 0) {
            log_flush("[%03d] *** sc=%d(-1) = SUCCESS ret=0 ***\n", idx, num);
        } else if (err != 78 && err != 22 && err != 1 && err != 14 && err != 2) {
            log_flush("[%03d] sc=%d(-1) ret=%ld errno=%d (%s)\n",
                      idx, num, ret, err, strerror(err));
        }

        usleep(50000);
    }

    log_flush("\n=== RESULTS ===\n");
    log_flush("Tested: %zu syscalls\n", NUM_TARGETS - SKIP_COUNT);
    log_flush("Crashes (SIGNAL): %d\n", crashes);
    log_flush("Success (ret=0): %d\n", success);
    log_flush("Any CRASH or INFO LEAK = investigate further!\n");

    notify("Fuzzer done: %d crash, %d ok", crashes, success);

    munmap(buf, 0x10000);
    if (log_fd >= 0) close(log_fd);
    return 0;
}
