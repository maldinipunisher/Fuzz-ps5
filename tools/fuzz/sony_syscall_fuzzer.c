/*
 * PS5 Sony Syscall Fuzzer v1.0
 *
 * Fuzzes Sony-specific syscalls (not in upstream FreeBSD) to find
 * crashes, memory corruption, or unexpected behavior.
 *
 * Strategy:
 *  - Target unnamed/Sony-specific syscalls (400-408, 585-678, etc.)
 *  - Send edge-case values: 0, -1, INT_MAX, kernel pointers, NULL
 *  - Log results via TCP to PC for offline analysis
 *  - Catch crashes via signal handlers
 *
 * Build: make (requires ps5-payload-dev SDK)
 * Run: load via Relapse → nc receives log on PC
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
#define LOG_BUF     4096

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

static int log_fd = -1;
static sigjmp_buf fuzz_jmp;
static volatile int caught_signal = 0;

static void notify(const char *msg) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, msg, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static void log_send(const char *fmt, ...) {
    char buf[LOG_BUF];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    printf("%s", buf);
    fflush(stdout);

    if (log_fd >= 0 && n > 0)
        write(log_fd, buf, n);
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

/*
 * Sony-specific syscall numbers identified from kernel DATA analysis.
 * These are NOT in upstream FreeBSD and are less audited.
 */
static const int sony_syscalls[] = {
    /* Group 1: unknown purpose, unique handlers */
    55, 65, 99, 101, 102, 113, 114, 125,

    /* Group 2: Sony additions 400-408 */
    400, 401, 402, 403, 404, 405, 406, 407, 408,

    /* Group 3: Sony additions 421-431 */
    421, 422, 423, 429, 430, 431,

    /* Group 4: Sony additions 499-572 (many unique) */
    476, 499, 515, 522, 534, 535, 536, 538, 539,
    541, 542, 543, 544, 546, 547, 548, 549,
    550, 551, 552, 553, 554, 555, 556, 560, 563,
    565, 566, 567, 572,

    /* Group 5: Sony additions 585-678 (heavily custom) */
    585, 586, 587, 588,
    591, 592, 593, 594, 595, 596, 598, 599,
    600, 601, 602, 603, 604, 605, 606, 607, 608,
    610, 611, 612, 613, 615, 616, 617, 618, 619,
    620, 622, 623, 624, 625, 626, 627, 628, 629, 630,
    632, 633, 634, 635, 636, 637, 638, 639, 640,
    641, 642, 643, 646, 647, 648, 649,
    652, 653, 654, 655, 656, 657, 658, 659, 660,
    661, 662, 663, 664, 665, 666, 667, 668, 669, 670,
    671, 672, 673, 674, 675, 676,
};

#define NUM_SONY_SYSCALLS (sizeof(sony_syscalls) / sizeof(sony_syscalls[0]))

/* Edge-case argument values for fuzzing */
static const uint64_t fuzz_values[] = {
    0x0000000000000000ULL,  /* NULL / zero */
    0x0000000000000001ULL,  /* minimal */
    0x00000000FFFFFFFFULL,  /* INT_MAX */
    0x0000000080000000ULL,  /* INT_MIN as unsigned */
    0xFFFFFFFFFFFFFFFFULL,  /* -1 / UINT64_MAX */
    0x0000000041414141ULL,  /* canary pattern */
    0x4141414141414141ULL,  /* large canary */
    0x0000000000001000ULL,  /* page size */
    0x0000000000000FFFULL,  /* page mask */
    0x00007FFFFFFFFFFFULL,  /* user space max */
    0xFFFF800000000000ULL,  /* kernel space min */
    0xFFFFFFFF00000000ULL,  /* high 32 set */
};

#define NUM_FUZZ_VALUES (sizeof(fuzz_values) / sizeof(fuzz_values[0]))

static long do_syscall(int num, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5, uint64_t a6) {
    return syscall(num, a1, a2, a3, a4, a5, a6);
}

static void fuzz_syscall_basic(int num) {
    log_send("[*] Fuzzing syscall %d with NULL args\n", num);

    for (int i = 0; i < (int)NUM_FUZZ_VALUES; i++) {
        uint64_t val = fuzz_values[i];
        caught_signal = 0;

        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_send("  [!] SIGNAL %d on syscall(%d, 0x%lx, 0, 0, 0, 0, 0)\n",
                     caught_signal, num, (unsigned long)val);
            continue;
        }

        long ret = do_syscall(num, val, 0, 0, 0, 0, 0);
        int err = errno;

        if (ret != -1 || (err != 78 && err != 22 && err != 1 && err != 14)) {
            log_send("  [+] syscall(%d, 0x%lx) = %ld (errno=%d)\n",
                     num, (unsigned long)val, ret, err);
        }
    }
}

static void fuzz_syscall_multi(int num, int nargs) {
    log_send("[*] Multi-arg fuzz syscall %d (%d args)\n", num, nargs);

    uint8_t *buf = malloc(0x1000);
    if (!buf) return;
    memset(buf, 0x41, 0x1000);

    uint64_t args[6] = {0};

    /* Test with buffer pointer as first arg */
    args[0] = (uint64_t)(uintptr_t)buf;
    for (int i = 1; i < 6; i++) args[i] = 0x1000;

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_send("  [!] SIGNAL %d on syscall(%d, buf, ...)\n",
                 caught_signal, num);
    } else {
        long ret = do_syscall(num, args[0], args[1], args[2], args[3], args[4], args[5]);
        if (ret != -1)
            log_send("  [+] syscall(%d, buf, 0x1000, ...) = %ld\n", num, ret);
    }

    /* Test with -1 as all args */
    for (int i = 0; i < 6; i++) args[i] = 0xFFFFFFFFFFFFFFFFULL;

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_send("  [!] SIGNAL %d on syscall(%d, -1, -1, ...)\n",
                 caught_signal, num);
    } else {
        long ret = do_syscall(num, args[0], args[1], args[2], args[3], args[4], args[5]);
        if (ret != -1)
            log_send("  [+] syscall(%d, -1, -1, ...) = %ld\n", num, ret);
    }

    /* Test with large size + valid buffer */
    args[0] = (uint64_t)(uintptr_t)buf;
    args[1] = 0x7FFFFFFFULL;
    args[2] = 0;
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_send("  [!] SIGNAL %d on syscall(%d, buf, INT_MAX, ...)\n",
                 caught_signal, num);
    } else {
        long ret = do_syscall(num, args[0], args[1], args[2], args[3], args[4], args[5]);
        if (ret != -1)
            log_send("  [+] syscall(%d, buf, INT_MAX, ...) = %ld\n", num, ret);
    }

    free(buf);
}

/* Nargs lookup from sysent table */
static int get_nargs(int num) {
    /* From sysent analysis */
    static const struct { int num; int nargs; } nargs_table[] = {
        {55,1},{65,3},{99,4},{101,2},{102,4},{113,4},{114,1},{125,3},
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
    for (int i = 0; i < (int)(sizeof(nargs_table)/sizeof(nargs_table[0])); i++) {
        if (nargs_table[i].num == num) return nargs_table[i].nargs;
    }
    return 1;
}

int main(void) {
    printf("\n=== PS5 Sony Syscall Fuzzer v1.0 ===\n\n");

    notify("Syscall Fuzzer starting...");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();
    if (log_fd >= 0) {
        log_send("[+] Logger connected to %s:%d\n", PC_IP, PC_PORT);
    } else {
        printf("[!] Logger not available, output to stdout only\n");
    }

    log_send("[*] Targeting %zu Sony-specific syscalls\n", NUM_SONY_SYSCALLS);
    log_send("[*] Using %zu edge-case values per syscall\n\n", NUM_FUZZ_VALUES);

    int interesting = 0;

    for (int i = 0; i < (int)NUM_SONY_SYSCALLS; i++) {
        int num = sony_syscalls[i];
        int nargs = get_nargs(num);

        log_send("=== Syscall %d (nargs=%d) [%d/%zu] ===\n",
                 num, nargs, i+1, NUM_SONY_SYSCALLS);

        fuzz_syscall_basic(num);

        if (nargs >= 2)
            fuzz_syscall_multi(num, nargs);

        log_send("\n");
    }

    log_send("\n[*] Fuzzing complete. %d interesting results.\n", interesting);
    notify("Syscall Fuzzer done!");

    if (log_fd >= 0) close(log_fd);
    return 0;
}
