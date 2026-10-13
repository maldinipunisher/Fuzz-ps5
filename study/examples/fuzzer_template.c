/*
 * Fuzzer Template — Customizable skeleton for new fuzz targets
 *
 * Based on the patterns from tools/fuzz/sony_syscall_fuzzer.c
 * but generalized for any syscall/ioctl target.
 *
 * How to use:
 *   1. Copy this file
 *   2. Fill in TARGET_SYSCALLS[] with numbers from sysent analysis
 *   3. Customize fuzz_strategies[] for your target
 *   4. Compile with ps5-payload-dev SDK
 *   5. Load via Relapse → monitor logs on PC
 *
 * Compile (cross-compile for PS5):
 *   make -f Makefile TARGET=my_fuzzer
 *
 * Receive logs on PC:
 *   nc -l -p 9024 | tee fuzz_log.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

/* ============================================================
 * CONFIGURATION — Edit these for your target
 * ============================================================ */

#define PC_IP       "192.168.100.24"
#define PC_PORT     9024
#define LOG_BUF     4096
#define MAX_ITERS   10000

/* Target syscalls to fuzz — fill from sysent analysis */
static const int TARGET_SYSCALLS[] = {
    /* Example: Sony syscalls identified as interesting
     * Replace with your own targets from analyze_data.py output */
    400, 401, 402, 403,
};
#define NUM_TARGETS (sizeof(TARGET_SYSCALLS) / sizeof(TARGET_SYSCALLS[0]))

/* ============================================================
 * Fuzz value strategies
 * ============================================================ */

typedef struct {
    const char *name;
    uint64_t values[8];
    int count;
} fuzz_strategy_t;

static const fuzz_strategy_t strategies[] = {
    {
        .name = "boundaries",
        .values = {0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                   0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF},
        .count = 8,
    },
    {
        .name = "pointers",
        .values = {0, 0x1000, 0x00007FFFFFFFFFFF,
                   0xFFFF800000000000, 0xFFFFFFFF80000000, 0},
        .count = 5,
    },
    {
        .name = "sizes",
        .values = {0, 1, 0xFFF, 0x1000, 0x10000, 0x7FFFFFFF, 0xFFFFFFFF, 0},
        .count = 7,
    },
    {
        .name = "patterns",
        .values = {0x4141414141414141, 0x4242424242424242,
                   0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE, 0},
        .count = 4,
    },
};
#define NUM_STRATEGIES (sizeof(strategies) / sizeof(strategies[0]))

/* ============================================================
 * Infrastructure (logging, signal handling)
 * ============================================================ */

static int log_fd = -1;
static sigjmp_buf fuzz_jmp;
static volatile int caught_signal = 0;
static int total_crashes = 0;
static int total_interesting = 0;

static void log_send(const char *fmt, ...) {
    char buf[LOG_BUF];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        write(STDOUT_FILENO, buf, n);
        if (log_fd >= 0) write(log_fd, buf, n);
    }
}

static void sig_handler(int sig) {
    caught_signal = sig;
    total_crashes++;
    siglongjmp(fuzz_jmp, 1);
}

static int connect_logger(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PC_PORT),
    };
    inet_pton(AF_INET, PC_IP, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ============================================================
 * Fuzzing engine
 * ============================================================ */

typedef struct {
    int syscall_num;
    int strategy_idx;
    int value_idx;
    uint64_t args[6];
    int result;
    int error;
    int signal;
} fuzz_result_t;

static fuzz_result_t fuzz_one(int num, const uint64_t args[6]) {
    fuzz_result_t res = {
        .syscall_num = num,
        .signal = 0,
    };
    memcpy(res.args, args, sizeof(res.args));

    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        res.signal = caught_signal;
        return res;
    }

    long ret = syscall(num, args[0], args[1], args[2],
                       args[3], args[4], args[5]);
    res.result = (int)ret;
    res.error = errno;
    return res;
}

static int is_interesting(const fuzz_result_t *r) {
    if (r->signal) return 1;
    if (r->result == 0) return 1;
    if (r->error != 78 && r->error != 22 && r->error != 1 && r->error != 14)
        return 1;
    return 0;
}

static void report_result(const fuzz_result_t *r, const char *strategy_name) {
    if (r->signal) {
        log_send("[CRASH] syscall(%d) signal=%d strategy=%s "
                 "args=[%lx,%lx,%lx,%lx,%lx,%lx]\n",
                 r->syscall_num, r->signal, strategy_name,
                 r->args[0], r->args[1], r->args[2],
                 r->args[3], r->args[4], r->args[5]);
    } else if (is_interesting(r)) {
        log_send("[HIT]   syscall(%d)=%d errno=%d strategy=%s "
                 "args=[%lx,%lx,%lx,%lx,%lx,%lx]\n",
                 r->syscall_num, r->result, r->error, strategy_name,
                 r->args[0], r->args[1], r->args[2],
                 r->args[3], r->args[4], r->args[5]);
    }
}

/* ============================================================
 * Main fuzzing loop
 * ============================================================ */

int main(void) {
    log_send("\n=== Fuzzer Template v1.0 ===\n\n");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);

    log_fd = connect_logger();
    if (log_fd >= 0)
        log_send("[+] Logger connected to %s:%d\n", PC_IP, PC_PORT);

    log_send("[*] Targets: %zu syscalls, %zu strategies\n\n",
             NUM_TARGETS, NUM_STRATEGIES);

    /* Phase 1: Basic single-arg fuzzing */
    log_send("--- Phase 1: Single-argument fuzzing ---\n\n");
    for (int t = 0; t < (int)NUM_TARGETS; t++) {
        int num = TARGET_SYSCALLS[t];
        for (int s = 0; s < (int)NUM_STRATEGIES; s++) {
            const fuzz_strategy_t *strat = &strategies[s];
            for (int v = 0; v < strat->count; v++) {
                uint64_t args[6] = {strat->values[v], 0, 0, 0, 0, 0};
                fuzz_result_t r = fuzz_one(num, args);
                if (is_interesting(&r)) {
                    total_interesting++;
                    report_result(&r, strat->name);
                }
            }
        }
    }

    /* Phase 2: Buffer-based fuzzing */
    log_send("\n--- Phase 2: Buffer argument fuzzing ---\n\n");
    uint8_t *fuzz_buf = malloc(0x10000);
    if (fuzz_buf) {
        memset(fuzz_buf, 0x41, 0x10000);
        for (int t = 0; t < (int)NUM_TARGETS; t++) {
            int num = TARGET_SYSCALLS[t];
            uint64_t args[6] = {
                (uint64_t)(uintptr_t)fuzz_buf,
                0x10000, 0, 0, 0, 0
            };
            fuzz_result_t r = fuzz_one(num, args);
            if (is_interesting(&r)) {
                total_interesting++;
                report_result(&r, "buffer");
            }
        }
        free(fuzz_buf);
    }

    /* Summary */
    log_send("\n=== SUMMARY ===\n");
    log_send("Crashes:     %d\n", total_crashes);
    log_send("Interesting: %d\n", total_interesting);
    log_send("Done.\n");

    if (log_fd >= 0) close(log_fd);
    return 0;
}
