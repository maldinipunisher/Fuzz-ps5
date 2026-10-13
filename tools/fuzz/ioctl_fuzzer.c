/*
 * PS5 IOCTL Fuzzer v1.0
 *
 * Probes /dev/* devices and fuzzes ioctl commands to find
 * kernel vulnerabilities. IOCTL is the #1 attack surface for
 * jailbreak bugs (PS4 bd_jb exploit, GPU driver exploits, etc.)
 *
 * Strategy:
 *  1. Enumerate accessible /dev/* devices
 *  2. For each device, try opening with various flags
 *  3. Fuzz ioctl commands: iterate cmd numbers 0x0000-0xFFFF
 *  4. For interesting cmds, fuzz arg values
 *  5. Log all non-ENOTTY results (those are real ioctl handlers)
 *
 * Build: make (requires ps5-payload-dev SDK)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

/* High-priority devices from kernel DATA analysis */
static const char *priority_devices[] = {
    "/dev/dce",          /* Display Core Engine — GPU display */
    "/dev/gc",           /* Graphics Core — GPU compute */
    "/dev/deci_tty7",    /* Debug TTY */
    "/dev/dmem0",        /* Direct memory access */
    "/dev/dmem1",
    "/dev/ajm",          /* Audio Job Manager */
    "/dev/camera",       /* Camera */
    "/dev/notification", /* Notification system */
    "/dev/sbram",        /* Secure BRAM */
    "/dev/icc_power",    /* ICC power controller */
    "/dev/sflash",       /* SPI flash */
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/console",
    NULL
};

typedef struct {
    char path[256];
    int  fd;
    int  writable;
} device_t;

#define MAX_DEVICES 128
static device_t devices[MAX_DEVICES];
static int num_devices = 0;

static int try_open_device(const char *path) {
    int fd = open(path, O_RDWR | O_NONBLOCK);
    if (fd >= 0) return fd;
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd >= 0) return fd;
    fd = open(path, O_WRONLY | O_NONBLOCK);
    return fd;
}

static void enumerate_devices(void) {
    log_send("[*] Enumerating /dev/ devices...\n\n");

    /* Try priority devices first */
    for (int i = 0; priority_devices[i]; i++) {
        int fd = try_open_device(priority_devices[i]);
        if (fd >= 0) {
            log_send("  [+] %s → fd=%d\n", priority_devices[i], fd);
            strncpy(devices[num_devices].path, priority_devices[i], 255);
            devices[num_devices].fd = fd;
            devices[num_devices].writable = 1;
            num_devices++;
        } else {
            log_send("  [-] %s → %s\n", priority_devices[i], strerror(errno));
        }
        if (num_devices >= MAX_DEVICES) break;
    }

    /* Then scan /dev/ directory */
    DIR *dir = opendir("/dev");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL && num_devices < MAX_DEVICES) {
            if (ent->d_name[0] == '.') continue;

            char path[256];
            snprintf(path, sizeof(path), "/dev/%s", ent->d_name);

            /* Skip if already in list */
            int skip = 0;
            for (int i = 0; i < num_devices; i++) {
                if (strcmp(devices[i].path, path) == 0) { skip = 1; break; }
            }
            if (skip) continue;

            int fd = try_open_device(path);
            if (fd >= 0) {
                log_send("  [+] %s → fd=%d\n", path, fd);
                strncpy(devices[num_devices].path, path, 255);
                devices[num_devices].fd = fd;
                num_devices++;
            }
        }
        closedir(dir);
    }

    log_send("\n[+] Opened %d devices\n\n", num_devices);
}

/*
 * Fuzz ioctl commands on a device.
 * For each cmd that doesn't return ENOTTY, it's a valid handler.
 * Those valid handlers are then fuzzed with different arg values.
 */
static void deep_fuzz_ioctl(device_t *dev, unsigned long cmd);

static void fuzz_device_ioctls(device_t *dev) {
    log_send("=== Fuzzing: %s (fd=%d) ===\n", dev->path, dev->fd);

    uint8_t buf[4096];
    memset(buf, 0, sizeof(buf));

    int valid_cmds = 0;
    int interesting = 0;

    /*
     * ioctl command encoding (FreeBSD):
     *   bits 31-30: direction (00=none, 01=out, 10=in, 11=inout)
     *   bits 29-16: size
     *   bits 15-8:  group (ASCII char)
     *   bits 7-0:   number
     *
     * We scan common group chars: 'a'-'z', 'A'-'Z', special Sony groups
     */
    const char groups[] = "abcdefghijklmnopqrstuvwxyz"
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
                          "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99";

    for (int gi = 0; gi < (int)sizeof(groups) - 1; gi++) {
        unsigned char g = groups[gi];

        for (int n = 0; n < 256; n++) {
            /* Try all 4 directions */
            unsigned long cmds[4];
            cmds[0] = (g << 8) | n;                           /* _IO */
            cmds[1] = (0x40000000UL) | (8 << 16) | (g << 8) | n; /* _IOR 8 */
            cmds[2] = (0x80000000UL) | (8 << 16) | (g << 8) | n; /* _IOW 8 */
            cmds[3] = (0xC0000000UL) | (8 << 16) | (g << 8) | n; /* _IOWR 8 */

            for (int d = 0; d < 4; d++) {
                caught_signal = 0;
                errno = 0;

                if (sigsetjmp(fuzz_jmp, 1) != 0) {
                    log_send("  [!!!] SIGNAL %d on ioctl(%s, 0x%lx)\n",
                             caught_signal, dev->path, cmds[d]);
                    interesting++;
                    continue;
                }

                memset(buf, 0, sizeof(buf));
                int ret = ioctl(dev->fd, cmds[d], buf);
                int err = errno;

                if (err != ENOTTY && err != EBADF && err != ENXIO) {
                    valid_cmds++;
                    const char *dir_str[] = {"IO", "IOR", "IOW", "IOWR"};
                    log_send("  [+] %s(0x%lx) '%c' #%d = %d (errno=%d %s)\n",
                             dir_str[d], cmds[d], (g >= 0x20 && g < 0x7f) ? g : '?',
                             n, ret, err, strerror(err));

                    if (ret == 0) {
                        /* Successful ioctl — deep fuzz this command */
                        interesting++;
                        deep_fuzz_ioctl(dev, cmds[d]);
                    }
                }
            }
        }
    }

    log_send("  Summary: %d valid cmds, %d interesting\n\n", valid_cmds, interesting);
}

static void deep_fuzz_ioctl(device_t *dev, unsigned long cmd) {
    log_send("    [DEEP] Fuzzing cmd 0x%lx with edge-case args\n", cmd);

    /* Test 1: NULL arg */
    caught_signal = 0;
    if (sigsetjmp(fuzz_jmp, 1) != 0) {
        log_send("    [!!!] SIGNAL %d on ioctl(cmd=0x%lx, NULL)\n",
                 caught_signal, cmd);
        return;
    }
    int ret = ioctl(dev->fd, cmd, NULL);
    log_send("    NULL arg → %d (errno=%d)\n", ret, errno);

    /* Test 2: Large buffer with pattern */
    uint8_t *big = malloc(0x10000);
    if (big) {
        memset(big, 0x41, 0x10000);

        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_send("    [!!!] SIGNAL %d on ioctl(cmd=0x%lx, 0x41*64K)\n",
                     caught_signal, cmd);
        } else {
            ret = ioctl(dev->fd, cmd, big);
            log_send("    64K AAAA → %d (errno=%d)\n", ret, errno);

            /* Check if kernel wrote anything back */
            int nonzero = 0;
            for (int i = 0; i < 0x100; i++) {
                if (big[i] != 0x41) { nonzero++; }
            }
            if (nonzero > 0) {
                log_send("    [!] Kernel wrote %d bytes to output buffer!\n", nonzero);
                log_send("    First 32 bytes: ");
                for (int i = 0; i < 32; i++)
                    log_send("%02x", big[i]);
                log_send("\n");
            }
        }

        /* Test 3: Buffer with kernel-like pointer */
        memset(big, 0, 0x1000);
        *(uint64_t *)big = 0xFFFFFFFF80000000ULL;
        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_send("    [!!!] SIGNAL %d on ioctl(cmd=0x%lx, kern_ptr)\n",
                     caught_signal, cmd);
        } else {
            ret = ioctl(dev->fd, cmd, big);
            log_send("    kern_ptr arg → %d (errno=%d)\n", ret, errno);
        }

        /* Test 4: Negative size in struct */
        memset(big, 0, 0x1000);
        *(int32_t *)big = -1;
        *(int32_t *)(big + 4) = 0x7FFFFFFF;
        caught_signal = 0;
        if (sigsetjmp(fuzz_jmp, 1) != 0) {
            log_send("    [!!!] SIGNAL %d on ioctl(cmd=0x%lx, neg_size)\n",
                     caught_signal, cmd);
        } else {
            ret = ioctl(dev->fd, cmd, big);
            log_send("    neg_size arg → %d (errno=%d)\n", ret, errno);
        }

        free(big);
    }
}

int main(void) {
    printf("\n=== PS5 IOCTL Fuzzer v1.0 ===\n\n");

    notify("IOCTL Fuzzer starting...");

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGABRT, sig_handler);

    log_fd = connect_logger();
    if (log_fd >= 0) {
        log_send("[+] Logger connected to %s:%d\n", PC_IP, PC_PORT);
    } else {
        printf("[!] No logger, stdout only\n");
    }

    enumerate_devices();

    if (num_devices == 0) {
        log_send("[!] No devices opened\n");
        notify("IOCTL Fuzzer: no devices");
        return 1;
    }

    notify("Fuzzing %d devices...");

    for (int i = 0; i < num_devices; i++) {
        fuzz_device_ioctls(&devices[i]);
    }

    /* Close all devices */
    for (int i = 0; i < num_devices; i++) {
        close(devices[i].fd);
    }

    log_send("\n[*] IOCTL fuzzing complete\n");
    notify("IOCTL Fuzzer done!");

    if (log_fd >= 0) close(log_fd);
    return 0;
}
