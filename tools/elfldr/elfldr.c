/*
 * PS5 ELF Loader v1.0
 *
 * Standalone TCP-based ELF loader for PS5 security research.
 * Listens on a configurable port (default 9021), receives ELF payloads
 * over TCP, maps them into memory, and executes them.
 *
 * Built with ps5-payload-dev SDK.
 * Usage: load this as a payload via Relapse or any exploit,
 *        then send ELF files via: nc <PS5_IP> 9021 < payload.elf
 *
 * Features:
 *  - Persistent listener (keeps accepting after each payload)
 *  - Proper ELF parsing (PT_LOAD segments)
 *  - Threaded execution (each payload runs in its own thread)
 *  - PS5 notification on load/error
 *  - Connection timeout to avoid hangs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <elf.h>

#include <ps5/kernel.h>
#include <ps5/payload.h>

#define LISTEN_PORT     9021
#define MAX_ELF_SIZE    (64 * 1024 * 1024)
#define RECV_BUF_SIZE   65536
#define RECV_TIMEOUT_S  30
#define MAX_PAYLOADS    256

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

static void notify(const char *fmt, ...) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);

    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);
}

typedef struct {
    void     *base;
    size_t    total_size;
    uintptr_t entry;
} loaded_elf_t;

static int load_elf(const uint8_t *buf, size_t size, loaded_elf_t *out) {
    if (size < sizeof(Elf64_Ehdr)) {
        log_msg("[!] ELF too small: %zu bytes\n", size);
        return -1;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)buf;

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        log_msg("[!] Not an ELF file (bad magic)\n");
        return -1;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        log_msg("[!] Not a 64-bit ELF\n");
        return -1;
    }

    if (ehdr->e_machine != EM_X86_64) {
        log_msg("[!] Not x86_64 ELF (machine=%d)\n", ehdr->e_machine);
        return -1;
    }

    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
        log_msg("[!] No program headers\n");
        return -1;
    }

    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size) {
        log_msg("[!] Program headers extend past file\n");
        return -1;
    }

    const Elf64_Phdr *phdr = (const Elf64_Phdr *)(buf + ehdr->e_phoff);

    uintptr_t vaddr_min = UINTPTR_MAX;
    uintptr_t vaddr_max = 0;
    int load_count = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;
        load_count++;

        uintptr_t seg_start = phdr[i].p_vaddr;
        uintptr_t seg_end = seg_start + phdr[i].p_memsz;

        if (seg_start < vaddr_min) vaddr_min = seg_start;
        if (seg_end > vaddr_max)   vaddr_max = seg_end;
    }

    if (load_count == 0) {
        log_msg("[!] No PT_LOAD segments\n");
        return -1;
    }

    vaddr_min &= ~0xFFFULL;
    vaddr_max = (vaddr_max + 0xFFF) & ~0xFFFULL;
    size_t total_size = vaddr_max - vaddr_min;

    void *base = mmap(NULL, total_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        log_msg("[!] mmap failed: %zu bytes\n", total_size);
        return -1;
    }

    memset(base, 0, total_size);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD)
            continue;

        uintptr_t offset_in_map = phdr[i].p_vaddr - vaddr_min;
        size_t filesz = phdr[i].p_filesz;

        if (phdr[i].p_offset + filesz > size) {
            log_msg("[!] Segment %d extends past file\n", i);
            munmap(base, total_size);
            return -1;
        }

        memcpy((uint8_t *)base + offset_in_map,
               buf + phdr[i].p_offset,
               filesz);

        log_msg("    LOAD[%d]: vaddr=0x%lx memsz=0x%lx filesz=0x%lx\n",
                i, (unsigned long)phdr[i].p_vaddr,
                (unsigned long)phdr[i].p_memsz,
                (unsigned long)filesz);
    }

    uintptr_t entry = (uintptr_t)base + (ehdr->e_entry - vaddr_min);

    out->base = base;
    out->total_size = total_size;
    out->entry = entry;

    log_msg("[+] ELF loaded: base=%p size=0x%lx entry=%p\n",
            base, (unsigned long)total_size, (void *)entry);

    return 0;
}

typedef struct {
    loaded_elf_t elf;
    int payload_num;
} thread_arg_t;

static void *payload_thread(void *arg) {
    thread_arg_t *ta = (thread_arg_t *)arg;

    log_msg("[*] Payload #%d: executing entry at %p\n",
            ta->payload_num, (void *)ta->elf.entry);

    typedef int (*entry_fn_t)(void);
    entry_fn_t entry = (entry_fn_t)ta->elf.entry;

    int ret = entry();
    log_msg("[*] Payload #%d: returned %d\n", ta->payload_num, ret);

    free(ta);
    return NULL;
}

static uint8_t *recv_elf(int client_fd, size_t *out_size) {
    struct timeval tv = { .tv_sec = RECV_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t capacity = RECV_BUF_SIZE;
    size_t total = 0;
    uint8_t *buf = malloc(capacity);
    if (!buf) return NULL;

    while (total < MAX_ELF_SIZE) {
        ssize_t n = recv(client_fd, buf + total, capacity - total, 0);
        if (n <= 0) break;
        total += n;

        if (total >= capacity) {
            size_t new_cap = capacity * 2;
            if (new_cap > MAX_ELF_SIZE) new_cap = MAX_ELF_SIZE;
            uint8_t *nb = realloc(buf, new_cap);
            if (!nb) break;
            buf = nb;
            capacity = new_cap;
        }
    }

    if (total == 0) {
        free(buf);
        return NULL;
    }

    *out_size = total;
    return buf;
}

int main(void) {
    log_msg("\n=== PS5 ELF Loader v1.0 ===\n\n");

    notify("ELF Loader v1.0 starting on port %d", LISTEN_PORT);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        log_msg("[!] socket() failed\n");
        notify("ELF Loader: socket failed");
        return 1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg("[!] bind() failed (port %d in use?)\n", LISTEN_PORT);
        notify("ELF Loader: port %d in use", LISTEN_PORT);
        close(srv);
        return 1;
    }

    if (listen(srv, 5) < 0) {
        log_msg("[!] listen() failed\n");
        close(srv);
        return 1;
    }

    log_msg("[+] Listening on 0.0.0.0:%d\n", LISTEN_PORT);
    log_msg("[*] Send ELF payloads via: nc <PS5_IP> %d < payload.elf\n\n", LISTEN_PORT);
    notify("ELF Loader ready on port %d", LISTEN_PORT);

    int payload_count = 0;

    while (payload_count < MAX_PAYLOADS) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client = accept(srv, (struct sockaddr *)&client_addr, &client_len);
        if (client < 0) {
            log_msg("[!] accept() failed\n");
            continue;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
        log_msg("[+] Connection from %s\n", ip_str);

        size_t elf_size = 0;
        uint8_t *elf_data = recv_elf(client, &elf_size);
        close(client);

        if (!elf_data) {
            log_msg("[!] Empty or failed receive\n");
            continue;
        }

        log_msg("[+] Received %zu bytes\n", elf_size);

        loaded_elf_t loaded;
        if (load_elf(elf_data, elf_size, &loaded) < 0) {
            log_msg("[!] ELF load failed\n");
            notify("ELF Loader: load failed (%zu bytes)", elf_size);
            free(elf_data);
            continue;
        }
        free(elf_data);

        payload_count++;
        notify("Payload #%d loaded (%zu KB)", payload_count, elf_size / 1024);

        thread_arg_t *ta = malloc(sizeof(thread_arg_t));
        if (!ta) {
            log_msg("[!] malloc failed for thread arg\n");
            continue;
        }
        ta->elf = loaded;
        ta->payload_num = payload_count;

        pthread_t tid;
        if (pthread_create(&tid, NULL, payload_thread, ta) != 0) {
            log_msg("[!] pthread_create failed, running inline\n");
            payload_thread(ta);
        } else {
            pthread_detach(tid);
            log_msg("[+] Payload #%d launched in thread\n", payload_count);
        }
    }

    close(srv);
    log_msg("[*] ELF Loader shutting down (max payloads reached)\n");
    notify("ELF Loader: max payloads reached");

    return 0;
}
