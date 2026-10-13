/*
 * Exercise 03: Use-After-Free Demonstration
 *
 * Tujuan: Pahami UAF vulnerability dan bagaimana exploit-nya.
 * Ini adalah simplified version dari pola yang dipakai di Relapse
 * (aio_multi_wait UAF race condition).
 *
 * Compile:
 *   gcc -o uaf 03_uaf_demo.c
 *
 * Tasks:
 *   1. Run → observe normal behavior
 *   2. Uncomment the "EXPLOIT" section → observe hijack
 *   3. Study how heap reclamation works
 *   4. Think about how this maps to kernel UAF
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct network_handler {
    char name[32];
    void (*process)(const char *data);
    void (*cleanup)(void);
    int priority;
};

static void safe_process(const char *data) {
    printf("    [safe_process] Processing: %s\n", data);
}

static void safe_cleanup(void) {
    printf("    [safe_cleanup] Handler cleaned up.\n");
}

static void evil_function(const char *data) {
    printf("\n    [!!!] HIJACKED! evil_function called!\n");
    printf("    [!!!] In real exploit: this is shellcode/ROP trigger\n");
    printf("    [!!!] Argument was: %s\n\n", data);
}

static void demonstrate_normal(void) {
    printf("=== NORMAL OPERATION ===\n\n");

    struct network_handler *handler = malloc(sizeof(struct network_handler));
    strcpy(handler->name, "HTTP-Handler");
    handler->process = safe_process;
    handler->cleanup = safe_cleanup;
    handler->priority = 5;

    printf("[*] Handler '%s' created at %p\n", handler->name, (void *)handler);
    printf("[*] process() = %p (safe_process)\n", (void *)(uintptr_t)handler->process);
    printf("[*] Calling handler->process()...\n");
    handler->process("GET /index.html");

    handler->cleanup();
    free(handler);
    printf("[*] Handler freed.\n\n");
}

static void demonstrate_uaf(void) {
    printf("=== USE-AFTER-FREE VULNERABILITY ===\n\n");

    printf("[1] Allocate handler (same as normal)...\n");
    struct network_handler *handler = malloc(sizeof(struct network_handler));
    strcpy(handler->name, "HTTP-Handler");
    handler->process = safe_process;
    handler->cleanup = safe_cleanup;
    handler->priority = 5;
    printf("    Handler at %p, size=%zu bytes\n",
           (void *)handler, sizeof(*handler));

    printf("[2] Free the handler (but keep the pointer!)...\n");
    free(handler);
    printf("    handler is now a DANGLING POINTER: %p\n", (void *)handler);

    /*
     * === HEAP RECLAMATION ===
     * After free(), the allocator puts the chunk back in its free list.
     * A new malloc() of the same size will likely return the SAME address.
     * This is the core of heap feng shui.
     */
    printf("[3] Allocate evil data (same size = %zu bytes)...\n",
           sizeof(*handler));

    struct network_handler *evil = malloc(sizeof(struct network_handler));
    printf("    Evil allocation at %p\n", (void *)evil);

    if (evil == handler) {
        printf("    [!] SAME ADDRESS! Heap reclaimed the freed chunk.\n");
    }

    strcpy(evil->name, "EVIL-PAYLOAD");
    evil->process = evil_function;
    evil->cleanup = NULL;
    evil->priority = 0xdeadbeef;

    printf("[4] Using the DANGLING pointer (handler->process)...\n");
    printf("    handler->process is now: %p (was safe_process)\n",
           (void *)(uintptr_t)handler->process);

    handler->process("PWNED");

    printf("[*] UAF demonstrated. In kernel:\n");
    printf("    - The 'handler' would be a kernel object\n");
    printf("    - The 'evil' allocation uses sendmsg/pipe spray\n");
    printf("    - Function pointer hijack → kernel code execution\n\n");

    free(evil);
}

static void demonstrate_race_uaf(void) {
    printf("=== RACE CONDITION UAF (Relapse pattern) ===\n\n");

    printf("In the real Relapse exploit (aio_multi_wait):\n\n");

    printf("  Thread A (victim):           Thread B (attacker):\n");
    printf("  ─────────────────           ────────────────────\n");
    printf("  aio_multi_wait() called\n");
    printf("  → allocates aio_request\n");
    printf("  → req->callback = handler\n");
    printf("                               close(aio_fd)\n");
    printf("                               → triggers cleanup\n");
    printf("                               → free(aio_request)\n");
    printf("  → uses req->callback         \n");
    printf("  → CRASH (or hijack!)         spray heap here\n");
    printf("\n");

    printf("  Key insight:\n");
    printf("  - Thread A holds pointer to aio_request\n");
    printf("  - Thread B triggers free via close()\n");
    printf("  - Window between alloc and use = race window\n");
    printf("  - Attacker sprays heap during this window\n");
    printf("  - req->callback now points to attacker code\n\n");

    printf("  Kernel heap spray techniques:\n");
    printf("  - sendmsg() with msghdr (controlled data into kernel heap)\n");
    printf("  - pipe() buffers (known size allocations)\n");
    printf("  - setgroups() (control ucred allocation)\n");
    printf("  - knote/kevent (event structures)\n\n");
}

int main(void) {
    printf("\n=== Use-After-Free Exercise ===\n\n");

    demonstrate_normal();
    demonstrate_uaf();
    demonstrate_race_uaf();

    return 0;
}
