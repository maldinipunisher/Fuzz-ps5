/*
 * PS5 Kernel Memory Dumper v0.8 — DATA-only, safe
 *
 * Dumps large kernel DATA section (up to 64 MB).
 * No PTE modification, no TEXT read attempts.
 * Probes each 1MB region before dumping to avoid unmapped pages.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ps5/kernel.h>

#define PC_IP       "192.168.100.24"
#define PC_PORT     9023
#define CHUNK_SIZE  0x1000    // 4KB per read
#define PROBE_STEP  0x100000  // 1MB probe step

int main(void) {
    printf("\n=== PS5 Kernel Dumper v0.8 (DATA safe) ===\n\n");

    uint32_t fw = kernel_get_fw_version();
    printf("[+] FW: %x.%02x\n", fw >> 16, (fw >> 8) & 0xff);

    intptr_t text_base = KERNEL_ADDRESS_TEXT_BASE;
    intptr_t data_base = KERNEL_ADDRESS_DATA_BASE;
    printf("[+] text: 0x%lx\n", (unsigned long)text_base);
    printf("[+] data: 0x%lx\n", (unsigned long)data_base);

    if (!data_base) {
        printf("[!] Missing data base\n");
        return 1;
    }

    // Probe DATA to find how far it extends
    printf("\n[*] Probing DATA extent (1 MB steps)...\n");

    size_t max_data = 64 * 1024 * 1024; // Try up to 64 MB
    size_t data_size = 0;
    uint8_t probe[8];

    for (size_t off = 0; off < max_data; off += PROBE_STEP) {
        if (kernel_copyout(data_base + off, probe, 8) == 0) {
            data_size = off + PROBE_STEP;
            if ((off % (4 * PROBE_STEP)) == 0) {
                printf("    0x%06lx: OK (%02x%02x%02x%02x)\n",
                       (unsigned long)off,
                       probe[0], probe[1], probe[2], probe[3]);
            }
        } else {
            printf("    0x%06lx: END\n", (unsigned long)off);
            break;
        }
    }

    if (data_size == 0) {
        printf("[!] Cannot read DATA at all\n");
        return 1;
    }

    printf("\n[+] DATA size: 0x%lx (%lu MB)\n",
           (unsigned long)data_size, (unsigned long)(data_size >> 20));

    // Show known offset locations
    size_t allproc_off = 0x03589E80 - 0x00CC0000;  // relative to DATA
    size_t rootvnode_off = 0x03E0B510 - 0x00CC0000;

    printf("\n[*] Key offsets:\n");
    if (allproc_off < data_size) {
        kernel_copyout(data_base + allproc_off, probe, 8);
        uint64_t val = *(uint64_t *)probe;
        printf("    ALLPROC:   data+0x%lx ✓ (val=0x%lx)\n",
               (unsigned long)allproc_off, (unsigned long)val);
    } else {
        printf("    ALLPROC:   data+0x%lx ✗ (beyond %lu MB dump)\n",
               (unsigned long)allproc_off, (unsigned long)(data_size >> 20));
    }

    if (rootvnode_off < data_size) {
        kernel_copyout(data_base + rootvnode_off, probe, 8);
        uint64_t val = *(uint64_t *)probe;
        printf("    ROOTVNODE: data+0x%lx ✓ (val=0x%lx)\n",
               (unsigned long)rootvnode_off, (unsigned long)val);
    } else {
        printf("    ROOTVNODE: data+0x%lx ✗ (beyond %lu MB dump)\n",
               (unsigned long)rootvnode_off, (unsigned long)(data_size >> 20));
    }

    // Connect and dump
    printf("\n[*] Connecting to %s:%d...\n", PC_IP, PC_PORT);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { printf("[!] socket failed\n"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PC_PORT);
    inet_pton(AF_INET, PC_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[!] connect failed\n");
        close(sock);
        return 1;
    }
    printf("[+] Connected\n");

    // Header: text_base=0, text_size=0 (no TEXT), data_base, data_size
    uint64_t hdr[4] = { 0, 0, (uint64_t)data_base, (uint64_t)data_size };
    send(sock, hdr, sizeof(hdr), 0);

    // Dump DATA
    printf("[*] Dumping DATA: 0x%lx (%lu MB)\n",
           (unsigned long)data_base, (unsigned long)(data_size >> 20));

    uint8_t *buf = malloc(CHUNK_SIZE);
    if (!buf) { close(sock); return 1; }

    size_t total = 0;
    size_t skipped = 0;

    for (size_t off = 0; off < data_size; off += CHUNK_SIZE) {
        size_t chunk = CHUNK_SIZE;
        if (off + chunk > data_size)
            chunk = data_size - off;

        if (kernel_copyout(data_base + off, buf, chunk) < 0) {
            memset(buf, 0, chunk);
            skipped++;
        }

        if (write(sock, buf, chunk) < 0) {
            printf("\n[!] write failed at 0x%lx\n", (unsigned long)off);
            break;
        }
        total += chunk;

        if ((off % 0x100000) == 0) {
            printf("\r    %lu / %lu MB",
                   (unsigned long)(total >> 20),
                   (unsigned long)(data_size >> 20));
            if (skipped > 0)
                printf(" (%lu skipped)", (unsigned long)skipped);
            fflush(stdout);
        }
    }

    printf("\r    %lu / %lu MB done", (unsigned long)(total >> 20),
           (unsigned long)(data_size >> 20));
    if (skipped > 0)
        printf(" (%lu pages skipped)", (unsigned long)skipped);
    printf("\n");

    free(buf);
    close(sock);

    printf("\n[*] Done.\n");
    printf("[*] Ghidra base: 0x%lx\n", (unsigned long)data_base);

    return 0;
}
