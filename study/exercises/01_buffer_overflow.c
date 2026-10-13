/*
 * Exercise 01: Buffer Overflow Basics
 *
 * Tujuan: Pahami stack layout dan bagaimana overflow terjadi.
 *
 * Compile (disable protections for learning):
 *   gcc -fno-stack-protector -z execstack -no-pie -o bof 01_buffer_overflow.c
 *
 * Run:
 *   ./bof
 *   ./bof $(python3 -c "print('A'*80)")
 *
 * Tasks:
 *   1. Run normally — observe output
 *   2. Run with 80 'A's — observe the crash
 *   3. Use GDB to find exact offset to return address
 *   4. Overwrite return address to call secret_function()
 *
 * GDB commands:
 *   gdb ./bof
 *   (gdb) disas vulnerable_function
 *   (gdb) break vulnerable_function
 *   (gdb) run AAAA...
 *   (gdb) info frame
 *   (gdb) x/20gx $rsp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void secret_function(void) {
    printf("\n[!] SECRET FUNCTION CALLED!\n");
    printf("[!] You successfully hijacked control flow.\n");
    printf("[!] In a real exploit, this would be shellcode or a ROP chain.\n\n");
    exit(0);
}

void vulnerable_function(const char *input) {
    char buffer[64];

    printf("[*] buffer is at:          %p\n", (void *)buffer);
    printf("[*] secret_function is at: %p\n", (void *)secret_function);
    printf("[*] Copying %zu bytes into 64-byte buffer...\n", strlen(input));

    strcpy(buffer, input);

    printf("[*] buffer contents: %.64s\n", buffer);
}

int main(int argc, char **argv) {
    printf("\n=== Buffer Overflow Exercise ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("\nTry:\n");
        printf("  %s hello\n", argv[0]);
        printf("  %s $(python3 -c \"print('A'*80)\")\n", argv[0]);
        printf("  %s $(python3 -c \"print('A'*72 + '<addr_of_secret>')\")\n",
               argv[0]);
        return 1;
    }

    vulnerable_function(argv[1]);

    printf("\n[*] Normal return from vulnerable_function.\n");
    return 0;
}
