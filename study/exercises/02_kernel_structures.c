/*
 * Exercise 02: Understanding Kernel Structures
 *
 * Tujuan: Pahami structure kernel FreeBSD yang relevan untuk exploit.
 * Ini adalah simulasi — berjalan di userland, bukan kernel.
 *
 * Compile:
 *   gcc -o kstruct 02_kernel_structures.c
 *
 * Tasks:
 *   1. Understand the proc/ucred relationship
 *   2. Walk the simulated allproc list
 *   3. Find and modify your process's ucred (privilege escalation)
 *   4. Map this to real PS5 kernel (offsets in analyze_data.py)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Simplified FreeBSD kernel structures.
 * Real offsets differ, but the relationships are the same.
 */

struct ucred {
    uint32_t cr_uid;
    uint32_t cr_ruid;
    uint32_t cr_gid;
    uint32_t cr_rgid;
    uint32_t cr_ngroups;
    uint32_t cr_groups[16];
};

struct proc {
    struct proc *p_list_next;
    struct proc *p_list_prev;
    int p_pid;
    char p_comm[20];
    struct ucred *p_ucred;
    uint64_t p_flag;
};

static struct proc *allproc = NULL;

static struct proc *create_proc(int pid, const char *name,
                                uint32_t uid, uint32_t gid) {
    struct proc *p = calloc(1, sizeof(struct proc));
    struct ucred *cr = calloc(1, sizeof(struct ucred));

    p->p_pid = pid;
    strncpy(p->p_comm, name, sizeof(p->p_comm) - 1);
    cr->cr_uid = uid;
    cr->cr_ruid = uid;
    cr->cr_gid = gid;
    cr->cr_rgid = gid;
    cr->cr_ngroups = 1;
    cr->cr_groups[0] = gid;
    p->p_ucred = cr;

    p->p_list_next = allproc;
    if (allproc) allproc->p_list_prev = p;
    allproc = p;

    return p;
}

static void dump_proc(const struct proc *p) {
    printf("  PID %-5d %-16s uid=%-5u gid=%-5u @ %p\n",
           p->p_pid, p->p_comm,
           p->p_ucred->cr_uid, p->p_ucred->cr_gid, (void *)p);
}

static void walk_allproc(void) {
    printf("\n[*] Walking allproc list:\n");
    struct proc *p = allproc;
    while (p) {
        dump_proc(p);
        p = p->p_list_next;
    }
}

/*
 * Simulate kernel exploit: privilege escalation via ucred modification.
 * This is what happens after achieving kernel r/w:
 *   1. Read allproc pointer from known offset
 *   2. Walk linked list to find our PID
 *   3. Read p_ucred pointer
 *   4. Overwrite cr_uid and cr_groups to 0 (root/wheel)
 */
static int escalate_privileges(int target_pid) {
    printf("\n[*] === PRIVILEGE ESCALATION SIMULATION ===\n\n");

    printf("[1] Reading allproc from kernel data...\n");
    printf("    allproc = %p (offset 0x03589E80 in real PS5)\n",
           (void *)allproc);

    printf("[2] Walking proc list to find PID %d...\n", target_pid);
    struct proc *target = NULL;
    struct proc *p = allproc;
    int count = 0;
    while (p) {
        count++;
        if (p->p_pid == target_pid) {
            target = p;
            printf("    Found! proc @ %p (after %d hops)\n",
                   (void *)target, count);
            break;
        }
        p = p->p_list_next;
    }

    if (!target) {
        printf("    [!] PID %d not found\n", target_pid);
        return -1;
    }

    printf("[3] Reading ucred pointer...\n");
    printf("    ucred @ %p\n", (void *)target->p_ucred);
    printf("    Current: uid=%u gid=%u\n",
           target->p_ucred->cr_uid, target->p_ucred->cr_gid);

    printf("[4] Overwriting ucred (kernel_write primitive)...\n");
    target->p_ucred->cr_uid = 0;
    target->p_ucred->cr_ruid = 0;
    target->p_ucred->cr_gid = 0;
    target->p_ucred->cr_rgid = 0;
    target->p_ucred->cr_groups[0] = 0;
    printf("    Written: uid=0 gid=0 (root:wheel)\n");

    printf("[5] Verifying...\n");
    dump_proc(target);
    printf("    Privilege escalation %s!\n\n",
           target->p_ucred->cr_uid == 0 ? "SUCCESSFUL" : "FAILED");

    return 0;
}

static void cleanup(void) {
    struct proc *p = allproc;
    while (p) {
        struct proc *next = p->p_list_next;
        free(p->p_ucred);
        free(p);
        p = next;
    }
}

int main(void) {
    printf("\n=== Kernel Structures Exercise ===\n");
    printf("    Simulating FreeBSD proc/ucred for PS5 research\n");

    create_proc(0,    "kernel",     0, 0);
    create_proc(1,    "init",       0, 0);
    create_proc(42,   "SceShellUI", 1, 1);
    create_proc(100,  "WebKit",     1000, 1000);
    create_proc(200,  "game.elf",   1001, 1001);
    create_proc(1337, "exploit",    1000, 1000);

    walk_allproc();

    escalate_privileges(1337);

    printf("[*] After escalation, full process list:\n");
    walk_allproc();

    cleanup();
    return 0;
}
