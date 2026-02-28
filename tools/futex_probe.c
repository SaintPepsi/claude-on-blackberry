/*
 * futex_probe.c — Test for CVE-2014-3153 (Towelroot) vulnerability
 *
 * CVE-2014-3153 is a futex_requeue bug where FUTEX_CMP_REQUEUE_PI allows
 * requeueing a non-PI waiter onto a PI futex, creating a dangling pointer
 * in the kernel's rt_waiter structure.
 *
 * This probe tests the specific syscall sequence that triggers the bug
 * WITHOUT attempting exploitation. If the kernel returns EINVAL on the
 * requeue, the bug is PATCHED. If the requeue succeeds (returns 1),
 * the bug EXISTS.
 *
 * SAFETY: This probe only tests the syscall behavior. It does not
 * attempt to corrupt kernel memory or escalate privileges.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>

/* Futex operations */
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI    12
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI   11
#endif
#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI           6
#endif
#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI         7
#endif

static int futex1 = 0;  /* Non-PI futex (source) */
static int futex2 = 0;  /* PI futex (destination) */
static volatile int waiter_ready = 0;

static long sys_futex(void *addr, int op, int val, void *timeout,
                      void *addr2, int val3) {
    return syscall(SYS_futex, addr, op, val, timeout, addr2, val3);
}

static void *waiter_thread(void *arg) {
    (void)arg;
    waiter_ready = 1;

    /* Wait on futex1 with FUTEX_WAIT_REQUEUE_PI
     * This puts us on futex1's wait queue but expects to be
     * requeued to a PI futex (futex2). */
    long ret = sys_futex(&futex1, FUTEX_WAIT_REQUEUE_PI, futex1,
                         NULL, &futex2, 0);
    printf("  waiter: FUTEX_WAIT_REQUEUE_PI returned %ld (errno=%d)\n",
           ret, errno);
    return NULL;
}

int main(void) {
    printf("=== CVE-2014-3153 (Towelroot/Futex) PROBE ===\n");
    printf("uid=%u, kernel should be 3.10.84\n\n", getuid());

    /* Method 1: Direct FUTEX_CMP_REQUEUE_PI test
     * The bug: kernel allows requeueing a FUTEX_WAIT waiter (non-PI)
     * onto a PI futex via FUTEX_CMP_REQUEUE_PI. The fix adds a check
     * that the waiter must have been waiting via FUTEX_WAIT_REQUEUE_PI. */

    printf("--- Test 1: FUTEX_CMP_REQUEUE_PI basic behavior ---\n");
    {
        /* Try CMP_REQUEUE_PI with no waiters */
        futex1 = 0;
        futex2 = 0;
        errno = 0;
        long ret = sys_futex(&futex1, FUTEX_CMP_REQUEUE_PI, 0,
                             (void *)1, &futex2, futex1);
        printf("  CMP_REQUEUE_PI (no waiters): ret=%ld errno=%d (%s)\n",
               ret, errno, strerror(errno));
        if (ret == 0) {
            printf("  -> Requeue returned 0 (no waiters to move). Expected.\n");
        } else if (errno == ENOSYS) {
            printf("  -> ENOSYS: FUTEX_CMP_REQUEUE_PI not supported!\n");
            printf("  -> Cannot test this vulnerability.\n");
            return 1;
        }
    }

    printf("\n--- Test 2: FUTEX_WAIT_REQUEUE_PI + CMP_REQUEUE_PI ---\n");
    {
        futex1 = 0;
        futex2 = 0;
        waiter_ready = 0;

        pthread_t tid;
        if (pthread_create(&tid, NULL, waiter_thread, NULL) != 0) {
            printf("  pthread_create failed: %s\n", strerror(errno));
            return 1;
        }

        /* Wait for waiter to be ready */
        while (!waiter_ready) usleep(1000);
        usleep(50000); /* Extra time for futex wait to engage */

        /* Now try to requeue the waiter from futex1 to futex2 */
        errno = 0;
        long ret = sys_futex(&futex1, FUTEX_CMP_REQUEUE_PI, 0,
                             (void *)1, &futex2, futex1);
        printf("  CMP_REQUEUE_PI (1 waiter): ret=%ld errno=%d (%s)\n",
               ret, errno, strerror(errno));

        if (ret == 1) {
            printf("  -> *** REQUEUE SUCCEEDED (1 waiter moved) ***\n");
            printf("  -> This is EXPECTED behavior for PI waiters.\n");
            /* Wake the requeued waiter */
            sys_futex(&futex2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (ret < 0 && errno == EINVAL) {
            printf("  -> EINVAL: Requeue rejected.\n");
        }

        pthread_join(tid, NULL);
    }

    /* Test 3: The actual vulnerability — FUTEX_WAIT (non-PI) then
     * CMP_REQUEUE_PI. In unpatched kernels, this creates the dangling
     * waiter. In patched kernels, it returns -EINVAL. */
    printf("\n--- Test 3: NON-PI FUTEX_WAIT + CMP_REQUEUE_PI (THE BUG) ---\n");
    {
        int npi_futex = 0;  /* Non-PI source */
        int pi_futex = 0;   /* PI destination */

        /* We need a thread doing FUTEX_WAIT (non-PI) on npi_futex */
        /* Then we try FUTEX_CMP_REQUEUE_PI from npi_futex to pi_futex */

        /* Since FUTEX_WAIT blocks, use a timeout approach */
        /* Actually, let's just try the requeue on an empty queue first
         * with a non-PI futex. The interesting thing is whether the
         * kernel even validates the futex type. */

        npi_futex = 0;
        pi_futex = 0;

        /* First, put a waiter on npi_futex via plain FUTEX_WAIT */
        /* We'll do this in a thread with a timeout */
        volatile int ready3 = 0;
        struct {
            int *futex;
            volatile int *ready;
        } args = { &npi_futex, &ready3 };

        pthread_t tid3;
        pthread_create(&tid3, NULL, (void*(*)(void*))({
            void *fn(void *a) {
                struct { int *futex; volatile int *ready; } *p = a;
                *(p->ready) = 1;
                /* Plain FUTEX_WAIT (non-PI!) */
                struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
                long r = sys_futex(p->futex, FUTEX_WAIT, 0, &ts, NULL, 0);
                printf("  non-PI waiter: FUTEX_WAIT returned %ld (errno=%d)\n",
                       r, errno);
                return NULL;
            }
            fn;
        }), &args);

        while (!ready3) usleep(1000);
        usleep(50000);

        /* Now try to requeue the NON-PI waiter onto a PI futex
         * THIS IS THE CVE-2014-3153 BUG TEST */
        errno = 0;
        long ret = sys_futex(&npi_futex, FUTEX_CMP_REQUEUE_PI, 0,
                             (void *)1, &pi_futex, npi_futex);
        printf("  CMP_REQUEUE_PI (non-PI waiter -> PI): ret=%ld errno=%d (%s)\n",
               ret, errno, strerror(errno));

        if (ret == 1) {
            printf("\n  ****************************************************\n");
            printf("  * CVE-2014-3153 IS PRESENT — FUTEX BUG EXISTS!    *\n");
            printf("  * Non-PI waiter was requeued to PI futex.          *\n");
            printf("  * This kernel is vulnerable to Towelroot.          *\n");
            printf("  ****************************************************\n\n");
            /* Clean up — unlock the PI futex to release the waiter */
            sys_futex(&pi_futex, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        } else if (errno == EINVAL) {
            printf("\n  -> CVE-2014-3153 is PATCHED.\n");
            printf("  -> Kernel correctly rejects non-PI waiter requeue.\n");
        } else {
            printf("\n  -> Unexpected result. ret=%ld errno=%d\n", ret, errno);
        }

        /* Wake any remaining waiter */
        npi_futex = 1;
        sys_futex(&npi_futex, FUTEX_WAKE, 1, NULL, NULL, 0);
        pthread_join(tid3, NULL);
    }

    printf("\n=== FUTEX PROBE COMPLETE ===\n");
    return 0;
}
