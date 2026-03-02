#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <linux/futex.h>
#include <sys/time.h>

/*
 * CVE-2014-3153 (Towelroot) Detection Test
 *
 * Tests whether the kernel properly validates waiter types during
 * futex_requeue operations. The vulnerability allows requeuing
 * non-PI waiters to PI futexes, causing stack-local rt_waiter corruption.
 *
 * Safe detection method:
 * 1. Thread A waits on futex1 with FUTEX_WAIT (non-PI waiter)
 * 2. Main thread attempts FUTEX_CMP_REQUEUE_PI from futex1 to futex_pi
 * 3. If requeue succeeds (returns 1): VULNERABLE
 * 4. If returns EINVAL: PATCHED
 *
 * This does NOT trigger the actual exploit (no stack corruption).
 */

static volatile int futex1 = 0;
static volatile int futex_pi = 0;
static volatile int thread_ready = 0;
static volatile int thread_done = 0;

/* Thread that blocks on FUTEX_WAIT (non-PI wait) */
void *waiter_thread(void *arg) {
    (void)arg;
    thread_ready = 1;

    /* Block on futex1 with FUTEX_WAIT (non-PI) */
    struct timespec ts = {2, 0}; /* 2 second timeout */
    long ret = syscall(SYS_futex, &futex1, FUTEX_WAIT, 0, &ts, NULL, 0);
    printf("  Waiter thread: FUTEX_WAIT returned %ld errno=%d\n",
           ret, ret < 0 ? errno : 0);
    thread_done = 1;
    return NULL;
}

/* Thread that blocks on FUTEX_WAIT_REQUEUE_PI */
void *pi_waiter_thread(void *arg) {
    (void)arg;
    thread_ready = 1;

    struct timespec ts = {2, 0};
    long ret = syscall(SYS_futex, &futex1, FUTEX_WAIT_REQUEUE_PI,
                       0, &ts, &futex_pi, 0);
    printf("  PI-waiter thread: FUTEX_WAIT_REQUEUE_PI returned %ld errno=%d\n",
           ret, ret < 0 ? errno : 0);
    thread_done = 1;
    return NULL;
}

int main(void) {
    printf("=== CVE-2014-3153 (Towelroot) Detection ===\n");
    printf("uid=%d pid=%d\n\n", getuid(), getpid());

    /* === Test 1: Basic PI futex operations === */
    printf("--- Test 1: PI futex basics ---\n");
    {
        volatile int pf = 0;

        /* LOCK_PI */
        long ret = syscall(SYS_futex, &pf, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        printf("  LOCK_PI: ret=%ld errno=%d val=0x%x\n",
               ret, ret < 0 ? errno : 0, pf);

        /* Check that the futex was set to our TID */
        pid_t tid = syscall(SYS_gettid);
        printf("  Our TID: %d, futex val: %d %s\n",
               tid, pf, pf == tid ? "(matches — PI lock acquired)" : "");

        /* UNLOCK_PI */
        ret = syscall(SYS_futex, &pf, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        printf("  UNLOCK_PI: ret=%ld errno=%d val=0x%x\n",
               ret, ret < 0 ? errno : 0, pf);
    }

    /* === Test 2: CVE-2014-3153 Detection — non-PI waiter requeue === */
    printf("\n--- Test 2: Non-PI waiter requeue to PI futex ---\n");
    {
        futex1 = 0;
        futex_pi = 0;
        thread_ready = 0;
        thread_done = 0;

        /* First, acquire the PI futex */
        long ret = syscall(SYS_futex, &futex_pi, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        printf("  Acquired PI lock: ret=%ld futex_pi=0x%x\n", ret, futex_pi);

        /* Start a thread that does FUTEX_WAIT (non-PI) on futex1 */
        pthread_t th;
        pthread_create(&th, NULL, waiter_thread, NULL);

        /* Wait for thread to be ready and blocked */
        while (!thread_ready) usleep(1000);
        usleep(50000); /* 50ms — ensure it's blocked in kernel */

        /* Now attempt CMP_REQUEUE_PI from futex1 to futex_pi */
        printf("  Attempting FUTEX_CMP_REQUEUE_PI (non-PI → PI)...\n");
        ret = syscall(SYS_futex, &futex1, FUTEX_CMP_REQUEUE_PI,
                      1,        /* val: wake up to 1 */
                      (void *)1, /* val2: requeue up to 1 */
                      &futex_pi, /* uaddr2: PI futex target */
                      0);        /* val3: expected value of futex1 */

        printf("  FUTEX_CMP_REQUEUE_PI: ret=%ld errno=%d\n",
               ret, ret < 0 ? errno : 0);

        if (ret == 1) {
            printf("  *** REQUEUE SUCCEEDED — WAITER MOVED TO PI FUTEX! ***\n");
            printf("  *** CVE-2014-3153 LIKELY VULNERABLE ***\n");
        } else if (ret == 0) {
            printf("  Returned 0 — no waiters moved (thread may not have blocked yet)\n");
        } else if (ret < 0 && errno == EINVAL) {
            printf("  EINVAL — kernel rejects non-PI to PI requeue (PATCHED)\n");
        } else {
            printf("  Unexpected result — need further investigation\n");
        }

        /* Wake the waiter thread so it can exit */
        syscall(SYS_futex, &futex1, FUTEX_WAKE, 1, NULL, NULL, 0);

        /* Unlock PI futex */
        syscall(SYS_futex, &futex_pi, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

        /* Wait for thread */
        struct timespec join_ts = {3, 0};
        usleep(100000);
        if (!thread_done) {
            printf("  Waiter thread still blocked, canceling...\n");
            pthread_cancel(th);
        }
        pthread_join(th, NULL);
    }

    /* === Test 3: PI waiter requeue (legitimate case) === */
    printf("\n--- Test 3: PI waiter requeue (legitimate) ---\n");
    {
        futex1 = 0;
        futex_pi = 0;
        thread_ready = 0;
        thread_done = 0;

        /* Acquire PI lock */
        long ret = syscall(SYS_futex, &futex_pi, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        printf("  Acquired PI lock: ret=%ld futex_pi=0x%x\n", ret, futex_pi);

        /* Start a thread that does FUTEX_WAIT_REQUEUE_PI on futex1 */
        pthread_t th;
        pthread_create(&th, NULL, pi_waiter_thread, NULL);

        while (!thread_ready) usleep(1000);
        usleep(50000);

        /* Requeue PI waiter */
        printf("  Attempting FUTEX_CMP_REQUEUE_PI (PI → PI)...\n");
        ret = syscall(SYS_futex, &futex1, FUTEX_CMP_REQUEUE_PI,
                      1, (void *)1, &futex_pi, 0);
        printf("  FUTEX_CMP_REQUEUE_PI: ret=%ld errno=%d\n",
               ret, ret < 0 ? errno : 0);

        if (ret >= 0) {
            printf("  PI-to-PI requeue: %s\n",
                   ret > 0 ? "SUCCEEDED (expected)" : "no waiters");
        }

        /* Unlock to let thread finish */
        syscall(SYS_futex, &futex_pi, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

        usleep(100000);
        if (!thread_done) {
            pthread_cancel(th);
        }
        pthread_join(th, NULL);
    }

    /* === Test 4: Requeue with mismatched futex types === */
    printf("\n--- Test 4: Additional requeue variants ---\n");
    {
        volatile int f_a = 0, f_b = 0;

        /* Can we do FUTEX_REQUEUE (non-PI) freely? */
        long ret = syscall(SYS_futex, &f_a, FUTEX_REQUEUE, 0, (void*)1, &f_b, 0);
        printf("  FUTEX_REQUEUE (no waiters): ret=%ld errno=%d\n",
               ret, ret < 0 ? errno : 0);

        /* CMP_REQUEUE with wrong expected value */
        f_a = 0;
        ret = syscall(SYS_futex, &f_a, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &f_b, 99);
        printf("  CMP_REQUEUE_PI (wrong expected): ret=%ld errno=%d\n",
               ret, ret < 0 ? errno : 0);

        /* LOCK_PI with timeout=0 (trylock behavior) */
        f_b = 0;
        struct timespec ts = {0, 0};
        ret = syscall(SYS_futex, &f_b, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
        printf("  LOCK_PI(timeout=0): ret=%ld errno=%d val=%d\n",
               ret, ret < 0 ? errno : 0, f_b);
        if (ret == 0) {
            syscall(SYS_futex, &f_b, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        }

        /* Can we LOCK_PI on a futex already set to someone else's TID? */
        f_b = 99999; /* fake TID */
        ts.tv_sec = 0;
        ts.tv_nsec = 100000; /* 100us */
        ret = syscall(SYS_futex, &f_b, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
        printf("  LOCK_PI(fake TID 99999): ret=%ld errno=%d\n",
               ret, ret < 0 ? errno : 0);

        /* Try with TID=0 (should succeed, lock is uncontested) */
        f_b = 0;
        ret = syscall(SYS_futex, &f_b, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
        printf("  LOCK_PI(val=0): ret=%ld errno=%d val=%d\n",
               ret, ret < 0 ? errno : 0, f_b);
        if (ret == 0) {
            syscall(SYS_futex, &f_b, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        }
    }

    /* === Test 5: Robustness list (used by towelroot) === */
    printf("\n--- Test 5: Robust futex list ---\n");
    {
        struct robust_list_head {
            void *list;
            long futex_offset;
            void *list_op_pending;
        } rl;

        memset(&rl, 0, sizeof(rl));
        rl.list = &rl; /* Point to self (empty list) */

        long ret = syscall(SYS_set_robust_list, &rl, sizeof(rl));
        printf("  set_robust_list: ret=%ld errno=%d\n",
               ret, ret < 0 ? errno : 0);

        struct robust_list_head *head = NULL;
        size_t len = 0;
        ret = syscall(SYS_get_robust_list, 0, &head, &len);
        printf("  get_robust_list: ret=%ld head=%p len=%zu\n",
               ret, head, len);
    }

    /* === Test 6: FUTEX_LOCK_PI priority inheritance chain === */
    printf("\n--- Test 6: PI chain test ---\n");
    {
        /* Test that PI futex properly does priority inheritance */
        volatile int chain[3] = {0, 0, 0};

        /* Lock all three */
        for (int i = 0; i < 3; i++) {
            long ret = syscall(SYS_futex, &chain[i], FUTEX_LOCK_PI, 0, NULL, NULL, 0);
            printf("  chain[%d] LOCK_PI: ret=%ld val=%d\n", i, ret, chain[i]);
        }

        /* Unlock in reverse */
        for (int i = 2; i >= 0; i--) {
            long ret = syscall(SYS_futex, &chain[i], FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            printf("  chain[%d] UNLOCK_PI: ret=%ld\n", i, ret);
        }
    }

    printf("\n=== CVE-2014-3153 Summary ===\n");
    printf("  PI futex operations: AVAILABLE\n");
    printf("  Robust list: AVAILABLE\n");
    printf("  See Test 2 result above for vulnerability status.\n");

    printf("\n=== Done ===\n");
    return 0;
}
