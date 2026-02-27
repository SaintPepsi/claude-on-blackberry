/*
 * Ralph Wiggum KGSL Fuzzer
 * "I'm in danger!" -- Ralph Wiggum
 *
 * Dumb-persistent ioctl fuzzer for /dev/kgsl-3d0 (Qualcomm Adreno GPU).
 * Targets BlackBerry Priv (Snapdragon 808, kernel 3.10.84, Oct 2017 patches).
 *
 * Phase 1: Enumerate valid ioctl numbers (which ones does the driver accept?)
 * Phase 2: Mutation-fuzz the valid ones with random data
 *
 * Any crash signal (SIGSEGV, SIGBUS) during an ioctl = potential kernel bug.
 * Any ioctl returning 0 with weird data = potential info leak or state corruption.
 *
 * Usage: ./ralph [max_rounds] [phase]
 *   max_rounds: mutation rounds (default 100000)
 *   phase: 1 = discovery only, 2 = both (default 2)
 *
 * Compile: gcc -static -O2 -o ralph ralph.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <setjmp.h>
#include <sys/ioctl.h>

#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOC_TYPE 0x09

/* ioctl encoding (Linux convention) */
#define MY_IOC(dir,type,nr,size) \
    (((dir) << 30) | ((size) << 16) | ((type) << 8) | (nr))

/* Signal recovery */
static sigjmp_buf jmp;
static volatile sig_atomic_t caught_sig = 0;

static void sighandler(int sig) {
    caught_sig = sig;
    siglongjmp(jmp, sig);
}

/* xorshift64 PRNG */
static unsigned long long rng;

static unsigned long long rand64(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static void fill_rand(void *p, int n) {
    unsigned long long *q = p;
    int i;
    for (i = 0; i + 8 <= n; i += 8)
        q[i/8] = rand64();
    if (i < n) {
        unsigned long long v = rand64();
        memcpy((char*)p + i, &v, n - i);
    }
}

/* Logging */
static FILE *logfp;

static void lg(const char *phase, unsigned long cmd, int ret, int err,
               int nr, int dir, int sz, const char *tag) {
    fprintf(logfp,
        "%s | cmd=0x%08lx nr=0x%02x dir=%d sz=%3d | ret=%d err=%d(%s) | %s\n",
        phase, cmd, nr, dir, sz, ret, err, strerror(err), tag);
    fflush(logfp);
    printf("%s | nr=0x%02x dir=%d sz=%3d | ret=%d err=%s | %s\n",
        phase, nr, dir, sz, ret, strerror(err), tag);
    fflush(stdout);
}

static int reopen(void) {
    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0)
        printf("!! reopen failed: %s\n", strerror(errno));
    return fd;
}

int main(int argc, char **argv) {
    int max_rounds = 100000;
    int run_phase2 = 1;
    int fd, ret;
    unsigned int nr, dir, sz;
    unsigned long cmd;
    unsigned char buf[4096];

    /* Interesting ioctl numbers from Phase 1 */
    int valid[256];
    int valid_dir[256];
    int valid_sz[256];
    int n_valid = 0;

    if (argc > 1) max_rounds = atoi(argv[1]);
    if (argc > 2 && argv[2][0] == '1') run_phase2 = 0;

    rng = (unsigned long long)time(NULL) ^ ((unsigned long long)getpid() << 16);

    /* Log to file and stdout */
    logfp = fopen("/data/data/com.termux/files/home/ralph.log", "w");
    if (!logfp) logfp = fopen("ralph.log", "w");
    if (!logfp) logfp = stdout;

    printf("=============================================\n");
    printf("  Ralph Wiggum KGSL Fuzzer\n");
    printf("  \"I'm in danger!\" -- Ralph Wiggum\n");
    printf("=============================================\n");
    printf("Target: %s\n", KGSL_DEVICE);
    printf("PID: %d\n", getpid());
    printf("Max rounds: %d\n", max_rounds);
    printf("Phase 2: %s\n\n", run_phase2 ? "YES" : "NO (discovery only)");

    fprintf(logfp, "=== Ralph Wiggum KGSL Fuzzer ===\n");
    fprintf(logfp, "Target: %s | PID: %d | Rounds: %d\n\n",
            KGSL_DEVICE, getpid(), max_rounds);

    /* Signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighandler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    /* Open device */
    fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("FATAL: open(%s): %s\n", KGSL_DEVICE, strerror(errno));
        return 1;
    }
    printf("Opened %s fd=%d\n\n", KGSL_DEVICE, fd);

    /* ========== PHASE 1: DISCOVERY ========== */
    printf("--- PHASE 1: DISCOVERY ---\n");
    printf("Scanning ioctl type 0x%02x, nr 0x00-0x7F, 4 directions, 9 sizes\n\n",
           KGSL_IOC_TYPE);
    fprintf(logfp, "--- PHASE 1: DISCOVERY ---\n");

    memset(valid, 0, sizeof(valid));

    unsigned int sizes[] = {0, 4, 8, 16, 32, 64, 128, 256, 512};
    int nsizes = sizeof(sizes)/sizeof(sizes[0]);

    for (nr = 0; nr < 0x80; nr++) {
        for (dir = 0; dir < 4; dir++) {
            int si;
            for (si = 0; si < nsizes; si++) {
                sz = sizes[si];
                cmd = MY_IOC(dir, KGSL_IOC_TYPE, nr, sz);
                memset(buf, 0, sizeof(buf));
                caught_sig = 0;

                if (sigsetjmp(jmp, 1) == 0) {
                    errno = 0;
                    ret = ioctl(fd, cmd, buf);

                    if (ret != -1 || (errno != ENOTTY && errno != EBADF)) {
                        if (!valid[nr]) {
                            valid[nr] = 1;
                            valid_dir[nr] = dir;
                            valid_sz[nr] = sz;
                            n_valid++;
                        }
                        lg("DISC", cmd, ret, errno, nr, dir, sz,
                           ret == 0 ? "** ACCEPTED **" : "** RECOGNIZED **");
                    }
                } else {
                    lg("DISC", cmd, -1, 0, nr, dir, sz,
                       "!! CRASH SIGNAL -- EXPLOITABLE? !!");
                    close(fd);
                    fd = reopen();
                    if (fd < 0) return 2;
                }
            }
        }
    }

    printf("\n=== Phase 1 complete: %d valid ioctl numbers ===\n", n_valid);
    fprintf(logfp, "\n=== Phase 1: %d valid ioctl numbers ===\n\n", n_valid);

    if (n_valid == 0) {
        printf("No ioctls accepted. SELinux is blocking everything.\n");
        printf("The bounty remains unclaimed. Ralph is safe.\n");
        close(fd);
        if (logfp != stdout) fclose(logfp);
        return 0;
    }

    /* Print summary of valid ioctls */
    printf("\nValid ioctls:\n");
    fprintf(logfp, "Valid ioctls:\n");
    for (nr = 0; nr < 0x80; nr++) {
        if (valid[nr]) {
            printf("  nr=0x%02x (best: dir=%d sz=%d)\n", nr, valid_dir[nr], valid_sz[nr]);
            fprintf(logfp, "  nr=0x%02x dir=%d sz=%d\n", nr, valid_dir[nr], valid_sz[nr]);
        }
    }
    printf("\n");
    fflush(logfp);

    if (!run_phase2) {
        printf("Phase 1 only. Exiting.\n");
        close(fd);
        if (logfp != stdout) fclose(logfp);
        return 0;
    }

    /* ========== PHASE 2: MUTATION FUZZING ========== */
    printf("--- PHASE 2: MUTATION FUZZING (%d rounds) ---\n\n", max_rounds);
    fprintf(logfp, "\n--- PHASE 2: MUTATION (%d rounds) ---\n", max_rounds);

    int crashes = 0, successes = 0, unusual = 0;
    int round;

    for (round = 0; round < max_rounds; round++) {
        /* Pick random valid ioctl */
        int pick;
        do { pick = rand64() % 0x80; } while (!valid[pick]);

        /* Random parameters */
        dir = rand64() % 4;
        unsigned int sz_opts[] = {4, 8, 12, 16, 20, 24, 28, 32, 48, 64,
                                  96, 128, 192, 256, 384, 512, 1024, 2048, 4096};
        sz = sz_opts[rand64() % (sizeof(sz_opts)/sizeof(sz_opts[0]))];
        cmd = MY_IOC(dir, KGSL_IOC_TYPE, pick, sz);

        /* Fill strategy */
        int strat = rand64() % 7;
        switch (strat) {
            case 0: memset(buf, 0, sizeof(buf)); break;
            case 1: memset(buf, 0xFF, sizeof(buf)); break;
            case 2: memset(buf, 0x41, sizeof(buf)); break;
            case 3: fill_rand(buf, sizeof(buf)); break;
            case 4: /* Incrementing ints */
                { unsigned int *p = (unsigned int*)buf;
                  int i; for (i=0; i<1024; i++) p[i] = i; }
                break;
            case 5: /* Edge-case integers */
                { unsigned int *p = (unsigned int*)buf;
                  unsigned int edges[] = {0,1,2,0x7FFFFFFF,0x80000000,
                    0xFFFFFFFF,0xFFFFFFFE,0x1000,0x10000,4096,65536};
                  int i; for (i=0; i<1024; i++)
                    p[i] = edges[rand64() % (sizeof(edges)/sizeof(edges[0]))]; }
                break;
            case 6: /* Pointer-like values */
                { unsigned long long *p = (unsigned long long*)buf;
                  unsigned long long ptrs[] = {0, 0xDEADBEEF, 0x4141414141414141ULL,
                    0xffffffc000000000ULL, 0x7f00000000ULL, (unsigned long long)-1,
                    0x1000, 0x2000, 0x4000};
                  int i; for (i=0; i<512; i++)
                    p[i] = ptrs[rand64() % (sizeof(ptrs)/sizeof(ptrs[0]))]; }
                break;
        }

        caught_sig = 0;

        if (sigsetjmp(jmp, 1) == 0) {
            errno = 0;
            ret = ioctl(fd, cmd, buf);

            if (ret == 0) {
                successes++;
                char tag[64];
                snprintf(tag, sizeof(tag), "** SUCCESS s=%d **", strat);
                lg("FUZZ", cmd, ret, errno, pick, dir, sz, tag);
            } else if (errno != EINVAL && errno != EFAULT &&
                       errno != ENOTTY && errno != EBADF && errno != ENODEV) {
                unusual++;
                char tag[64];
                snprintf(tag, sizeof(tag), "** UNUSUAL s=%d **", strat);
                lg("FUZZ", cmd, ret, errno, pick, dir, sz, tag);
            }
        } else {
            crashes++;
            char tag[80];
            snprintf(tag, sizeof(tag),
                "!! CRASH sig=%d s=%d !! POTENTIAL EXPLOIT VECTOR", caught_sig, strat);
            lg("FUZZ", cmd, -1, 0, pick, dir, sz, tag);

            close(fd);
            usleep(50000);
            fd = reopen();
            if (fd < 0) {
                printf("FATAL: kernel may be damaged after %d rounds\n", round);
                break;
            }
        }

        if ((round+1) % 10000 == 0) {
            printf("[round %d/%d] crashes=%d successes=%d unusual=%d\n",
                   round+1, max_rounds, crashes, successes, unusual);
            fprintf(logfp, "[round %d/%d] crashes=%d successes=%d unusual=%d\n",
                   round+1, max_rounds, crashes, successes, unusual);
            fflush(logfp);
        }
    }

    printf("\n=============================================\n");
    printf("  Ralph Wiggum says: \"I did a fuzzing!\"\n");
    printf("=============================================\n");
    printf("Rounds: %d | Crashes: %d | Successes: %d | Unusual: %d\n",
           round, crashes, successes, unusual);
    printf("Log: ~/ralph.log\n");

    fprintf(logfp, "\n=== DONE: %d rounds, %d crashes, %d successes, %d unusual ===\n",
            round, crashes, successes, unusual);

    close(fd);
    if (logfp != stdout) fclose(logfp);
    return 0;
}
