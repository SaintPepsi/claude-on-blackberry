# Sessions 15-16: Binder UAF Slab Reclamation Blocked, KGSL Page Reuse Pivot

## Date: 2026-03-01 to 2026-03-02
## Status: CLOSED — All approaches in this doc definitively ruled out (see doc 13)

---

## Executive Summary

These sessions definitively proved that **GRSEC slab hardening on the BlackBerry Priv prevents UAF slab reclamation at ALL tested sizes** (kmalloc-128 through kmalloc-512). Five exploit versions (v1-v5) systematically ruled out every slab spray mechanism. The pivot is now to **KGSL page-level exploitation** which bypasses both GRSEC slab isolation and ARM64 LDTR/STTR restrictions.

---

## What Was Tried and Why It Failed

### Binder Exploit v1 (writev + sendmsg spray)
- **Strategy:** writev blocking threads + sendmsg for iovec spray + vmsplice for buffer control
- **Result:** writev didn't block (returned immediately), sendmsg spray didn't reclaim slab
- **Root cause:** The writev approach needs iovec to be in-flight, but writev completed too fast

### Binder Exploit v2 (readv + pipe blocking)
- **Strategy:** readv from empty pipe to block thread, vmsplice for buffer control
- **Result:** readv returned only 4 bytes (pipe_read returns early after partial read)
- **Root cause:** ARM64 pipe_read implementation returns after first buffer consumed

### Binder Exploit v3 (readv + vmsplice non-mergeable buffers)
- **Strategy:** vmsplice creates non-mergeable pipe buffers, readv blocks waiting for more data
- **Result:** 80/80 threads blocked successfully, UAF triggered, list_del triggered
- **BUT:** 0 slab reclamation detected across all 80 threads
- **Details:** 14/80 got short reads (52 bytes, vmsplice race on buffer 2+3), all 66 others got expected 68 bytes of normal data
- **Root cause:** GRSEC slab hardening prevents cross-object reclamation

### Binder Exploit v4 (multi-phase diagnostic)
- **Phase A: msg_msg spray** → `msgget: Function not implemented` (ENOSYS) — System V IPC not available
- **Phase B: writev kernel read** → 0 suspicious across 3 attempts, all 80 threads returned exactly 76 bytes
- **Phase C: fast single-thread** → no anomalies
- **Root cause:** System V IPC not compiled into this Android kernel

### Binder Exploit v5 (comprehensive slab diagnostic)
- **keyctl spray:** `add_key: Permission denied (errno=13)` — GRSEC blocks from shell context
- **iovec at 5 sizes (kmalloc-128 through kmalloc-512):** 0 anomalies across ALL sizes, 100 threads each
- **Rapid single-alloc test:** 0 anomalies in 20 attempts
- **DEFINITIVE CONCLUSION:** GRSEC slab hardening prevents reclamation regardless of object size

### Additional ARM64 Blocking Factor
- `__copy_to_user_inatomic` on ARM64 3.10 uses STTR (Store Unprivileged) instructions
- STTR enforces EL0 permissions even from kernel context
- This blocks writes to kernel addresses through pipe, even without PAN
- LDTR similarly blocks kernel reads through pipe
- **Impact:** Even if slab reclamation worked, the pipe-based read/write primitive wouldn't work for kernel addresses

---

## What's Definitively Ruled Out

| Approach | Reason |
|----------|--------|
| Binder UAF slab reclamation | GRSEC slab hardening at ALL sizes (kmalloc-128 through 512) |
| System V IPC (msgget/msgsnd) | ENOSYS — not compiled into kernel |
| keyctl/add_key spray | EPERM — GRSEC blocks from shell context |
| sendmsg spray | No observable reclamation |
| Pipe-based kernel R/W (even if reclaimed) | ARM64 STTR/LDTR blocks at EL0 permission level |
| userfaultfd | ENOSYS — not compiled into kernel |
| KGSL stale mmap page reclaim (without madvise) | Pages pinned in GPU driver pool (session 13) |

---

## What Remains Viable

### Tier 1: Currently Being Tested
| Approach | Status | Notes |
|----------|--------|-------|
| KGSL page reuse (with madvise) | Code written, untested | Bypasses GRSEC slab + STTR. Uses madvise(MADV_DONTNEED) to zap PTEs |
| CVE-2018-5831 (KGSL refcount race) | Confirmed unpatched, untested | Backup if page reuse fails |

### Tier 2: Untested But Available
| Approach | Status | Notes |
|----------|--------|-------|
| CVE-2019-10567 (GPU ring buffer) | DRAWCTXT_CREATE crashes phone | Deterministic but needs draw context |
| CVE-2016-3842 (ALLOC/FREE_ID race) | kgsl_mem_entry UAF in kmalloc-192 | May have same GRSEC slab issue |
| CVE-2018-13905 (syncsource race) | Unpatched, untested | Need to check ioctl availability |

### Tier 3: Nuclear Options
| Approach | Status | Notes |
|----------|--------|-------|
| Crash scenario exploitation | Not yet investigated | Phone crashes indicate reachable code paths |
| CVE-2018-9568 (WrongZone) | Very low reliability | IPv6→IPv4 type confusion in sk_clone_lock |

---

## KGSL Page Reuse Approach (Current Focus)

### Theory
KGSL GPU pages are backed by real physical memory. After:
1. GPU buffer alloc + mmap (gives userspace PTE to physical page)
2. GPU buffer free (GPU releases the buffer, but PTE may remain)
3. KGSL fd close (GPU driver releases all state)
4. madvise(MADV_DONTNEED) (explicitly zaps our PTE, releases page reference)
5. Fork spray (creates 128 children, each needs thread_info/task_struct pages)

The physical pages previously held by KGSL may be recycled by the kernel page allocator for process stacks, thread_info, task_struct, or cred structures.

### Why This Bypasses GRSEC
- Works at PAGE level (4KB), not SLAB level (kmalloc cache)
- GRSEC slab hardening isolates slab objects — it doesn't control the page allocator
- No LDTR/STTR issue because access is through our own userspace PTE (if the page gets re-mapped)

### Test Result (Session 16)
```
After madvise: 0 zeroed, 0 changed, 256 unchanged
Pages changed: 0/256 (both rounds)
```
**DEFINITIVELY DEAD.** madvise(MADV_DONTNEED) returned success on all 256 pages but had NO EFFECT — the KGSL VMA is flagged VM_PFNMAP which makes madvise a no-op. Physical pages remain pinned in GPU driver control regardless of madvise, KGSL fd close, or memory pressure. Page-level reuse is impossible on this driver.

### Code: /tmp/kgsl_page_reuse.c
- Allocates 256 GPU pages, mmaps all
- Frees all GPU buffers, closes KGSL fd
- madvise(MADV_DONTNEED) on all pages
- Fork sprays 128 children
- Scans all pages for: thread_info, task_struct, cred
- If cred found: direct overwrite uid/gid to 0
- If thread_info found: overwrite addr_limit, use /proc/self/mem for kernel R/W

---

## Crash Scenarios (Not Yet Investigated)

The phone has crashed several times during testing:
- DRAWCTXT_CREATE caused kernel panic
- Various KGSL operations triggered bad memory accesses

**Potential value:**
- Crashes indicate reachable, vulnerable code paths
- Crash dumps (if captured via ramoops/last_kmsg) show register state and stack traces
- A controlled crash that writes a known value to a known address = primitive
- Null pointer derefs can be exploitable if mmap_min_addr is 0 or we can map the faulting address

**TODO:** Investigate /proc/last_kmsg or /sys/fs/pstore/ for crash dumps from previous kernel panics.

---

## Known Kernel Addresses (No KASLR)

```
commit_creds         = 0xffffffc00024a840
prepare_kernel_cred  = 0xffffffc00024ab74
init_task            = 0xffffffc0016247e0
init_cred            = 0xffffffc00162d688
selinux_enforcing    = 0xffffffc001649178
selinux_enabled      = 0xffffffc00164917c
```

---

## Device Capabilities Summary

```
AVAILABLE:
  ✓ /dev/binder (CVE-2019-2215 UAF trigger works, reclamation blocked)
  ✓ /dev/kgsl-3d0 (GPU alloc/free/mmap, world-writable)
  ✓ TCP/UDP/IPv6, NETLINK_ROUTE, ping sockets
  ✓ /proc/self/mem RW
  ✓ madvise, pipes, vmsplice, epoll, fork
  ✓ seccomp (spray tested — per-callsite slab isolation blocks reclamation)
  ✓ Cross-compiler: aarch64-linux-musl-gcc

NOT AVAILABLE:
  ✗ System V IPC (msgget ENOSYS)
  ✗ keyctl/add_key (EPERM from shell)
  ✗ userfaultfd (ENOSYS)
  ✗ AF_PACKET (EACCES)
  ✗ perf_event_open (EACCES, paranoid=3)
  ✗ KGSL DRAWCTXT_CREATE (crashes phone)
  ✗ UAF slab reclamation (GRSEC blocks all sizes)
```
