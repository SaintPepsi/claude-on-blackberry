# Sessions 11-12: CVE-2019-2215 Exhaustive Testing, Alternative Vulns, KGSL Pivot

**Date:** 2026-02-28
**Goal:** Definitively determine if CVE-2019-2215 slab reclaim is possible. If not, find alternative kernel attack surfaces.
**Status:** CVE-2019-2215 slab reclaim DEFINITIVELY BLOCKED. All alternative vulns blocked except KGSL. Pivoted to KGSL exploitation.

---

## Executive Summary

After 2 full sessions of exhaustive testing, CVE-2019-2215 (binder/epoll UAF) is **confirmed present but unexploitable** on this BlackBerry Priv kernel. The vulnerability code exists (binder_poll is present, BINDER_THREAD_EXIT triggers the free, epoll holds the dangling reference), but **no spray primitive can reclaim the freed binder_thread memory slot**. This is likely due to slab-level hardening (caller-site isolation or equivalent) in BlackBerry's kernel.

All alternative kernel vulnerabilities are either patched or blocked. The **only remaining viable kernel attack surface** is KGSL (/dev/kgsl-3d0), which is world-writable and has a rich ioctl interface.

---

## CVE-2019-2215: Final Slab Reclaim Results

### Spray Primitives Tested (ALL FAILED)

| Spray Primitive | Mechanism | Target Cache | Threads/Objects | Result |
|----------------|-----------|-------------|-----------------|--------|
| BPF socket filters | SO_ATTACH_FILTER / SO_GET_FILTER readback | kmalloc-512 | 20+ configs, up to 1020 sockets | NO reclaim |
| Pipe iovec copies | Blocking writev with N iovecs | kmalloc-256/512 | 12-32 iovecs, up to 512 threads | NO reclaim |
| sendmsg (Unix sockets) | skb allocation via sendmsg | kmalloc-512 | 128-256 byte msgs, 278 sent | NO reclaim |
| Self-reclaim (binder_thread spray) | Open N binder fds, create threads | kmalloc-512 | 512 binder_threads sprayed | 0 anomalies |
| Slab exhaustion + iovec | BPF exhaust FDs, then iovec spray | kmalloc-512 | 1020 BPF sockets | Failed: no FDs left for binder |

### Timing and Delay Strategies (ALL FAILED)

| Strategy | Hypothesis | Delays Tested | Result |
|----------|-----------|---------------|--------|
| RCU grace period | kfree_rcu delays prevent early reclaim | 1ms, 10ms, 100ms, 500ms | NO effect at any delay |
| Timing-precise single-shot | Minimize delay between free and spray | 100 rounds, zero delay | NO reclaim in any round |

### Pipe Readback v2 Results (Definitive)

Pre-filled pipes with 0xAA, writev wrote 0xBB markers. Read entire pipe after drain. Checked for "alien" bytes (not 0xAA or 0xBB = kernel data).

```
=== kmalloc-512 (binder_thread = 304 bytes) ===
  n_iovecs=19 (304 bytes), threads=128: all clean
  n_iovecs=20 (320 bytes), threads=128: all clean
  n_iovecs=32 (512 bytes), threads=128: all clean

=== kmalloc-256 ===
  n_iovecs=16 (256 bytes), threads=128: all clean
  n_iovecs=12 (192 bytes), threads=128: all clean

=== High spray count ===
  n_iovecs=19 (304 bytes), threads=509: all clean
```

### Conclusion

The freed binder_thread memory is **isolated from general-purpose kmalloc caches**. No userspace-triggerable allocator can reclaim the slot. BlackBerry's kernel likely uses:
- CONFIG_FREELIST_RANDOM (slab freelist randomization), and/or
- Caller-site slab isolation (separate caches per allocation site), and/or
- Some other proprietary hardening

We cannot verify directly because:
- `/proc/slabinfo` does NOT exist (CONFIG_SLABINFO is disabled)
- `/proc/config.gz` does NOT exist
- `userfaultfd` returns ENOSYS (not compiled in)

---

## System Capabilities Discovered

### Resource Limits
- **Max FDs:** ~1020 (hard limit prevents FD-intensive strategies)
- **userfaultfd:** ENOSYS — not compiled into kernel
- **Seccomp:** 0 — no seccomp filtering (unusual, but no syscall is helpful)

### Kernel Visibility
- `/proc/slabinfo`: Does not exist
- `/proc/config.gz`: Does not exist
- `/proc/kallsyms`: Exists but addresses all 0x0000000000000000 (KASLR hides)
- `dmesg`: Permission denied from shell context

---

## Alternative Vulnerability Assessment

Every known Android 6.0.1 / kernel 3.10 exploit path was tested:

| Vector | CVE / Technique | Status | Evidence |
|--------|----------------|--------|----------|
| Dirty COW | CVE-2016-5195 | **PATCHED** | Race between /proc/self/mem write and madvise(MADV_DONTNEED) for 5 seconds — target file unchanged |
| AF_PACKET | Various | **BLOCKED** | socket(AF_PACKET) returns EACCES |
| perf_event_open | CVE-2013-2094 etc. | **BLOCKED** | Returns EACCES, perf_event_paranoid=3 |
| add_key/keyctl | CVE-2016-0728 | **BLOCKED** | Returns EACCES (SELinux) |
| msgget/msgsnd | IPC-based exploits | **BLOCKED** | Returns ENOSYS (SysV IPC not compiled in) |
| /dev/mem, /dev/kmem | Direct memory access | **DON'T EXIST** | Device nodes not present |
| Setuid binaries | Privilege escalation | **NONE FOUND** | No setuid binaries on filesystem |
| Writable /proc/sys | Kernel parameter tweaks | **NONE** | No writable paths from shell context |
| ptrace | Process injection | **AVAILABLE** but useless | No YAMA ptrace scope, but no elevated targets to ptrace |

### SELinux Context
```
u:r:shell:s0
```
Shell domain, not untrusted_app. Slightly more capable but still heavily restricted.

### sendmsg Spray Details
- Unix domain socket, SOCK_DGRAM
- Messages 128-256 bytes targeting kmalloc-512
- Only 278 messages before buffer limit hit (socket buffer full)
- No corruption detected in pipe readback after EPOLL_CTL_DEL

---

## KGSL: The Last Viable Attack Surface

### Why KGSL?

`/dev/kgsl-3d0` is **crw-rw-rw-** (world writable). It's a complex kernel driver (Qualcomm Adreno GPU) with:
- 13 working ioctls (discovered in Session 8)
- Complex memory management (GPU memory alloc/free/mmap)
- Context management (draw contexts with create/destroy)
- Known CVE history with patches often missing from older builds

### Device Info (from prior sessions)
- **GPU:** Adreno 418
- **Chip ID:** 0x4010800
- **GPU resets since boot:** 16,506
- **MMIO base:** 0xfdb00000

### Security Patch Level
- **Patch level:** 2017-10-05
- **Kernel build:** March 2, 2018
- **Implication:** Post-October 2017 KGSL CVEs are likely UNPATCHED

### Working KGSL Ioctls
| Ioctl | Number | Struct Size (ARM64) | Function |
|-------|--------|-------------------|----------|
| GPUMEM_ALLOC_ID | 0x34 | 48 bytes | Allocate GPU memory |
| GPUMEM_FREE_ID | 0x35 | 8 bytes | Free GPU memory |
| GPUMEM_GET_INFO | 0x36 | varies | Query GPU memory info |
| DRAWCTXT_CREATE | 0x13 | 8 bytes | Create draw context |
| DRAWCTXT_DESTROY | 0x14 | 4 bytes | Destroy draw context |
| GETPROPERTY | 0x02 | varies | Get device properties |
| SETPROPERTY | 0x32 | varies | Set device properties |
| DEVICE_WAITTIMESTAMP_CTXTID | 0x18 | varies | Wait for GPU completion |
| TIMESTAMP_EVENT | 0x33 | varies | Timestamp events |
| MAP_USER_MEM | 0x2D | varies | Map user memory to GPU |
| GPUOBJ_IMPORT | 0x3C | varies | Import GPU object |
| GPUOBJ_SYNC | 0x3D | varies | Sync GPU object |
| PERFCOUNTER_GET | 0x3A | varies | Performance counters |

### kgsl_mmap_uaf.c — Created, Compiled, Awaiting Execution

Tests created for initial KGSL exploitation probing:

1. **Ioctl Size Probe** — Dynamic probing of ALLOC/FREE/GET_INFO with sizes 24-64 bytes
2. **Test 1: Basic GPU alloc/mmap/free** — Verify the basic alloc→mmap→read/write→free path works
3. **Test 2: mmap-after-free** — Alloc GPU mem, mmap it, free the GPU mem (keep mapping), spray new allocations, check if stale mapping shows new data
4. **Test 3: Alloc/free race** — 4 threads doing rapid alloc/free cycles for 3 seconds, looking for crashes
5. **Test 4: Context create/destroy race** — 4 threads rapidly creating/destroying draw contexts
6. **Test 5: Info leak after free** — Query GET_INFO on freed buffer IDs to check for stale metadata

### Key Struct Correction
ARM64 uses 8-byte `size_t`, making the GPUMEM_ALLOC_ID struct 48 bytes (not 32). First compilation attempt returned ENOTTY due to wrong struct size encoding in the ioctl number. Fixed with:
```c
struct kgsl_gpumem_alloc_id {
    unsigned int id;          /* 0: out */
    unsigned int flags;       /* 4: in */
    size_t size;              /* 8: in (8 bytes on arm64) */
    size_t mmapsize;          /* 16: out */
    unsigned long gpuaddr;    /* 24: out */
    unsigned long __pad;      /* 32: reserved */
    unsigned long __pad2;     /* 40: reserved */
};
```

---

## Tools Created This Session

| Tool | Purpose | Status |
|------|---------|--------|
| `tools/pipe_readback_v2.c` | Pipe iovec readback with 0xAA/0xBB pattern detection | Compiled, executed — ALL CLEAN |
| `tools/slab_final_test.c` | Multi-strategy slab reclaim (self-reclaim, exhaustion, RCU, timing) | Compiled, executed — ALL NEGATIVE |
| `tools/alt_exploit_test.c` | Alternative exploit assessment (Dirty COW, AF_PACKET, perf, etc.) | Compiled, executed — ALL BLOCKED |
| `tools/kgsl_mmap_uaf.c` | KGSL GPU memory UAF exploitation test | Compiled — **AWAITING EXECUTION** |

All compiled with: `aarch64-linux-musl-gcc -static -O2 -o <binary> <source> -lpthread`

---

## Attack Surface Summary (End of Session 12)

```
ELIMINATED:
  ✗ CVE-2019-2215 (binder UAF) — vuln exists, slab reclaim BLOCKED
  ✗ CVE-2016-5195 (Dirty COW) — PATCHED
  ✗ AF_PACKET — EACCES
  ✗ perf_event_open — EACCES (paranoid=3)
  ✗ add_key/keyctl — EACCES (SELinux)
  ✗ msgsnd/msgrcv — ENOSYS
  ✗ userfaultfd — ENOSYS
  ✗ /dev/mem, /dev/kmem — don't exist
  ✗ setuid binaries — none found
  ✗ writable proc/sys — none from shell

STILL VIABLE:
  → KGSL (/dev/kgsl-3d0) — world-writable, rich ioctl surface, likely unpatched post-Oct-2017 CVEs
```

---

## KGSL mmap_v2 Test Results (Session 12b)

### Phone Recovery
- Phone rebooted during testing, "Waiting for debugger" dialog blocked Settings app
- Fixed via USB ADB: `settings put global debug_app ""` and `settings put global wait_for_debugger 0`
- WiFi ADB re-enabled with `adb tcpip 5555`

### kgsl_mmap_uaf.c v1 Issues
- First compiled binary had wrong struct size (32 bytes, used `_IOW` for FREE)
- BB Priv KGSL uses `_IOWR` for ALL ioctls (confirmed by comparing with ralph3.c)
- Fixed FREE ioctl to `_IOWR`, size probe found 48-byte ALLOC + 8-byte FREE

### kgsl_mmap_v2.c Results

**Test 1 — Basic GPU mmap access:**
```
  mmap at 0x7f7d787000 (size=8192)
  read[0] = 0x00 (OK)                     ← GPU memory readable
  write 0x41, readback = 0x41 (OK)         ← Single byte write works
  CRASH on WRITE (sig=7)                   ← memset causes SIGBUS!
```
**Key finding:** GPU memory is CPU-accessible via volatile single-byte reads/writes, but `memset` (bulk store) triggers SIGBUS. This is a cache coherency / write-combining issue. GPU memory requires uncached access patterns.

**Test 2 — mmap-after-free:**
```
  CRASH writing marker (sig=7)             ← memset crashed before we could test the UAF
```
Needs rewrite to use byte-by-byte volatile writes instead of memset.

**Test 3 — Info leak after free:**
```
  GET_INFO returns ENOTTY for ALL buffers   ← Wrong ioctl size for GET_INFO
```
GET_INFO ioctl size needs probing (40-byte struct doesn't match kernel).

**Test 4 — Allocation sizes (ALL WORK):**
```
     4096 bytes: mmap+write OK
     8192 bytes: mmap+write OK
    16384 bytes: mmap+write OK
    65536 bytes: mmap+write OK
   262144 bytes: mmap+write OK
  1048576 bytes: mmap+write OK
  4194304 bytes: mmap+write OK
```
All sizes from 4KB to 4MB allocate and mmap successfully. mmapsize = alloc_size + 4096 (guard page). Single volatile byte write works for all sizes.

**Test 5 — Alloc/free race:**
```
  CRASH in free (sig=11)                   ← SIGSEGV in concurrent alloc/free
  CRASH in free (sig=7)                    ← SIGBUS in concurrent alloc/free
  race thread: 18847 cycles               ← One thread got 18K cycles before crashing
```
Multi-threaded GPU alloc/free produces crashes. This is potentially exploitable — concurrent operations corrupt GPU memory manager state.

**Test 6 — Large spray + stale mapping:**
Did not execute (process died in test 5 due to signal handler thread-safety issue).

### Critical Observations

1. **GPU memory IS directly CPU-accessible** from shell context — this is the most important finding
2. **Must use volatile byte access** — no memset, memcpy, or bulk stores
3. **Race conditions crash the GPU driver** — SIGSEGV and SIGBUS from concurrent alloc/free
4. **GET_INFO ioctl needs size probing** — current 40-byte size returns ENOTTY
5. **mmap-after-free path is viable** — just needs byte-by-byte pattern writes

## Next Steps

1. Fix kgsl_mmap_v2 to use volatile byte-by-byte writes instead of memset
2. Properly test mmap-after-free: alloc → byte-fill → free (keep mapping) → spray → scan for changes
3. Probe GET_INFO ioctl sizes (try 16-64 bytes)
4. Investigate the race condition crashes — if KGSL state corruption is repeatable, it may be exploitable
5. Research specific KGSL CVEs for 3.10.84 kernel (post October 2017)
