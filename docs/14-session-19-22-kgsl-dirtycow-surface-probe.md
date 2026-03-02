# Sessions 19-22: KGSL Deep Exploitation, Dirty COW, Broad Surface Probe

## Summary

Exhaustive testing of KGSL UAF exploitation, Dirty COW alternative vectors, and broad kernel attack surface enumeration. Multiple vectors conclusively eliminated. Key discoveries about PaX configuration and remaining attack surface identified.

## Session 19-20: KGSL Deep Exploitation

### KGSL Ioctl Discovery (kgsl_cmd2, kgsl_cmd3)
- Confirmed correct aarch64 struct alignment for all KGSL ioctls
- **GPUMEM_ALLOC (nr=0x2f, 24-byte struct)**: Works, returns sequential gpuaddrs (0x1000, 0x3000, 0x5000)
- **SHAREDMEM_FREE (nr=0x21, 8-byte struct)**: Found via IOW scan
- **Second free-like ioctl (nr=0x24)**: Found during scan, behavior investigated
- DRAWCTXT_CREATE: EINVAL for ALL flag combinations (brute-forced 0 to 0x800000)
- GETPROPERTY: EINVAL for all property types (0-30) and sizes
- **mmap works**: `mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, gpuaddr)` succeeds

### KGSL UAF Attempt (kgsl_uaf)
- **READ UAF**: After SHAREDMEM_FREE, stale mmap readable — all sentinel data intact
- **WRITE UAF**: Wrote 0xDEADBEEF through stale mapping, read back successfully
- **"Double-free"**: ioctl 0x24 then 0x21 both return success on same buffer
- **No page reclamation**: 50 GPU allocs and 200 pipes didn't reclaim freed pages

### Memory Pressure Testing (kgsl_uaf2)
- BPF socket filter spray (500 sockets): No page reuse
- Anonymous page pressure (1MB to 256MB): No page reuse
- setxattr spray (170 xattrs): No page reuse
- Pipe spray (500 pipes × 16 pages): No page reuse
- **False positive identified**: scan_page() had expected value calculation bug

### KGSL Conclusions (kgsl_uaf3, kgsl_dfree)
- **VMA refcount prevents true page freeing**: Stale mapping keeps pages alive
- **GPU pages in separate memory pool**: Not reused by kernel slab/buddy/pipe
- **Ioctl 0x24 is NOT a free**: Idempotent, validates gpuaddr, probably cache flush/sync
- **No duplicate gpuaddrs from "double-free"**: Even 20 double-frees + 40 re-allocs produce zero duplicates
- **Max 4096 × 4K GPU buffers (16MB)**: Large allocs up to 16MB all work with mmap

**KGSL exploitation verdict: DEAD.** Stale mmap provides R/W access to original pages only, which remain alive due to VMA refcount.

## Session 21: Dirty COW Testing

### Standard Dirty COW (dirtycow_test)
- /proc/self/mem opens O_RDWR: OK
- /proc/self/mem **write FAILS**: EPERM (GRSEC PROC_MEMPROTECT)
- madvise DONTNEED works, zeroes anonymous pages
- **Dirty COW: SKIPPED** — no write primitive

### Alternative Vectors (cow_alt)
- **/proc/self/mem write ALL BLOCKED**: RW mmap, RO mmap, heap — all EPERM
- **process_vm_writev**: ENOSYS (not implemented in kernel)
- **vmsplice/splice**: Both work (4096 bytes)
- **mprotect RO→RW on MAP_PRIVATE**: Works, but COW semantics correct (file unchanged)
- **fork()**: Works

### PaX Flags: `Pemrs`
| Flag | Status | Meaning |
|------|--------|---------|
| P | ENABLED | PAGEEXEC — NX enforcement |
| e | disabled | EMUTRAMP — not needed |
| m | disabled | **MPROTECT not enforced** — W→X, RWX allowed |
| r | disabled | **RANDMMAP not enforced** — no PaX ASLR |
| s | disabled | SEGMEXEC — x86 only |

Key implication: We can create RWX memory freely. Any exploit that needs shellcode execution has no W^X barrier.

### GRSEC Hardening Confirmed
- /proc/self/mem write: BLOCKED
- ptrace: BLOCKED (EPERM)
- process_vm_writev: NOT IMPLEMENTED
- Per-callsite slab isolation: CONFIRMED (earlier sessions)
- No writable /proc/sys or /sys entries from shell

**Dirty COW verdict: DEAD.** All three write primitives blocked.

## Session 22: Broad Surface Probe

### Network Sockets
| Socket | Status |
|--------|--------|
| NETLINK_ROUTE | **OK** |
| NETLINK_SELINUX | **OK** |
| AF_INET6 TCP/UDP | OK |
| AF_UNIX (all types) | OK |
| AF_PACKET | EPERM |
| NETLINK_GENERIC | EPERM |
| AF_INET RAW | EPERM |

### Futex Operations
- All PI futex operations work (LOCK_PI, UNLOCK_PI, TRYLOCK_PI)
- WAIT_REQUEUE_PI works
- Robust list: set/get both work
- **CVE-2014-3153 (towelroot): PATCHED** — non-PI to PI requeue returns EINVAL

### perf_event_open
- **ALL BLOCKED** (errno=13) — perf_event_paranoid = 3

### Accessible Device Files
| Device | Status | Notes |
|--------|--------|-------|
| /dev/ion | OPEN | ION allocator, chr(10,94) |
| /dev/ashmem | OPEN | Shared memory |
| /dev/binder | OPEN | IPC |
| /dev/adsprpc-smd | OPEN | **Qualcomm ADSP RPC**, chr(222,0) |
| /dev/xt_qtaguid | OPEN | Traffic tagging |
| /dev/kgsl-3d0 | OPEN | GPU (from earlier) |

### prctl/Personality
- NO_NEW_PRIVS: 0 (can still gain privileges)
- DUMPABLE: 1
- ADDR_NO_RANDOMIZE: Can be set
- CHILD_SUBREAPER: Can be set

### Kernel Specifics
- kallsyms: Addresses zeroed (kptr_restrict)
- /dev/kmsg: Not accessible
- 4 kernel modules visible
- No writable /proc or /sys entries

## Dead Vectors (Comprehensive)

1. CVE-2018-5831 (KGSL refcount race) — kref protection
2. CVE-2018-13905 (syncsource race) — kref prevents UAF
3. CVE-2016-2062 (KGSL perfcounter overflow) — ioctls removed
4. Binder UAF (CVE-2019-2215) — GRSEC per-callsite slab isolation
5. CVE-2018-9568 WrongZone — wrong cross-cache direction
6. SysV IPC heap spray — ENOSYS
7. KGSL page-level UAF — VMA refcount prevents true page freeing
8. KGSL "double-free" via ioctl 0x24 — not actually a free
9. Dirty COW (CVE-2016-5195) — /proc/self/mem write blocked by GRSEC
10. process_vm_writev — ENOSYS
11. ptrace — EPERM
12. CVE-2014-3153 (towelroot) — PATCHED (futex requeue validation)
13. perf_event_open — paranoid=3, all operations EPERM

## Remaining Attack Surface

### Unexplored Device Drivers
- **/dev/ion**: ION memory allocator — has had multiple CVEs on Qualcomm 3.10 kernels
- **/dev/adsprpc-smd**: Qualcomm ADSP RPC — large attack surface, multiple historical CVEs
- **NETLINK_ROUTE**: Can we manipulate routing in useful ways?
- **NETLINK_SELINUX**: Can receive SELinux audit events

### Key Constraints
- CapBnd: CAP_SETUID + CAP_SETGID (0xc0) — in bounding set but not effective
- PaX MPROTECT disabled — RWX memory available for shellcode
- No KASLR, known kernel addresses (from earlier sessions)
- Security patch level: 2017-10-05

## Tools Written This Session

All in /tmp, compiled with `/opt/homebrew/bin/aarch64-linux-musl-gcc -static -O2`:

| Tool | Purpose | Key Result |
|------|---------|------------|
| kgsl_cmd2.c | KGSL ioctl discovery with correct structs | GPUMEM_ALLOC works |
| kgsl_cmd3.c | mmap, free, context discovery | mmap works, FREE at 0x21 |
| kgsl_uaf.c | UAF basic test | R/W UAF confirmed (but not exploitable) |
| kgsl_uaf2.c | Memory pressure exploitation | No page reclamation |
| kgsl_uaf3.c | Same-pool reclaim, exhaustion | GPU pages in separate pool |
| kgsl_dfree.c | Double-free overlap test | No overlapping allocations |
| dirtycow_test.c | CVE-2016-5195 detection | /proc/self/mem write blocked |
| cow_alt.c | Alternative COW vectors + hardening | PaX Pemrs, all writes blocked |
| probe_surface.c | Broad surface enumeration | ION, ADSP, futex findings |
| futex_test.c | CVE-2014-3153 detection | PATCHED (requeue validated) |
