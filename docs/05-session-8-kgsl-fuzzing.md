# Session 8: KGSL Fuzzing — Ralph Wiggum

**Date:** 2026-02-28
**Goal:** Find exploitable kernel bugs in the Qualcomm KGSL GPU driver via ioctl fuzzing
**Status:** COMPLETE — 3 fuzzer generations, 126K+ iterations, 0 kernel crashes. KGSL driver is hardened.

## Background

After confirming Dirty COW is patched (Session 7), `/dev/kgsl-3d0` remains the only
exploitable attack surface accessible from the Termux sandbox. The KGSL (Kernel Graphics
Support Layer) driver for the Qualcomm Adreno 418 GPU is:

- World-writable (`crw-rw-rw-`)
- Opens from untrusted_app SELinux domain
- Uses ioctl interface (type 0x09)
- Has a history of CVEs on kernel 3.10 (CVE-2016-2067, CVE-2016-2504, CVE-2017-0576)
- October 2017 patches may not cover all post-2017 KGSL vulnerabilities

## The Fuzzer: Ralph Wiggum

**Source:** `tools/ralph.c` (323 lines)

A two-phase dumb-persistent ioctl fuzzer that:
1. **Phase 1 (Discovery):** Enumerates all valid ioctl numbers by scanning nr 0x00-0x7F across 4 directions (none/write/read/readwrite) and 9 sizes (0,4,8,16,32,64,128,256,512)
2. **Phase 2 (Mutation):** Fuzzes the valid ioctls with 7 data strategies (zeros, 0xFF, 0x41, random, incrementing ints, edge-case integers, pointer-like values)

Survives crashes via `sigsetjmp`/`siglongjmp` signal recovery. Logs to `~/ralph.log`.

### Compilation

```bash
docker run --rm --platform linux/arm64 \
  -v "/tmp/dirtycow-android:/src" -w /src alpine:3.20 \
  sh -c 'apk add gcc musl-dev && gcc -static -O2 -o ralph ralph.c && strip ralph'
```

Produces a 66944-byte static aarch64 binary.

## Phase 1 Results: Discovery (Ralph v1)

**13 of 128 ioctl numbers are valid** from the untrusted_app SELinux context.

**IMPORTANT:** Phase 1 used generic sizes (0,4,8,...) in the ioctl encoding. The nr values
discovered were initially given incorrect names. Research into msm-3.10 kernel source
revealed the correct mapping:

| nr | Correct Name | Phase 1 Result | Notes |
|----|-------------|----------------|-------|
| 0x02 | GETPROPERTY | RECOGNIZED | Works with exact struct sizes |
| 0x10 | RINGBUFFER_ISSUEIBCMDS | RECOGNIZED | Legacy command submission |
| 0x13 | DRAWCTXT_CREATE | RECOGNIZED | Always returns EINVAL (see v2 results) |
| 0x14 | DRAWCTXT_DESTROY | RECOGNIZED | |
| 0x21 | SHAREDMEM_FREE | RECOGNIZED | |
| 0x34 | GPUMEM_ALLOC_ID | RECOGNIZED | **Works with correct struct size (48 bytes)** |
| 0x35 | GPUMEM_FREE_ID | RECOGNIZED | **Works** |
| 0x36 | GPUMEM_GET_INFO | RECOGNIZED | **Works** |
| 0x38 | PERFCOUNTER_GET | RECOGNIZED | **Works — returns register offsets** |
| 0x3a | PERFCOUNTER_QUERY | **ACCEPTED** | Returns counter counts per group |
| 0x3b | PERFCOUNTER_READ | N/A | ENOTTY — not supported on this kernel |
| 0x40 | SYNCSOURCE_CREATE | **ACCEPTED** | ENOTTY — too new for kernel 3.10 |
| 0x41 | SYNCSOURCE_DESTROY | RECOGNIZED | ENOTTY — too new for kernel 3.10 |

**Key correction:** nr 0x3a is PERFCOUNTER_QUERY (not GPUOBJ_ALLOC), and 0x40 is
SYNCSOURCE_CREATE (not GPUOBJ_SET_INFO). The actual GPUOBJ ioctls (0x45-0x4C) don't
exist on this kernel.

## Phase 2 Results: Mutation Fuzzing (100K Rounds)

| Metric | Value |
|--------|-------|
| Total rounds | 100,000 |
| Crashes (SIGSEGV/SIGBUS) | **0** |
| Successes (ret=0) | **122** |
| Unusual errors | **18** |

### Hot Ioctls (accepted mutations)

| nr | Correct Name | Successes | Unusual |
|----|-------------|-----------|---------|
| 0x3a | PERFCOUNTER_QUERY | ~80 | 0 |
| 0x40 | SYNCSOURCE_CREATE | ~30 | 12 |
| 0x13 | DRAWCTXT_CREATE | ~12 | 6 |

**Zero crashes is expected** for dumb fuzzing — the driver validates struct sizes before
touching data. Generic sizes (0,4,...) don't match actual structs, so most calls
are rejected at the size-check gate.

## Phase 3 Results: Structure-Aware Fuzzing (Ralph v2)

**Source:** `tools/ralph2.c` (~700 lines)

Used actual KGSL struct definitions from msm-3.10 kernel source with correct arm64
sizes and ioctl command encodings. 7 test categories.

### Device Identification

| Property | Value |
|----------|-------|
| device_id | 1 |
| chip_id | 0x4010800 (Adreno 418) |
| mmu_enabled | 1 |
| gmem_sizebytes | 524288 (512KB) |
| gpu_id | 0x800 |
| KGSL driver | v3.14 |
| Device version | v3.1 |

### API Availability

| API | Status | Notes |
|-----|--------|-------|
| GPUMEM_ALLOC_ID (0x34) | **WORKS** | Allocates GPU memory, returns ID |
| GPUMEM_FREE_ID (0x35) | **WORKS** | Frees by ID |
| GPUMEM_GET_INFO (0x36) | **WORKS** | Returns size, flags, gpuaddr |
| GPUMEM_ALLOC (old, 0x2f) | **WORKS** | Legacy alloc path |
| PERFCOUNTER_GET (0x38) | **WORKS** | Returns register offsets |
| PERFCOUNTER_QUERY (0x3a) | **WORKS** | 18 groups accessible |
| GETPROPERTY (0x02) | **WORKS** | Requires exact buffer sizes |
| DRAWCTXT_CREATE (0x13) | RECOGNIZED | **EINVAL for all 20+ flag combos** |
| SYNCSOURCE (0x40-0x43) | ENOTTY | Not in this kernel |
| GPUOBJ (0x45-0x4C) | ENOTTY | Not in this kernel |

### Security Testing (v2)

| Test | Result |
|------|--------|
| Use-after-free (alloc → free → get_info) | EINVAL — properly rejected |
| Double-free | EINVAL — properly rejected |
| Integer overflow sizes | ENOMEM — properly bounds-checked |
| Context races (100 iters) | 0 crashes |
| Memory races (100 iters) | 0 crashes |
| 5000 mutation rounds | 0 crashes, 366 successes |

## Phase 4 Results: High-Intensity Racing (Ralph v3)

**Source:** `tools/ralph3.c` (~700 lines)

Focused on the attack vectors most likely to find exploitable bugs: tight race conditions,
cross-fd operations, kernel info leaks, and mmap-after-free.

### Test 1: Alloc/Free Race (10K iterations, 3 threads)

Main thread allocates+frees, two additional threads race to free and get_info on the same IDs.

**Result: 0 crashes, 0 wins.** The kernel's locking on KGSL memory objects is solid.
No race condition window found in 10,000 iterations.

### Test 2: Multi-FD Race (5K iterations)

Open two file descriptors to `/dev/kgsl-3d0`, allocate on fd1, free on fd2.

**Result: Cross-fd free accepted 100% (5000/5000).** This is by-design behavior —
KGSL tracks GPU objects per-process (not per-fd), so any fd from the same process
can operate on any object. Not exploitable from a single UID, but documents the
KGSL object ownership model.

### Test 3: GETPROPERTY Stack Leak Hunting

Tested 5 property types with exact buffer sizes, plus oversized buffers to detect
kernel stack data leakage.

| Property | Size | Result |
|----------|------|--------|
| DEVICE_INFO | 40 bytes | SUCCESS — device_id, chip_id, mmu, gmem |
| VERSION | 16 bytes | SUCCESS — drv 3.14, dev 3.1 |
| DEVICE_SHADOW | 24 bytes | SUCCESS — addr 0xf8001000, size 0x2000 |
| MMU_ENABLE | 4 bytes | SUCCESS — enabled (1) |
| INTERRUPT_WAITS | 4 bytes | SUCCESS — enabled (1) |

**No stack leaks detected.** Oversized buffers did not return extra kernel data.
DEVICE_SHADOW address (0xf8001000) is a GPU MMIO physical address, not a kernel VA.

### Test 4: Perfcounter Exploitation

Enumerated all performance counter register offsets:

- **18 counter groups** with 2-4 countables each
- Standard groups (0-12, 23-24, 27): offsets 0xaa-0x16f (Adreno GPU MMIO space)
- VBIF groups (13-14): offsets 0x30d8-0x311b
- PERFCOUNTER_READ: **ENOTTY** — ioctl not supported on this kernel version

**No kernel address leakage.** Offsets are GPU register addresses (MMIO space), not
kernel virtual addresses. Cannot defeat KASLR through perfcounters.

### Test 5: Mmap + Free Race (1K iterations)

Allocate GPU memory → mmap into userspace → free while mapped → read from freed mapping.

**Result: Mmap persists after free, reads succeed, but ALL reads return 0x00.**

This is the most interesting finding:
- The mapping survives the free operation (no SIGBUS/SIGSEGV)
- We can read from freed GPU memory without crashing
- But the zero-fill mitigation prevents data exposure
- The physical page is either zeroed on free or redirected to a zero page

**Exploitability: LOW.** The zero-fill mitigation prevents using this as an info leak.
To exploit this, we would need to get the kernel to reallocate the physical page for
something else (kernel structures) AND have the mapping still point to the original
physical address. The zeroing suggests the kernel unmaps and remaps to a zero page.

## Cumulative Results

| Generation | Iterations | Crashes | Key Findings |
|-----------|-----------|---------|--------------|
| Ralph v1 (dumb) | 100,000 | **0** | 13 valid ioctls, 3 accept mutations |
| Ralph v2 (struct-aware) | ~5,400 | **0** | UAF/double-free guarded, device identified |
| Ralph v3 (race/leak) | ~16,000 | **0** | Mmap-after-free persists but zero-filled |
| **Total** | **~121,400** | **0** | |

## Exploitation Theory

The path from KGSL bug to root:

```
KGSL ioctl bug → arbitrary kernel read/write → credential overwrite → root

1. Find a use-after-free, buffer overflow, or type confusion in KGSL
2. Use it to gain arbitrary kernel memory read/write
3. Find current process's cred struct in kernel memory
4. Overwrite uid/gid fields to 0 (root)
5. setresuid(0,0,0) succeeds → root shell
```

## Conclusion

After three generations of fuzzing with 121K+ iterations, the KGSL driver on
BlackBerry Priv (kernel 3.10.84, Oct 2017 patches) shows no exploitable bugs
from the untrusted_app sandbox:

1. **Memory management is locked.** No race conditions in 10K alloc/free races.
2. **UAF is guarded.** Free→use patterns properly rejected with EINVAL.
3. **No info leaks.** GETPROPERTY and perfcounters return GPU MMIO addresses,
   not kernel virtual addresses.
4. **Mmap-after-free is mitigated.** Freed mappings return only zeros.
5. **Context creation blocked.** DRAWCTXT_CREATE refuses all flag combinations,
   preventing access to GPU command submission (the most complex code path).

The driver's attack surface from userspace is limited to:
- Memory alloc/free/get_info (all well-guarded)
- Perfcounter get/query (read-only, no sensitive data)
- GETPROPERTY (read-only, returns GPU hardware info)

**Remaining theoretical vectors (would require deeper research):**
- Custom Adreno GPU shader microcode execution (requires context creation to work)
- Timing side-channels on perfcounter values
- Undiscovered ioctls in non-standard encoding formats
- Kernel module-specific bugs not reachable through standard ioctl interface

## Files

**On phone:**
- `~/ralph` — v1 dumb fuzzer (66944 bytes)
- `~/ralph2` — v2 structure-aware fuzzer (67448 bytes)
- `~/ralph3` — v3 race/leak prober (67224 bytes)
- `~/ralph.log` — v1 output
- `~/ralph2.log` — v2 output

**In repo:**
- `tools/ralph.c` — v1 source (323 lines)
- `tools/ralph2.c` — v2 source (~700 lines)
- `tools/ralph3.c` — v3 source (~700 lines)
