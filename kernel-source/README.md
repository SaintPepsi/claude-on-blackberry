# MSM8992 (Snapdragon 808) Kernel Source — KGSL Driver

**Source:** [LineageOS/android_kernel_lge_msm8992](https://github.com/LineageOS/android_kernel_lge_msm8992) branch `cm-13.0`

This directory contains the KGSL (Qualcomm GPU) driver source from the MSM8992
kernel 3.10 tree. The KGSL driver code is Qualcomm-authored and identical across
all msm8992 devices (LG G4, Nexus 5X, Xiaomi Mi4c, BlackBerry Priv, etc.).

The BlackBerry Priv kernel (`3.10.84-perf-gd46863f`) was never open-sourced by
BlackBerry. The LG msm8992 kernel is the closest available reference for the
shared Qualcomm driver code.

**IMPORTANT: BB Priv kernel differs from this source.** Live testing confirmed
that DRAWCTXT_CREATE returns EINVAL on the BB Priv even with the flag combination
(0x41) that this source requires. BlackBerry modified the KGSL driver beyond what
is shown here. This source is a reference, not an exact match.

## File Inventory (60 files, 45,605 lines)

### Core KGSL Framework
- `kgsl.c` / `kgsl.h` — Main ioctl handler, context lifecycle, memory ops
- `kgsl_device.h` — Device abstraction, function table
- `kgsl_sharedmem.c/h` — GPU memory allocation and mapping
- `kgsl_events.c` — Event/fence management
- `kgsl_mmu.c/h` — Memory management unit abstraction
- `kgsl_iommu.c/h` — ARM IOMMU implementation (SMMU)
- `kgsl_sync.c/h` — Android sync fence integration
- `kgsl_snapshot.c/h` — GPU crash dump capture
- `kgsl_debugfs.c/h` — debugfs interface
- `kgsl_pwrctrl.c/h` — Power management (clocks, regulators)
- `kgsl_pwrscale.c/h` — Dynamic frequency scaling
- `kgsl_cffdump.c/h` — Command feed format dump (debug)
- `kgsl_drm.c` — DRM integration
- `kgsl_compat.c/h` — 32-bit compat ioctl layer
- `kgsl_log.h` — Logging macros
- `kgsl_trace.c/h` — ftrace integration

### Adreno GPU Driver (Adreno 418 on Snapdragon 808)
- `adreno.c/h` — GPU initialization, power, fault recovery
- `adreno_drawctxt.c/h` — **Draw context create/destroy** (critical for exploit analysis)
- `adreno_dispatch.c/h` — Command buffer dispatch and scheduling
- `adreno_ringbuffer.c/h` — GPU ringbuffer management
- `adreno_a4xx.c/h` — Adreno 4xx generation specifics (includes 418)
- `adreno_a4xx_snapshot.c` — A4xx crash dump
- `adreno_a3xx.c/h` — Adreno 3xx (fallback reference)
- `adreno_a3xx_snapshot.c/h` — A3xx crash dump
- `adreno_snapshot.c` — Common snapshot code
- `adreno_perfcounter.c` — Performance counter management
- `adreno_profile.c/h` — GPU profiling
- `adreno_cp_parser.c/h` — Command parser for IB validation
- `adreno_coresight.c` — CoreSight debug trace
- `adreno_compat.c` — 32-bit compat layer
- `adreno_iommu.c` — Adreno-specific IOMMU ops
- `adreno_trace.c/h` — Adreno ftrace events
- `adreno_pm4types.h` — PM4 command packet types
- `a3xx_reg.h` / `a4xx_reg.h` — Register definitions
- `adreno-gpulist.h` — GPU identification table

## Key Finding: DRAWCTXT_CREATE Flag Requirements

From `adreno_drawctxt.c` lines 346-351:
```c
if ((local & KGSL_CONTEXT_PREAMBLE) == 0 ||
    (local & KGSL_CONTEXT_NO_GMEM_ALLOC) == 0) {
    return ERR_PTR(-EINVAL);
}
```

Both `PREAMBLE` (0x40) and `NO_GMEM_ALLOC` (0x01) are **mandatory** in this LG
source. However, Session 10 deep investigation proved that the BB Priv kernel
has a **caller identity restriction** not present in this source. After testing
30+ flag combinations from both shell and untrusted_app domains, 32-bit and
64-bit architectures, all return EINVAL. The ioctl dispatch works correctly
(DEVINFO succeeds), and dmesg confirms the flag check passes (no "legacy
context switch" message), but a BB-specific check after the flag validation
blocks non-system processes. Most likely a UID whitelist restricting context
creation to system UIDs (< 1000).
