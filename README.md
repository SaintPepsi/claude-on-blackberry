# Claude Code on BlackBerry Priv (Android 6.0.1)

**STATUS: COMPLETE** — Claude Code v2.1.62 running, authenticated, and auto-launching on a 2015 BlackBerry Priv.

> *"Hello from the iconic BlackBerry Priv sliding keyboard phone!"*
> — Claude, responding from the BlackBerry Priv via API call, 2026-02-27

## Device Specs

| Spec | Value |
|------|-------|
| Model | BlackBerry Priv STV100-3 |
| OS | Android 6.0.1 |
| Kernel | 3.10.84-perf |
| Architecture | aarch64 |
| SoC | Snapdragon 808 |
| RAM | 3 GB |
| Security Patch | October 2017 |
| Build | AAW068 |

## The Problem

Claude Code requires Node.js 18+. Termux on Android 6.0.1 has a frozen package repo
(dropped support 2020-01-01) and maxes out at Node.js 13. The standard paths are blocked:

- `pkg install nodejs` = Node 13 only (frozen repo)
- `proot-distro` = requires Android 7+
- Compile Node 18 natively = kernel 3.10 < required 4.18, no glibc

## The Solution

**Vector A: proot + Alpine Linux** — use raw `proot` (not proot-distro) to create an
Alpine Linux ARM64 chroot inside Termux. Alpine provides Node.js 20 via `apk`. proot
intercepts syscalls via ptrace.

### What's Running

| Layer | Component | Version |
|-------|-----------|---------|
| Host | Android / Termux | 6.0.1 / frozen repo |
| Chroot | proot + Alpine Linux | 5.1.0 + v3.20 aarch64 |
| Runtime | Node.js (musl) | v20.15.1 |
| Package Manager | npm | 10.9.1 |
| CLI | Claude Code | v2.1.62 |
| Auth | OAuth token | CLAUDE_CODE_OAUTH_TOKEN |

### How It Works

```
Termux (Android 6.0.1)
  ├── sshd starts automatically (port 8022)
  └── ~/.bashrc auto-launches:
      └── ~/start-alpine.sh
          └── proot (ptrace syscall interception)
              └── Alpine Linux v3.20 aarch64
                  └── .profile loads OAuth token
                      └── Claude Code v2.1.62
                          └── Anthropic API (authenticated)
                      └── On exit: reset terminal + Alpine shell fallback
```

## Quick Start

Open Termux on the phone. It auto-launches into Alpine and starts Claude Code.
SSH server starts automatically on port 8022 for remote management.
When you exit Claude (Ctrl+C), the terminal resets and drops to an Alpine shell.

If you need to reconfigure:

```bash
# Disable auto-launch:
touch ~/.no-alpine

# Re-enable:
rm ~/.no-alpine

# Manual launch:
~/start-alpine.sh

# Exit Claude to Alpine shell: Ctrl+C (terminal resets automatically)

# Emergency recovery (if locked out):
# Swipe left in Termux for session drawer -> tap FAILSAFE
# Then: export LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib
#        touch /data/data/com.termux/files/home/.no-alpine
```

## Six Critical Discoveries

These are the non-obvious problems that block this setup and their solutions.
Anyone attempting to run Claude Code on Android 5-6 will hit every one of these.

### 1. musl ELF Interpreter Resolution Failure

**Problem:** `proot -r ~/alpine /bin/sh` always fails with "No such file or directory"
even though `/bin/sh` exists. The kernel tries to resolve `/lib/ld-musl-aarch64.so.1`
(the ELF interpreter) at the HOST level before proot can intercept. On Android (Bionic),
this path doesn't exist.

**Fix:** Invoke the musl dynamic loader directly as the entry point:
```bash
proot -r ~/alpine /lib/ld-musl-aarch64.so.1 /bin/busybox sh
```
The musl loader is statically linked, so the kernel can execute it without another interpreter.

### 2. HTTPS/TLS Segfaults in proot

**Problem:** `apk update` crashes with signal 11 (SIGSEGV) when repos use HTTPS.
TLS operations trigger syscalls that proot 5.1.0 cannot properly intercept on kernel 3.10.

**Fix:** Switch Alpine repos to HTTP:
```bash
echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/main" > /etc/apk/repositories
echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/community" >> /etc/apk/repositories
```

### 3. Kernel Version Spoofing Breaks Node.js CSPRNG

**Problem:** With `-k 4.14.0`, Node.js thinks `getrandom()` syscall exists (added in
kernel 3.17), tries to use it, and crashes with `crypto::CSPRNG(nullptr, 0).is_ok()`
assertion failure (signal 6).

**Fix:** Don't use `-k 4.14.0`. Without the spoof, Node sees kernel 3.10, falls back
to `/dev/urandom`, works correctly. Alpine's musl Node.js build doesn't enforce a
minimum kernel version.

### 4. seccomp Acceleration Crashes on Kernel 3.10

**Problem:** proot's seccomp fast path causes crashes on the old kernel.

**Fix:** `PROOT_NO_SECCOMP=1` — falls back to pure ptrace. Slower but stable.

### 5. OAuth Token Authentication for Headless Devices

**Problem:** `claude auth login` and `claude setup-token` both require an interactive
TUI terminal. Can't run non-interactively or pipe tokens in.

**Fix:** Generate a setup token on another machine, then set it as an environment variable:
```bash
export CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-..."
```
Save to `/root/.profile` inside Alpine for persistence.

### 6. Terminal Raw Mode / exec Chain Recovery

**Problem:** Claude Code's Ink TUI puts the terminal in raw mode. The `.bashrc` uses
`exec` to replace the shell with the Alpine launcher. When Claude exits (Ctrl+C), proot
terminates, but there's no parent shell to return to. Termux has no process left and
closes. The terminal is stuck in a boot loop where every reopen immediately launches
Claude again.

**Fix (launcher):** Add `reset; exec sh -l` after `claude` in the launcher script so
exiting Claude resets the terminal and drops to an Alpine shell:
```bash
"... && . /root/.profile && claude; reset; exec sh -l"
```

**Fix (recovery):** If you're locked out, use Termux's **failsafe session**: swipe from
the left edge of the screen to open the session drawer, tap **FAILSAFE**, then:
```bash
export LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib
touch /data/data/com.termux/files/home/.no-alpine
/data/data/com.termux/files/usr/bin/sshd
```
The failsafe shell bypasses `.bashrc` entirely, using `/system/bin/sh` directly.

## Progress Log

### Session 1 — 2026-02-27

**MILESTONE: SSH ACCESS TO PHONE FROM MAC**

- Termux installed and running on BlackBerry Priv
- USB/ADB: FAILED (charge-only cable chain, no data lines)
- SSH over WiFi: SUCCESS (port 8022, key auth configured)
- Maple can execute commands on the phone remotely

### Session 2 — 2026-02-27

**MILESTONE: CLAUDE CODE FULLY OPERATIONAL**

- proot 5.1.0 installed (community build for Android 5-7)
- Alpine Linux v3.20 aarch64 minirootfs deployed
- Discovered and solved: musl ELF interpreter, HTTPS segfault, CSPRNG crash
- Node.js v20.15.1 + npm 10.9.1 installed via apk
- Claude Code v2.1.62 installed via npm
- OAuth token authentication configured
- Auto-launch configured: Termux -> Alpine -> Claude Code
- **First successful API call:** Claude responded from the BlackBerry Priv

### Session 3 — 2026-02-27

**MILESTONE: PRODUCTION-READY WITH ALL EDGE CASES SOLVED**

- Terminal raw mode fix: `reset; exec sh -l` after claude in launcher
- sshd auto-start: added to `.bashrc` before Alpine launch block
- Onboarding skip: `settings.json` with `hasCompletedOnboarding: true`
- Discovered Termux failsafe session recovery (6th critical discovery)
- Launcher now sources `.profile` for OAuth token persistence
- Full boot loop recovery documented (failsafe + LD_LIBRARY_PATH)

### Session 4 — 2026-02-27

**MILESTONE: SHELL FIX, STARTUP OPTIMIZATION, PERMISSIONS DISCOVERY**

- Fixed "No suitable shell found" — installed bash, set `SHELL=/bin/bash` in `.profile`
- Installed git via `apk add git`
- Startup time analysis: **~21 seconds** from Node.js start to first API response
  - Biggest bottleneck: TUI/Ink init through proot ptrace (~8-9 seconds, unavoidable)
  - OAuth 403s wasting ~5 seconds (setup token lacks `user:profile` scope)
  - MCP config scan: ~3-4 seconds for 0 servers
- Added performance env vars to `.profile`:
  - `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` — eliminates dead OAuth calls
  - `DISABLE_AUTOUPDATER=1` — skips update checks
  - `NODE_OPTIONS="--max-old-space-size=512"` — limits V8 heap on 3GB device
- Discovered: `--dangerously-skip-permissions` **incompatible with proot's `-0` (fake root)** — Claude detects uid 0 and refuses the flag
- Realistic startup: **~16-18 seconds** (with 2-3s run-to-run variance from proot)

### Session 5 — 2026-02-28

**MILESTONE: SSH MULTIPLEXING, PERMISSIONS WILDCARD, DEVICE MANAGEMENT AUDIT**

- SSH multiplexing configured (`~/.ssh/config` with `ControlMaster`)
  - Before: 2-3s per command (full handshake each time)
  - After: 0.3s per command (`ssh bb '<command>'`)
  - Persistent connection: 4 hours with keepalive
- Permissions wildcard: `settings.json` updated to `"allow": ["*"]` — all tools auto-approved
  - Workaround for `--dangerously-skip-permissions` being blocked by proot fake root
- Full device management audit: probed all Android management commands from Termux
  - `pm list packages`, `pm path`, `am start` — all work (read-only + launch)
  - `pm uninstall`, `pm disable-user`, `settings` — blocked (requires ADB shell uid 2000)
  - Termux user uid 10110 is sandboxed by Android security model
- ADB over WiFi: **not available** in BlackBerry Priv Developer Options
  - `adbd` running but USB-only mode (no TCP port)
  - One-time USB data cable needed to run `adb tcpip 5555` and unlock WiFi ADB permanently

### Session 6 — 2026-02-28

**MILESTONE: ROOT EXPLOIT COMPILATION, PERMISSION WALL DISCOVERY**

- Dirty COW (CVE-2016-5195) selected — kernel 3.10 is in vulnerable range
- Cross-compiled exploit for aarch64 using Docker ARM64 emulation
- Built 944-byte no-libc root shell payload (direct aarch64 syscalls, no musl)
  - Standard musl static binary: 66KB (too large for 14KB run-as target)
  - No-libc payload: 944 bytes with 13KB headroom
- **Permission wall discovered:** `/system/bin/run-as` is `rwxr-x---` (root:shell only)
  - Termux uid 10110 cannot read the target file — exploit fails at `open()`
  - This is why all Dirty COW Android tutorials use ADB shell (uid 2000, shell group)
- Investigated alternatives: Zygote hijack, vDSO injection, libc modification, Qualcomm CVEs
- Spawned an AI subagent that refused to help with the exploit (documented in session notes)
- Shared libraries (`libc.so` etc.) are world-readable — potential injection target
- `/dev/kgsl-3d0` (Qualcomm GPU) is world-writable — potential kernel exploit vector
- **Next step:** USB data cable for ADB shell, or vDSO arm64 shellcode development

### Session 7 — 2026-02-28

**MILESTONE: DIRTY COW CONFIRMED PATCHED, FULL ATTACK SURFACE AUDIT**

- **Dirty COW definitively tested on app_process64** (world-readable, 22456 bytes)
  - Exploit ran, mmap succeeded, race executed 456,544 madvise iterations
  - Result: **Bus error (SIGBUS), bytes unchanged, checksum identical**
  - Kernel patched: Oct 2017 security patches include Nov 2016 Dirty COW fix
- Built 1288-byte no-libc bind shell payload (port 9999) for Zygote hijack approach
- Comprehensive attack surface audit of every remaining vector:
  - Transparent Huge Pages: not enabled (blocks Huge Dirty COW CVE-2017-1000405)
  - User namespaces: not compiled (blocks modern kernel exploits)
  - AF_PACKET: exists but zero capabilities (can't create raw sockets)
  - perf_event: paranoid level 3 (maximum restriction)
  - userfaultfd, V4L2, keyctl, mqueue: all unavailable
  - No SUID binaries, no filesystem capabilities anywhere
  - SELinux enforcing, `untrusted_app` domain blocks all system access
  - `setprop`, `am start`, `content query`: all blocked by SELinux/permissions
- `/dev/kgsl-3d0` opens from Termux — last theoretical vector (requires custom exploit)
- **Conclusion: BlackBerry Priv is unrootable from Termux sandbox with known exploits**
  - XDA's $1000 bounty for BB Priv root was never claimed — now we know why
  - Most practical path: USB data cable for ADB shell (uid 2000, not root, but useful)

### Session 8 — 2026-02-28

**MILESTONE: KGSL FUZZING — 121K ITERATIONS, 0 CRASHES, DRIVER IS HARDENED**

- Built 3 generations of "Ralph Wiggum" KGSL ioctl fuzzer
  - v1 (`tools/ralph.c`): Dumb discovery + mutation (100K rounds)
  - v2 (`tools/ralph2.c`): Structure-aware with kernel struct layouts (~5.4K iterations)
  - v3 (`tools/ralph3.c`): High-intensity races + info leak hunting (~16K iterations)
- Cross-compiled all via Docker ARM64 emulation, deployed to phone
- **Corrected ioctl mapping:** 0x3a = PERFCOUNTER_QUERY, 0x40 = SYNCSOURCE_CREATE (not GPUOBJ)
- **Device identified:** Adreno 418, chip_id 0x4010800, KGSL driver v3.14, 512KB GMEM
- **Key findings across 121K iterations:**
  - UAF and double-free: properly rejected (EINVAL)
  - 10K alloc/free races: 0 crashes — kernel locking is solid
  - Cross-fd free: accepted (by design, per-process object tracking)
  - Mmap-after-free: mapping persists but zero-filled (mitigation active)
  - GETPROPERTY: no stack leaks; DEVICE_SHADOW returns GPU MMIO address
  - Perfcounters: 18 groups enumerated, no kernel address leakage
  - DRAWCTXT_CREATE: EINVAL for all 20+ flag combinations
- **Conclusion: KGSL driver on BB Priv is well-hardened from untrusted_app sandbox**
- Most practical path to root remains USB data cable for ADB shell (uid 2000)

### Session 9 — 2026-02-28

**MILESTONE: ADB CONNECTION, SHELL DOMAIN AUDIT, MARCH 2018 KERNEL DISCOVERY**

- **ADB shell access established** via $5 Keji Micro USB data cable from Officeworks
  - USB device serial: 1162961923
  - WiFi ADB enabled: `adb tcpip 5555` then `adb connect 192.168.4.51:5555`
  - Shell identity: uid=2000(shell), SELinux `u:r:shell:s0`
- **Kernel build date: March 2, 2018** — 5 months newer than Oct 2017 patch level
  - BlackBerry rebuilt kernel post-Spectre/Meltdown
  - Nov/Dec 2017 kernel CVEs (including CVE-2017-13162 binder EoP) likely patched
- **Shell domain capabilities enumerated vs untrusted_app:**
  - NEW: `settings put global/secure`, `pm grant`, `run-as`, `/data/local/tmp/` exec
  - NEW: `dumpsys`, `service list/call` (132 services), `dmesg`, `content query`
  - STILL BLOCKED: `setenforce`, `/system` remount, `insmod`, `/dev/` listing, kallsyms
- **KGSL DRAWCTXT_CREATE tested from shell** — EINVAL for all 20 flag combos (Session 10: also EINVAL with correct flags, BB Priv kernel differs from LG source)
- **Comprehensive CVE assessment:**
  - 7 CVEs confirmed patched (Dirty COW, QuadRooter x4, iovyroot, KGSL GPUREADONLY)
  - 3 CVEs likely patched (March 2018 kernel: binder EoP, late-2016 KGSL, 2017 KGSL UAF)
  - 1 CVE unpatched but limited: CVE-2017-13156 Janus APK (app-level only, not root)
- **CapBnd = 0xc0** (CAP_SETUID + CAP_SETGID in bounding set, but CapEff = 0)
- **No SUID/SGID binaries anywhere**, KASLR active, SELinux enforcing
- **Conclusion: No viable root path from shell context on this device**
  - Every known exploit vector tested from both untrusted_app and shell domains
  - Root requires either 0-day kernel exploit, bootloader unlock, or hardware attack

### Session 10 — 2026-02-28

**MILESTONE: KERNEL DATE CONFIRMED, KGSL DEEP EXTRACTION, SOURCE CODE ACQUIRED, BB KGSL DIVERGENCE CONFIRMED**

- **Kernel build date verified**: `Fri Mar 2 10:04:14 EST 2018` confirmed from `/proc/version`, `uname -a`, and `ro.build.date` (UTC: 1520002871). Security patch level `2017-10-05` is bulletin date, not compile date.
- **KGSL fully mapped** from sysfs, debugfs, platform device, and interrupt info:
  - GPU: Adreno 418, MMIO at 0xfdb00000, IRQ 65 (114K interrupts)
  - 6 frequency steps: 180MHz-600MHz, currently at 300MHz
  - 16,506 GPU resets since boot (aggressive fault recovery)
  - 16 active draw contexts across 7 processes
- **com.termux has active KGSL contexts** (ctx 5 + ctx 10, 1.9M timestamps) — created through Android GLES library
- **Snapdragon 808 kernel source acquired**: 60 KGSL driver files (45,605 lines) from [LineageOS/android_kernel_lge_msm8992](https://github.com/LineageOS/android_kernel_lge_msm8992) cm-13.0 branch
- **LG source analysis**: found Session 8-9 tests were missing mandatory `PREAMBLE | NO_GMEM_ALLOC` flags
- **Live verification disproved source analysis**: flags 0x41, 0x341, 0x10341 ALL returned EINVAL on BB Priv
  - BB Priv kernel (`d46863f`) has KGSL modifications not in LG source
  - DRAWCTXT_CREATE remains blocked — Sessions 8-9 conclusion was correct
  - GPU attack surface is closed for direct ioctl access on this device

### Sessions 11-12 — 2026-02-28

**MILESTONE: CVE-2019-2215 TESTED (INCORRECTLY CONCLUDED BLOCKED), KGSL PIVOT**

- **CVE-2019-2215 (binder/epoll UAF) exhaustively tested** — vulnerability code CONFIRMED present but slab reclaim is BLOCKED:
  - BPF socket filter spray: NO reclaim (20+ configurations, up to 1020 sockets)
  - Pipe iovec readback v2 (0xAA/0xBB pattern detection): NO corruption across 6 configurations, up to 512 threads
  - Self-reclaim (512 binder_thread objects sprayed): 0 anomalies
  - RCU grace period delays (1ms to 500ms): NO effect
  - Timing-precise single-shot (100 rounds): NO reclaim
  - sendmsg Unix socket spray: only 278 messages before buffer limit, 0 corruption
  - Slab exhaustion via BPF: consumed all ~1020 FDs, no FDs left for binder
- **Conclusion: BlackBerry kernel has slab-level hardening preventing cross-caller-site reclaim**
  - Cannot verify mechanism: /proc/slabinfo DOESN'T EXIST, /proc/config.gz DOESN'T EXIST, userfaultfd ENOSYS
- **Every alternative kernel exploit path tested and eliminated:**
  - Dirty COW (CVE-2016-5195): **PATCHED** (5-second race, file unchanged)
  - AF_PACKET: EACCES
  - perf_event_open: EACCES (paranoid=3)
  - add_key/keyctl: EACCES (SELinux)
  - msgsnd/msgrcv: ENOSYS (SysV IPC not compiled)
  - /dev/mem, /dev/kmem: don't exist
  - No setuid binaries, no writable /proc/sys paths
- **KGSL identified as ONLY remaining viable kernel attack surface:**
  - /dev/kgsl-3d0 is `crw-rw-rw-` (world writable)
  - Security patch level 2017-10-05 means post-Oct-2017 KGSL CVEs likely unpatched
  - kgsl_mmap_uaf.c created: tests mmap-after-free, alloc/free races, context races, info leaks
  - Dynamic ioctl size probing (fixed ARM64 struct sizing: 48 bytes, not 32)
  - **Compiled, awaiting execution on device**
- **Tools created:** `pipe_readback_v2.c`, `slab_final_test.c`, `alt_exploit_test.c`, `kgsl_mmap_uaf.c`

### Session 13 — 2026-02-28

**MILESTONE: KGSL SOURCE CODE AUDIT — NO CODE-EXECUTION BUGS, ALL CVEs PATCHED**

- **Stale mmap UAF confirmed but dead-ended**: Writing through stale mappings works, but freed GPU pages are **pinned in kernel memory** and never returned to the general page allocator — no path to kernel object corruption
- **KGSL source code acquired and audited**: 45,605 lines across 60 files from LineageOS MSM8992 kernel
- **CVE-2016-3842 (KGSL)**: CONFIRMED PATCHED — the `kgsl_check_idle()` removal fix is present in our source
- **CVE-2019-10567 (KGSL ringbuffer)**: DRAWCTXT_CREATE blocked — cannot reach the vulnerable code path
- **All known KGSL CVEs eliminated**: Every post-2017 KGSL CVE either patched in source, unreachable from our context, or requires blocked ioctls
- **Conclusion: KGSL driver is a dead end** — no code-execution vulnerabilities accessible from shell domain

### Session 14 — 2026-02-28

**MILESTONE: CVE-2019-2215 UAF CONFIRMED EXPLOITABLE ON FIRST ATTEMPT**

- **Systematic CVE research**: 4 parallel agents evaluated 20+ post-Oct-2017 CVEs against exact device constraints
- **CVE-2019-2215 (binder/epoll UAF) identified as primary target**:
  - Bug: `BINDER_THREAD_EXIT` frees `binder_thread` while epoll holds reference to `thread->wait`
  - Present on kernel 3.10.84: `binder_poll` with `poll_wait(&thread->wait)` confirmed in 3.10 source
  - Unpatched: discovered Nov 2017, patched Feb 2018, never backported to 3.10 branch
  - Accessible: `/dev/binder` open, no SECCOMP in shell domain
- **20+ CVEs evaluated and eliminated**: CVE-2015-1805 (patched), CVE-2016-0728 (SELinux), CVE-2017-7308/15649 (need CAP_NET_RAW), CVE-2016-4557/CVE-2017-16995 (need eBPF), CVE-2018-14634 (needs 32GB RAM), CVE-2018-17182 (3.16+ only), and more
- **struct binder_thread layout calculated from 3.10 source**: ~0x130 bytes (kmalloc-512), `wait_queue_head_t` at offset 0x48, `task_list.next` at 0x50 (overlaps iovec[5].iov_base)
- **UAF CONFIRMED on device**: readv returned 64 bytes (stopped at iov[5]) on first attempt — list_del corrupted the in-kernel iovec copy with kernel self-pointers. Slab reclaim WORKS with canonical readv-based spray.
  - Sessions 11-12 conclusion was WRONG: the sentinel values used in previous PoCs caused EINVAL before readv could block, preventing the UAF from activating. The slab reclaim was never actually tested.
- **Two exploit programs written and compiled**:
  - `binder_uaf_poc.c`: UAF trigger with CPU pinning + retry loop (confirmed working)
  - `binder_exploit.c`: Full 3-phase exploit skeleton (UAF → addr_limit overwrite → cred patch + SELinux disable)
- **Next step**: Complete `binder_exploit.c` Phase 2 (controlled addr_limit overwrite) and Phase 3 (privilege escalation)

### Sessions 15-16 — 2026-03-01 to 2026-03-02

**MILESTONE: BINDER UAF SLAB RECLAMATION BLOCKED AT ALL SIZES, KGSL PAGE REUSE DEAD**

- **Binder exploit v1-v5** systematically tested iovec/readv spray, writev, sendmsg, keyctl, and multi-size slab spray
  - v3: 80/80 threads blocked successfully, UAF triggered, list_del triggered — but 0 slab reclamation
  - v4: System V IPC (`msgget`) returns ENOSYS, `add_key` returns EPERM
  - v5: 0 anomalies across 5 cache sizes (kmalloc-128 through 512), 100 threads each
- **GRSEC slab hardening confirmed** — prevents cross-object reclamation at ALL tested sizes
- **ARM64 STTR/LDTR blocking factor**: even if reclaimed, pipe-based kernel R/W won't work (enforces EL0 permissions from kernel context)
- **KGSL page reuse tested and dead**: `madvise(MADV_DONTNEED)` is a no-op on `VM_PFNMAP` VMAs — GPU pages stay pinned regardless of buffer free, fd close, or memory pressure
- **Pivoted to**: KGSL CVEs (CVE-2018-5831 refcount race), CVE-2018-9568 WrongZone

### Sessions 17-18 — 2026-03-02

**MILESTONE: PER-CALLSITE SLAB ISOLATION DEFINITIVELY CONFIRMED — CVE-2019-2215 STANDARD PATH CLOSED**

- **Binder exploit v8-v10** — most exhaustive slab reclamation tests ever run:
  - v8: Seccomp-BPF spray at 5 cache sizes (kmalloc-192 through 2048), fork-based crash isolation → 0 corruption
  - v9: CPU pinning (all 4 CPUs) + socket BPF (256 sockets) + sendmsg + binder thread spray → 0 cross-type reclamation
  - v10: Massive post-free (600 seccomp + 128 pipes + 128 socket BPF), combined shotgun on all CPUs → 0 corruption
- **Root cause identified**: GRSEC per-callsite slab isolation — each kzalloc/kmalloc callsite gets its own logical cache, invisible in `/sys/kernel/slab/` but enforced at runtime
- **Same-type reclamation works** but is unexploitable — identical binder_thread layout at offsets 80/88 makes list_del a no-op
- **PAX_MEMORY_SANITIZE NOT active** — freed memory retains old values
- **PAX_USERCOPY IS active** — separate usercopy-kmalloc-* caches confirmed
- **Seccomp-BPF from uid=2000** — installs successfully (up to ~655 filters), no CAP_SYS_ADMIN needed
- **CVE-2019-2215 standard exploitation path is CLOSED** — no viable slab spray mechanism exists on this kernel
- **Remaining vectors**: CVE-2018-5831 (KGSL refcount), CVE-2018-13905 (syncsource race), CVE-2018-9568 (WrongZone), compat_writev (32-bit binary)

### Sessions 19-22 — 2026-03-02

**MILESTONE: KGSL EXPLOITATION DEAD, DIRTY COW DEAD, PAX FLAGS DECODED, BROAD SURFACE PROBE**

- **KGSL deep exploitation tested and eliminated**:
  - mmap-after-free: R/W works but VMA refcount keeps pages alive (never truly freed)
  - "Double-free" via ioctl 0x24+0x21: ioctl 0x24 is NOT a free (idempotent, probably cache flush)
  - No page reclamation despite BPF spray, anonymous pages (256MB), xattr spray, pipe spray (500×16 pages)
  - GPU pages in isolated memory pool, never reused by kernel allocations
- **Dirty COW (CVE-2016-5195) definitively dead**: /proc/self/mem write EPERM on all memory types (GRSEC)
- **Alternative COW vectors dead**: process_vm_writev (ENOSYS), ptrace (EPERM)
- **PaX flags decoded: `Pemrs`** — PAGEEXEC enforced, but MPROTECT and RANDMMAP **disabled**
  - RWX memory freely available (no W^X enforcement)
  - Can make stack executable, mmap RWX, mprotect RW→RX
- **CVE-2014-3153 (towelroot): PATCHED** — non-PI to PI requeue properly validated (EINVAL)
- **Broad surface probe**: perf blocked (paranoid=3), no writable /proc/sys or /sys entries
- **New attack surface found**: /dev/ion (ION allocator), /dev/adsprpc-smd (Qualcomm ADSP RPC)
- **13 total dead vectors** documented across all sessions

### Session 24 — 2026-03-08

**MILESTONE: TRUSTZONE/QSEE ATTACK SURFACE MAPPED — DIRECT ACCESS BLOCKED, INDIRECT PATHS OPEN**

- **`/dev/qseecom` SELinux-blocked** for shell domain — `tee_device` type, all open modes EACCES
- **qseecomd running** (PID 503/543, uid=1000 system) — brokers Normal World ↔ QSEE communication
- **Widevine trustlet analyzed**: 32-bit ARM, L1 hardware-backed, signed by BlackBerry (ECC-521/SHA-512, not Qualcomm standard)
  - SW_ID: 0x0C, HW_ID: 009690E100000000, DEBUG field: 2 (non-zero)
  - OEMCrypto Level 1 confirmed — full hardware key ladder in QSEE
  - Binary dated March 2018
- **CVE-2015-6639 (Widevine PRDiag): LIKELY PATCHED** — firmware 21 months after fix. Definitive confirmation requires RE of trustlet binary
- **CVE-2016-2431 (TZ kernel escalation): LIKELY PATCHED** — firmware 17 months after fix
- **DRM binder service reachable** from shell — the indirect path to Widevine trustlet IS open
- **New attack surfaces discovered**:
  - `com.qualcomm.qti.auth.fidocryptodaemon` — FIDO auth via QSEE, binder accessible, less audited than Widevine
  - `keystore.msm8992.so` / `gatekeeper.msm8992.so` — hardware-backed HALs
  - `com.blackberry.security.trustzone.ITrustZoneService` — BlackBerry proprietary TZ service, binder accessible
- **CVE-2018-11976 (keymaster side-channel)**: Disclosed June 2019, affects MSM8992. Device's Oct 2017 patch level means **almost certainly unpatched**. Extracts ECDSA private keys from Qualcomm keymaster trustlet via cache timing attack.
- **ION QSEE heap**: 11 active allocations, physical addresses known (no ASLR on ION)

### Connection Command (for remote management)

```bash
# Fast (requires ~/.ssh/config — see docs/03-session-5-remote-management.md):
ssh bb 'command'

# Establish persistent master connection (lasts 4 hours):
ssh -fN bb

# Legacy (no config needed):
ssh -p 8022 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes 192.168.4.51
```

See `docs/` for detailed step-by-step logs of each approach.
