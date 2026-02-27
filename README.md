# Claude Code on BlackBerry Priv (Android 6.0.1)

Running Claude Code CLI on a BlackBerry Priv STV100-3 with Android 6.0.1.

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

## The Solution: Two Attack Vectors

### Vector A: proot + Alpine Linux (Recommended First Try)

Use raw `proot` (not proot-distro) to create an Alpine Linux ARM64 chroot inside Termux.
Alpine provides Node.js 20+ via `apk`. proot intercepts syscalls via ptrace and can fake
the kernel version with `-k 4.14.0`.

**Pros:** Pre-built Node, battle-tested, no compilation needed.
**Cons:** ~25-75% performance overhead from ptrace syscall interception. Networking may
need manual DNS config.

### Vector B: Cross-Compiled Static Node.js Binary

Build a fully static Node.js 18 binary linked against musl libc using Docker on macOS.
Static binary has zero runtime dependencies — no glibc, no Bionic, no musl shared libs
needed on the device.

**Pros:** Native performance, no proot overhead.
**Cons:** Kernel 3.10 may lack `memfd_create` (3.17+) which V8 might use. Needs testing.

## Progress

### Session 1 — 2026-02-27

**MILESTONE: SSH ACCESS TO PHONE FROM MAC — CONFIRMED WORKING**

- Termux installed and running on BlackBerry Priv
- Node.js 13 installed via pkg (confirms Termux package system works)
- Claude Code installed but won't run (Node 13 too old — expected)
- USB/ADB: FAILED (charge-only cable/adapter chain, no data lines)
- SSH over WiFi: SUCCESS
  - `pkg install openssh` on phone
  - `sshd` running on port 8022
  - Phone IP: `192.168.4.51`
  - Password auth: works (password: "nani")
  - Key auth: works (`-i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes`)
  - **Maple can execute commands on the phone remotely**

### Next Session: Vector A Execution

1. Install proot (community build for Android 5-7)
2. Download Alpine Linux aarch64 minirootfs
3. Enter Alpine via proot with kernel version spoofing (-k 4.14.0)
4. Install Node.js 20+ via apk
5. Install Claude Code
6. Run Claude Code

### Connection Command (for next session)

```bash
# Maple connects to BlackBerry Priv:
ssh -p 8022 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes 192.168.4.51

# Note: sshd must be running on the phone first.
# If phone was rebooted, open Termux and type: sshd
```

See `docs/` for step-by-step logs of each approach.
