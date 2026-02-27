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

### Connection Command (for remote management)

```bash
ssh -p 8022 -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes 192.168.4.51
# sshd now starts automatically when Termux opens
# If phone rebooted: just open Termux, sshd starts via .bashrc
```

See `docs/` for detailed step-by-step logs of each approach.
