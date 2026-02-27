# Vector A: proot + Alpine Linux ARM64

**Status:** COMPLETE — Claude Code v2.1.62 installed and verified
**Estimated difficulty:** Hard (unexpected proot ELF interpreter issue)
**Estimated time:** 30-60 minutes

## Overview

Install a community-built `proot` binary for Android 5-7, download an Alpine Linux
aarch64 minirootfs, enter it via proot with kernel version spoofing, and install Node.js
20+ from Alpine's package manager.

## Prerequisites

- Termux installed and running on the BlackBerry Priv
- Internet connection on the phone
- (Optional) SSH access from Mac for easier typing

## Step 1: Fix Termux Package Sources (if needed)

The default Termux repos for Android 5/6 are dead. If `pkg update` fails:

```bash
# Point to the archived legacy repo
echo "deb https://archive.org/download/termux-repositories-legacy/termux-main-21-12-2019 stable main" > $PREFIX/etc/apt/sources.list
apt update
```

If that also fails, packages can be sideloaded via `adb push` from the Mac.

## Step 2: Install proot for Android 5-7

A community member (TokiZeng) maintains pre-built proot .deb files for Android 5-7:

```bash
# Download the community proot build
curl -L -O https://github.com/TokiZeng/proot-distro-for-Termux-Android-5.0-7.0/raw/main/proot_5.1.107-65_aarch64.deb

# Install it
apt install ./proot_5.1.107-65_aarch64.deb
```

**Note:** This is an unofficial community build. It's the most commonly referenced solution
for proot on Android 5/6, but review the repo if you have concerns.

### If curl/wget aren't available

Transfer the .deb from the Mac via ADB:

```bash
# On Mac:
curl -L -O https://github.com/TokiZeng/proot-distro-for-Termux-Android-5.0-7.0/raw/main/proot_5.1.107-65_aarch64.deb
adb push proot_5.1.107-65_aarch64.deb /data/data/com.termux/files/home/

# On phone (Termux):
apt install ./proot_5.1.107-65_aarch64.deb
```

## Step 3: Download Alpine Linux aarch64 Minirootfs

```bash
mkdir -p ~/alpine && cd ~/alpine

# Download Alpine 3.20 minirootfs (latest stable)
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.0-aarch64.tar.gz

# Extract it
tar --warning=no-unknown-keyword -xf alpine-minirootfs-3.20.0-aarch64.tar.gz
```

If wget isn't available, download on Mac and ADB push:

```bash
# On Mac:
curl -L -O https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.0-aarch64.tar.gz
adb push alpine-minirootfs-3.20.0-aarch64.tar.gz /data/data/com.termux/files/home/alpine/
```

## Step 4: Configure DNS

Networking inside proot won't work without explicit DNS config:

```bash
echo "nameserver 8.8.8.8" > ~/alpine/etc/resolv.conf
echo "nameserver 1.1.1.1" >> ~/alpine/etc/resolv.conf
```

## Step 5: Enter Alpine via proot

**IMPORTANT:** The naive `proot -r ~/alpine /bin/sh` does NOT work on Android 6.
You must invoke the musl dynamic loader directly (see Actual Results for full explanation).

```bash
PROOT_NO_SECCOMP=1 proot \
  --kill-on-exit \
  -r ~/alpine \
  -b /proc:/proc \
  -b /sys:/sys \
  -b /dev:/dev \
  -b /dev/urandom:/dev/urandom \
  -0 \
  -w /root \
  /lib/ld-musl-aarch64.so.1 /bin/busybox sh -c \
  'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && exec sh -l'
```

Key flags:
- `PROOT_NO_SECCOMP=1` — Seccomp acceleration crashes on kernel 3.10
- `/lib/ld-musl-aarch64.so.1` — Invoke musl loader directly (kernel can't resolve ELF interpreter)
- `-r ~/alpine` — Root filesystem
- `-b /proc:/proc` etc. — Bind-mount essential filesystems
- `-0` — Fake root (required for package management)
- **DO NOT USE `-k 4.14.0`** — Breaks Node.js CSPRNG (see Step 5.6)

### Verify you're in Alpine:

```bash
cat /etc/os-release
node --version  # Should show v20.x
```

## Step 5.5: Switch Alpine Repos to HTTP

HTTPS/TLS causes proot to segfault on kernel 3.10. Switch to HTTP:

```bash
echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/main" > /etc/apk/repositories
echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/community" >> /etc/apk/repositories
```

## Step 6: Install Node.js

```bash
apk update
apk add nodejs npm
node --version  # Expect v20.15.1
npm --version   # Expect 10.9.1
```

## Step 7: Install Claude Code

```bash
npm install -g @anthropic-ai/claude-code
```

### If it fails, try these fixes:

```bash
# Fix the sharp module (if it errors):
npm install -g @img/sharp-wasm32 --force
npm install -g sharp --force

# Fix /tmp paths (if Claude Code fails with EACCES):
mkdir -p /tmp/claude
export TMPDIR=/tmp
```

## Step 8: Authenticate and Run Claude Code

On a machine where Claude Code is already logged in, generate a setup token:

```bash
claude setup-token
# Copy the sk-ant-oat01-... token it displays
```

Then write it to Alpine's profile on the phone (via SSH or inside Termux):

```bash
# Inside Alpine proot:
echo 'export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-YOUR-TOKEN-HERE' >> /root/.profile
source /root/.profile
claude
```

Alternatively, use an API key if you have one:

```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-api03-YOUR-KEY-HERE' >> /root/.profile
```

## Step 9: Create a Launcher Script

Save this to `~/start-alpine.sh` in Termux (outside proot):

```bash
#!/data/data/com.termux/files/usr/bin/bash
# Launch Alpine Linux proot and drop straight into Claude Code
# CRITICAL: No kernel spoof (-k) — Node.js CSPRNG crashes with spoofed getrandom
# CRITICAL: Must invoke musl loader directly — kernel can not resolve it on Android 6
PROOT_NO_SECCOMP=1 proot \
  --kill-on-exit \
  -r ~/alpine \
  -b /proc:/proc \
  -b /dev:/dev \
  -b /dev/urandom:/dev/urandom \
  -b /sys:/sys \
  -0 \
  -w /root \
  /lib/ld-musl-aarch64.so.1 /bin/busybox sh -c \
  "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && export HOME=/root && . /root/.profile && claude; reset; exec sh -l"
```

Key changes from initial version:
- `. /root/.profile` — sources the OAuth token before launching Claude
- `claude; reset; exec sh -l` — when Claude exits, `reset` restores terminal from raw mode,
  then `exec sh -l` drops to an Alpine login shell instead of killing Termux

```bash
chmod +x ~/start-alpine.sh
```

## Step 10: Auto-Launch Alpine When Termux Opens

Save this as `~/.bashrc` in Termux (outside proot):

```bash
# Start SSH server for remote access (survives the Alpine exec)
sshd 2>/dev/null

# Auto-launch Alpine Linux proot
# To skip: touch ~/.no-alpine (then restart Termux)
# To re-enable: rm ~/.no-alpine
if [ ! -f /etc/alpine-release ] && [ ! -f ~/.no-alpine ] && [[ $- == *i* ]]; then
  exec ~/start-alpine.sh
fi
```

Key features:
- `sshd 2>/dev/null` runs BEFORE the exec, so SSH is always available on port 8022
- `2>/dev/null` suppresses "already running" errors on subsequent sessions
- Checks `/etc/alpine-release` to prevent recursion (won't trigger if already in Alpine)
- Checks `~/.no-alpine` — touch this file to disable auto-launch
- Checks `$-` for interactive flag — won't trigger for SSH remote commands

## Step 11: Skip Onboarding and Auth Selection Screens

Claude Code shows onboarding TUI screens (Getting Started, Select Login Method) on
first launch. These require interactive input that's fragile on proot. Skip them by
setting completion flags in the state file.

Claude Code stores its state in TWO places:
- `/root/.claude.json` — main state file (onboarding flags, feature flags, user ID)
- `/root/.claude/settings.json` — user settings (theme, permissions)

Set the onboarding flags via Node.js inside Alpine:

```bash
# Run from Termux (outside proot), or via SSH:
PROOT_NO_SECCOMP=1 proot -r ~/alpine -b /proc:/proc -b /dev:/dev -b /sys:/sys -0 -w /root \
  /lib/ld-musl-aarch64.so.1 /bin/busybox sh -c \
  'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && export HOME=/root && node -e "
const fs=require(\"fs\");
const p=\"/root/.claude.json\";
const d=fs.existsSync(p)?JSON.parse(fs.readFileSync(p)):{};
d.hasCompletedOnboarding=true;
d.hasCompletedAuthFlow=true;
d.hasCompletedProjectOnboarding=true;
fs.writeFileSync(p,JSON.stringify(d,null,2));
console.log(\"flags set\");
"'
```

The three critical flags:
- `hasCompletedOnboarding` — skips the "Getting Started" screen
- `hasCompletedAuthFlow` — skips the "Select Login Method" screen
- `hasCompletedProjectOnboarding` — skips the project intro screen

Also create the settings file:

```bash
PROOT_NO_SECCOMP=1 proot -r ~/alpine -b /proc:/proc -b /dev:/dev -b /sys:/sys -0 -w /root \
  /lib/ld-musl-aarch64.so.1 /bin/busybox sh -c \
  '/bin/busybox mkdir -p /root/.claude && /bin/busybox echo '"'"'{"hasCompletedOnboarding":true,"theme":"dark"}'"'"' > /root/.claude/settings.json'
```

Note: inside the proot busybox shell, commands like `mkdir` and `echo` need to be
prefixed with `/bin/busybox` because PATH isn't set up yet in this one-shot context.

## Step 12: Emergency Recovery (Termux Failsafe)

If the auto-launch creates a boot loop (Claude exits, Termux closes, reopen launches
Claude again), use Termux's failsafe session:

1. Open Termux (Claude will auto-launch)
2. Press **Ctrl+C** immediately to kill proot
3. When you see "process completed, press enter" — **DON'T press Enter**
4. **Swipe from the left edge** of the screen to open the session drawer
5. Tap **FAILSAFE** at the bottom of the drawer

The failsafe shell uses `/system/bin/sh` without sourcing `.bashrc`. It doesn't have
Termux's library paths, so you need to set them manually:

```bash
# Set Termux library path (failsafe shell doesn't have it)
export LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib

# Disable auto-launch
touch /data/data/com.termux/files/home/.no-alpine

# Start SSH server for remote fixes
/data/data/com.termux/files/usr/bin/sshd
```

Then SSH in from another machine to apply fixes. Re-enable auto-launch with:
```bash
rm ~/.no-alpine
```

## Step 13: Fix "No Suitable Shell Found" Error

Claude Code requires a `SHELL` environment variable pointing to a valid Posix shell.
Alpine's proot environment doesn't set this by default, causing Claude to error with
"No suitable shell found. Claude CLI requires a Posix shell environment."

Install bash and set the env var:

```bash
# Inside Alpine (via SSH + proot or interactive session):
apk add bash git  # bash for SHELL, git for Claude Code VCS features
```

Add to `/root/.profile`:
```bash
export SHELL=/bin/bash
```

Note: `apk add bash` shows harmless terminfo permission errors during install — ignore them.

## Step 14: Startup Performance Tuning

Claude Code startup through proot takes ~21 seconds. The main bottlenecks:

| Phase | Duration | Notes |
|-------|----------|-------|
| TUI/Ink initialization | ~8-9s | React rendering through ptrace — unavoidable |
| MCP config scanning | ~3-4s | Scans for 0 servers, internal to Claude Code |
| OAuth 403 errors | ~5s | Setup token lacks scopes, calls always fail |
| API call latency | ~1-2s | Network round-trip, irreducible |

Add performance env vars to `/root/.profile`:

```bash
# Skip OAuth profile/client_data calls (always 403 with setup token)
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# Skip auto-update checks
export DISABLE_AUTOUPDATER=1

# Limit V8 heap on 3GB device
export NODE_OPTIONS="--max-old-space-size=512"
```

The complete `/root/.profile` should now contain:

```bash
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
export SHELL=/bin/bash

# Performance: skip OAuth profile/client_data calls (always 403 with setup token)
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# Performance: skip auto-update checks
export DISABLE_AUTOUPDATER=1

# Performance: limit V8 heap on 3GB device
export NODE_OPTIONS="--max-old-space-size=512"
```

Realistic startup after tuning: **~16-18 seconds** (with 2-3s run-to-run variance from proot overhead).

## Step 15: --dangerously-skip-permissions Is Incompatible with proot -0

`--dangerously-skip-permissions` cannot be used when running as root. proot's `-0` flag
(fake root) makes Claude Code detect uid 0, which triggers a security check:

```
--dangerously-skip-permissions cannot be used with root/sudo privileges for security reasons
```

There is no workaround short of removing `-0` from proot, which would break `apk` and
other root-requiring operations. The flag is not essential — Claude Code works fine
without it, just prompts for tool permissions interactively.

## Known Risks

| Risk | Severity | Mitigation | Status |
|------|----------|------------|--------|
| proot .deb is community-built | Medium | Inspect before installing | ACCEPTED |
| HTTPS/TLS segfaults in proot | **Critical** | Use HTTP repos only (Step 5.5) | SOLVED |
| Kernel spoof breaks Node.js CSPRNG | **Critical** | Don't use `-k 4.14.0` (Step 5.6) | SOLVED |
| ELF interpreter not found on Android | **Critical** | Invoke musl loader directly (Step 5) | SOLVED |
| getrandom syscall missing (kernel 3.10) | High | Don't spoof kernel; Node falls back to /dev/urandom | SOLVED |
| Performance overhead (ptrace + no seccomp) | Medium | CLI is viable; API latency dominates anyway | ACCEPTED |
| GitHub .deb URL returns 404 | Low | Download ZIP, extract, serve from Mac HTTP | SOLVED |
| Terminal raw mode on Claude exit | **Critical** | `reset; exec sh -l` after claude in launcher | SOLVED |
| exec chain kills Termux on exit | **Critical** | Shell fallback after reset (Step 9) | SOLVED |
| sshd doesn't survive reboot | Medium | Auto-start in .bashrc before exec (Step 10) | SOLVED |
| Boot loop if Claude can't start | High | Failsafe session recovery (Step 12) | SOLVED |
| SHELL env var not set in Alpine | High | Install bash, set SHELL=/bin/bash (Step 13) | SOLVED |
| Startup takes ~21 seconds | Medium | Performance env vars reduce to ~16-18s (Step 14) | MITIGATED |
| --dangerously-skip-permissions fails | Low | Incompatible with proot -0 fake root (Step 15) | KNOWN |

## Actual Results

### Step 1 Result: FAILED initially, then FIXED
- Termux frozen repo repos work fine for `apt install libtalloc`
- The GitHub URL `https://github.com/TokiZeng/.../raw/main/proot_5.1.107-65_aarch64.deb` returns 404
- The .deb files are inside a ZIP: `proot-distro_4.16.0_all.zip`
- Had to download ZIP on Mac, extract, serve via `python3 -m http.server 9999`
- Phone downloaded from Mac: `curl -o ~/proot.deb http://192.168.4.32:9999/proot_5.1.107-65_aarch64.deb`
- `dpkg -i ~/proot.deb` needed libtalloc: `apt install libtalloc` from frozen repo worked
- proot 5.1.0 installed with process_vm and seccomp_filter accelerators

### Step 2 Result: SUCCESS
- `dpkg -i` initially failed: needed `apt install libtalloc` first
- After libtalloc: both proot and libtalloc configured successfully
- `proot --version` shows 5.1.0 with both accelerators

### Step 3 Result: SUCCESS
- `curl -L -o ~/alpine.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.0-aarch64.tar.gz`
- 3.9MB download, extracted to ~/alpine
- Alpine Linux v3.20 confirmed via /etc/os-release

### Step 4 Result: SUCCESS
- DNS configured: `nameserver 8.8.8.8` and `nameserver 1.1.1.1`

### Step 5 Result: MAJOR ISSUE FOUND AND SOLVED

**The Problem:** `proot -r ~/alpine /bin/sh` always fails with:
```
proot error: execve("/bin/sh"): No such file or directory
```
Even though `/bin/sh` exists in the rootfs. The error says "ELF but its interpreter
(eg. ld-linux.so) was not found" — the kernel tries to load `/lib/ld-musl-aarch64.so.1`
at the HOST level before proot can intercept the execve. On Android (Bionic), this
path doesn't exist on the real filesystem.

**Things that did NOT fix it:**
- `--link2symlink` flag
- `-0` (fake root) flag
- `PROOT_NO_SECCOMP=1`
- `-R` instead of `-r`
- Fixing symlinks (sh -> busybox relative vs absolute)
- Calling /bin/busybox directly instead of /bin/sh

**THE FIX:** Invoke the musl dynamic loader directly as the entry point:
```bash
proot -r ~/alpine /lib/ld-musl-aarch64.so.1 /bin/busybox sh
```

This bypasses the kernel's ELF interpreter resolution entirely. The musl loader
is a statically-linked binary itself, so the kernel can execute it without needing
another interpreter. It then loads and runs busybox.

**Working proot command:**
```bash
proot --kill-on-exit -k 4.14.0 -r ~/alpine \
  -b /proc:/proc -b /dev:/dev -b /dev/urandom:/dev/urandom \
  -w /root /lib/ld-musl-aarch64.so.1 /bin/busybox sh \
  -c "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && uname -r"
```

Output: `4.14.0` — kernel spoof working, Alpine shell running.

### Step 5.5: HTTPS/TLS Segfault in proot — DISCOVERED AND SOLVED

**The Problem:** `apk update` segfaults (signal 11) inside proot when repos use HTTPS:
```
fetch https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/APKINDEX.tar.gz
proot info: vpid 1: terminated with signal 11
```

This happens even with `PROOT_NO_SECCOMP=1`. The TLS/SSL operations trigger
syscalls that proot 5.1.0 cannot properly intercept on kernel 3.10.

**THE FIX:** Switch Alpine repos from HTTPS to HTTP:
```bash
echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/main" > /etc/apk/repositories
echo "http://dl-cdn.alpinelinux.org/alpine/v3.20/community" >> /etc/apk/repositories
```

Basic HTTP networking works fine through proot. Only HTTPS/TLS causes the segfault.

### Step 5.6: Kernel Spoof Breaks Node.js CSPRNG — DISCOVERED AND SOLVED

**The Problem:** With `-k 4.14.0` kernel spoof, `npm --version` crashes:
```
Assertion failed: crypto::CSPRNG(nullptr, 0).is_ok()
proot info: vpid 1: terminated with signal 6
```

Node.js thinks it's on kernel 4.14 → tries `getrandom()` syscall (added in 3.17) →
real kernel 3.10 doesn't have it → proot doesn't properly intercept → CSPRNG fails → abort.

**THE FIX:** Don't use kernel version spoofing. Remove `-k 4.14.0` from proot command.
Without the spoof, Node.js sees kernel 3.10, falls back to `/dev/urandom`, works correctly.

Note: `-k 4.14.0` was originally added for `uname -r` spoofing, but Node 20 from Alpine
musl builds apparently doesn't enforce a minimum kernel version check. If Claude Code
later needs a spoofed kernel version, we'll need a different approach (e.g., LD_PRELOAD
shim for getrandom).

### Step 6 Result: SUCCESS
- HTTPS repos crash proot with signal 11 — switched to HTTP repos (see Step 5.5)
- `apk update` fetched 24,058 packages from Alpine v3.20
- `apk add nodejs npm` installed 12 packages (76 MiB total)
- **Node.js v20.15.1** confirmed via `node --version`
- **npm 10.9.1** confirmed via `npm --version`
- CRITICAL: Must NOT use `-k 4.14.0` kernel spoof with Node (see Step 5.6)
- Must use `PROOT_NO_SECCOMP=1` and `-0` (fake root) flags

### Step 7 Result: SUCCESS
- `npm install -g @anthropic-ai/claude-code` completed in ~1 minute
- Installed 3 packages
- Claude Code v2.1.62 confirmed via `claude --version`
- `claude --help` outputs full usage information

### Step 8 Result: SUCCESS — FIRST API CALL CONFIRMED

**Authentication:** OAuth token via `CLAUDE_CODE_OAUTH_TOKEN` env var.
- `claude auth login` and `claude setup-token` both require interactive TUI — can't pipe tokens
- Solution: generate token on another machine via `claude setup-token`, copy the `sk-ant-oat01-...` string
- Set in Alpine's profile: `echo 'export CLAUDE_CODE_OAUTH_TOKEN=...' >> /root/.profile`

**First successful API call:**
```bash
$ claude -p "Say hello from BlackBerry Priv in exactly 8 words"
Hello from the iconic BlackBerry Priv sliding keyboard phone!
```

**Auto-launch configured:**
- `~/start-alpine.sh` now launches Claude Code directly (not just Alpine shell)
- `~/.bashrc` in Termux auto-runs `start-alpine.sh` for interactive sessions
- Opening Termux = straight into Claude Code, fully authenticated
- Escape hatch: `touch ~/.no-alpine` to disable auto-launch

### Updated Launcher Script (~/start-alpine.sh)

The final working launcher script incorporates ALL discoveries:

```bash
#!/data/data/com.termux/files/usr/bin/bash
# Launch Alpine Linux proot and drop straight into Claude Code
# CRITICAL: No kernel spoof (-k) — Node.js CSPRNG crashes with spoofed getrandom
# CRITICAL: Must invoke musl loader directly — kernel can not resolve it on Android 6
PROOT_NO_SECCOMP=1 proot \
  --kill-on-exit \
  -r ~/alpine \
  -b /proc:/proc \
  -b /dev:/dev \
  -b /dev/urandom:/dev/urandom \
  -b /sys:/sys \
  -0 \
  -w /root \
  /lib/ld-musl-aarch64.so.1 /bin/busybox sh -c \
  "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && export HOME=/root && . /root/.profile && claude; reset; exec sh -l"
```

Key details:
- Auth is handled via `CLAUDE_CODE_OAUTH_TOKEN` in `/root/.profile` (sourced before claude)
- `claude; reset; exec sh -l` — semicolons mean: run claude, when it exits run reset, then drop to shell
- `reset` clears terminal raw mode that Claude Code's Ink TUI leaves behind
- `exec sh -l` gives an Alpine login shell as a fallback instead of killing Termux
- **Note:** `--dangerously-skip-permissions` cannot be used because proot's `-0` (fake root) makes Claude see uid 0, which triggers a security check that blocks the flag

### Updated .bashrc (Termux, outside proot)

```bash
# Start SSH server for remote access (survives the Alpine exec)
sshd 2>/dev/null

# Auto-launch Alpine Linux proot
# To skip: touch ~/.no-alpine (then restart Termux)
# To re-enable: rm ~/.no-alpine
if [ ! -f /etc/alpine-release ] && [ ! -f ~/.no-alpine ] && [[ $- == *i* ]]; then
  exec ~/start-alpine.sh
fi
```

Key detail: `sshd` runs BEFORE the `exec`, so SSH is always available even if the Alpine
launch fails. The `2>/dev/null` suppresses "already running" noise on subsequent sessions.

### Settings.json (Alpine, /root/.claude/settings.json)

```json
{"hasCompletedOnboarding":true,"theme":"dark"}
```

Skips the onboarding "Getting Started" screen that appears on every launch.

### Session 3 Recovery: Termux Failsafe Discovery

When the exec chain created a boot loop (Claude exits -> Termux closes -> reopen ->
Claude launches again), recovery was achieved via Termux's **failsafe session**:

1. Open Termux, Ctrl+C to kill proot
2. At "process completed" prompt, swipe from left edge to open session drawer
3. Tap FAILSAFE — this runs `/system/bin/sh` without `.bashrc`
4. Failsafe shell needs Termux library path:
   ```bash
   export LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib
   touch /data/data/com.termux/files/home/.no-alpine
   /data/data/com.termux/files/usr/bin/sshd
   ```
5. SSH in from Mac and apply fixes

### Summary of All Required Flags

| Flag/Env | Required | Why |
|----------|----------|-----|
| `PROOT_NO_SECCOMP=1` | YES | seccomp acceleration causes crashes on kernel 3.10 |
| `--kill-on-exit` | YES | Clean up child processes when proot exits |
| `-r ~/alpine` | YES | Root filesystem |
| `-b /proc:/proc` | YES | Process information |
| `-b /dev:/dev` | YES | Device access |
| `-b /dev/urandom:/dev/urandom` | YES | Random number generation for Node.js |
| `-b /sys:/sys` | YES | System information |
| `-0` | YES | Fake root (required for apk) |
| `-w /root` | YES | Working directory |
| `/lib/ld-musl-aarch64.so.1` | YES | Musl loader as entry point (Android ELF fix) |
| `-k 4.14.0` | **NO** | Breaks Node.js CSPRNG — do NOT use |
| `--dangerously-skip-permissions` | **NO** | Blocked by proot's `-0` fake root (uid 0 check) |
| HTTP repos (not HTTPS) | YES | HTTPS/TLS causes proot segfault |
| `SHELL=/bin/bash` | YES | Claude Code requires SHELL env var |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | Recommended | Eliminates dead OAuth 403 calls (~5s saved) |
| `DISABLE_AUTOUPDATER=1` | Recommended | Skips update checks |
| `NODE_OPTIONS="--max-old-space-size=512"` | Recommended | Limits V8 heap on 3GB device |
