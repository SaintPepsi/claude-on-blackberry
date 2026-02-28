# Video Design: Claude Code on BlackBerry Priv — Part 1

> Getting Claude Code running on a 2015 BlackBerry Priv, told as a story/journey with a comedic hook and genuine technical depth.

## Overview

| What         | Decision                                     |
| ------------ | -------------------------------------------- |
| Format       | Story/Journey                                |
| Length       | 5-8 minutes (~900-1,400 words of script)     |
| Platform     | YouTube (primary), Twitter/X teaser (60-90s) |
| Audience     | Tech/dev + broader tech-curious              |
| Scope        | Sessions 1-3 only (getting Claude running)   |
| Sequel       | Part 2: Root exploit arc (sessions 6-8)      |
| Presentation | Voiceover + screen recordings + IRL B-roll   |
| On-camera    | No                                           |

## The Hook: Fake-Real Paper Reveal

```
[SHOT: Phone with printed Claude Code screenshot taped to screen]
[VO]: "I got Claude Code running on a BlackBerry Priv."
[BEAT — let it sit, looks legit from a distance]
[SHOT: Hand peels off the paper]
[VO]: "OK, that's fake."
[BEAT]
[SHOT: Phone boots Termux, Claude actually loads]
[VO]: "But this isn't."
[TITLE CARD]
```

The gag establishes humor, proves authenticity, and hooks the viewer in ~10 seconds.

## Narrative Structure

### Cold Open — The Hook (0:00-0:15)

- Paper reveal gag (above)
- Title card

### Act 1 — The Problem (0:15-1:30)

- Show the BlackBerry Priv. 2015. Sliding keyboard.
- Claude Code needs Node.js 18. This phone runs Android 6.0.1.
- Three obvious paths, all blocked:
  1. `pkg install nodejs` = Node 13 only (frozen Termux repo)
  2. `proot-distro` = requires Android 7+
  3. Compile Node 18 natively = kernel 3.10 < required 4.18
- "Every obvious path is a dead end."

**Visuals:** Phone IRL shots, terminal showing version numbers, text overlays showing the three blocked paths.

### Act 2 — The Hack (1:30-5:00)

- The proot vector: raw proot + Alpine Linux ARM64 chroot inside Termux
- Brief explainer: proot intercepts syscalls via ptrace, creates a fake Linux environment

Then the six discoveries, each as a mini-crisis:

1. **musl ELF Interpreter** — "No such file or directory" when the file exists. Kernel resolves the ELF interpreter at host level before proot can intercept. Fix: invoke the musl dynamic loader directly.

2. **HTTPS Segfaults** — `apk update` crashes with SIGSEGV. TLS operations break under proot on kernel 3.10. Fix: switch to HTTP repos.

3. **CSPRNG Crash** — Kernel version spoofing makes Node.js think `getrandom()` exists, assertion failure. Fix: don't spoof the kernel version.

4. **seccomp Crashes** — proot's seccomp fast path crashes on old kernel. Fix: `PROOT_NO_SECCOMP=1`.

5. **OAuth on Headless Device** — `claude auth login` needs an interactive TUI. Can't pipe tokens. Fix: generate token on another machine, set as env var.

6. **Terminal Boot Loop** — Claude's TUI puts terminal in raw mode. exec chain means no parent shell to return to. Termux closes. Every reopen auto-launches Claude again. Fix: `reset; exec sh -l` after claude in launcher.

**Pacing:** Each discovery is 20-30 seconds. Problem statement, brief "why," fix. Don't linger. The rhythm of "hit wall, solve, hit wall, solve" creates momentum.

**Visuals:** Terminal sessions showing each error and fix. Text overlays for the technical concepts. Diagrams for the architecture stack.

### Act 3 — The Payoff (5:00-6:00)

- Claude responds from the BlackBerry Priv
- Show it actually working: type a question, get an answer
- Use existing video footage of first successful run
- "But then I wondered... what if I could root this phone?"
- Tease the Dirty COW / KGSL fuzzing arc
- End card: subscribe for Part 2

**Visuals:** Terminal showing Claude responding. IRL shot of phone with Claude running. Walking video showing mobile usage.

### Optional: End Card (6:00-6:30)

- Architecture diagram: Android > Termux > proot > Alpine > Node > Claude
- "Full setup guide in the description"
- Subscribe CTA

## Visual Assets Needed

### Screen Recordings (to capture/recreate)

- [ ] Termux opening on the phone
- [ ] Alpine Linux booting in proot
- [ ] Each of the six error messages (can recreate from session logs)
- [ ] Node.js version check showing v20
- [ ] Claude Code launching
- [ ] Claude responding to a question
- [ ] The architecture stack (text/diagram overlay)

### IRL Footage (already captured)

- [ ] Screenshots of the process (scattered across devices)
- [ ] Video: accepting commands while walking
- [ ] Video: first run attempt, bash execution blocked
- [ ] Phone sliding keyboard open (to capture)
- [ ] Phone at desk next to modern hardware (to capture)
- [ ] Close-up of phone screen showing Claude (to capture)

### Graphics/Overlays (to create)

- [ ] Title card
- [ ] Architecture diagram (Termux > proot > Alpine > Node > Claude)
- [ ] "Dead end" overlays for the three blocked paths
- [ ] Text overlays for the six discoveries
- [ ] Thumbnail (possibly the paper gag shot)
- [ ] End card with Part 2 tease

### The Paper Gag (to create)

- [ ] Print a screenshot of Claude Code terminal
- [ ] Tape it to the phone screen
- [ ] Film: holding it, looks real from distance
- [ ] Film: peeling it off

## Twitter/X Teaser (60-90 seconds)

Compressed version: Hook (paper gag) > "This phone is from 2015, Claude needs Node 18, every path was blocked" > Quick montage of the six discoveries > Payoff (Claude responds) > "Full video on YouTube"

## Reference Videos

| Channel      | Video                                                                            | Why It's Relevant                                       |
| ------------ | -------------------------------------------------------------------------------- | ------------------------------------------------------- |
| sw7ft        | BB10 git/curl/openssl, QNX Dev Update, Running Linux on BB10, Ubuntu on Passport | Content niche overlap: BlackBerry + Linux revival scene |
| David Bombal | Kali Linux NetHunter Android install in 5 minutes                                | Practical tutorial, similar "install X on phone" format |
| jvscholz     | why I use a blackberry in 2024 (as a programmer)                                 | Personal essay angle, programmer using old hardware     |

Transcripts saved in: `docs/reference-videos/`

## Terminal Replay Visualizer

A custom HTML/JS page that simulates a terminal "replaying" Claude's session, showing commands typing out, errors appearing, fixes being applied, and discovery banners between sections.

**Purpose:** Cinematic B-roll for Act 2 (The Hack). Way more watchable than raw terminal recordings. Full control over pacing, colors, and dramatic timing.

**Tech:** Single HTML file with inline JS/CSS. No build tools. Data-driven from a JSON sequence array.

**Features:**
- Dark terminal aesthetic (monospace, dark background, green/white text)
- Characters type out at realistic speed (~50ms/char for commands, instant for output)
- Error output in red, success in green
- Discovery banners (e.g., "Discovery #1: musl ELF Interpreter") appear between sections
- Configurable speed (play/pause, speed up/slow down for screen recording)
- Data sourced from actual session logs in `docs/`

**Sequence structure (JSON):**
```json
[
  {"type": "command", "text": "proot -r ~/alpine /bin/sh", "delay": 500},
  {"type": "error", "text": "No such file or directory", "delay": 1000},
  {"type": "banner", "text": "Discovery #1: musl ELF Interpreter", "delay": 2000},
  {"type": "command", "text": "proot -r ~/alpine /lib/ld-musl-aarch64.so.1 /bin/busybox sh", "delay": 500},
  {"type": "success", "text": "/ #", "delay": 1000}
]
```

**Location:** `tools/terminal-replay/index.html`

## Production Notes

- First video ever. Keep it achievable.
- Voiceover gives full control over pacing. Can re-record any line.
- Existing session logs in `docs/` provide exact terminal commands and outputs.
- The real footage (walking video, failed bash video) adds authenticity.
- Script target: 900-1,100 words for 5-6 minutes at natural speaking pace.

## Next Steps

1. Gather all existing footage to one location
2. Write the full script (using this structure)
3. Capture any missing screen recordings (can recreate from session logs)
4. Capture IRL B-roll (phone shots, paper gag)
5. Record voiceover
6. Edit
7. Create thumbnail
8. Create Twitter teaser cut
