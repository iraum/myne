# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file curses TUI (`monitor.py`) that lists Linux processes and lets the user kill them. Python 3, stdlib only — no dependencies, no build step, no test suite.

## Run

```
./monitor.py        # or: python3 monitor.py
```

Linux only. Reads `/proc` directly; no `psutil`, no shelling out to `ps`.

## The central design decision: loginuid, not TTY

The whole reason this exists (vs. `top`/`htop`) is to answer "did *I* start this?" correctly even when the process was `nohup`'d, `disown`'d, double-forked, or escalated through `sudo`. The naive signal — controlling TTY — fails for all of those.

The tool uses **`/proc/<pid>/loginuid`** instead. PAM stamps this at login, the kernel inherits it across `fork`/`exec`/`setuid`, and **nothing in userspace can reset it without `CAP_AUDIT_CONTROL`**. So a nohup'd process that lost its TTY hours ago still reports your original login uid.

If you change the categorization logic, preserve this: TTY presence only distinguishes `MINE` from `MINE-BG` *within* the loginuid-matches-me bucket. It is never the primary signal.

## Category taxonomy

Buckets are decided in this fixed order (`categorize()` in `monitor.py`). Order matters — earlier rules win:

1. **KERNEL** — `pid == 2` (kthreadd) or `ppid == 2`. Detected structurally, not by empty cmdline (some daemons clear argv).
2. **SYSTEM** — cgroup contains `system.slice`. A root-owned daemon under `system.slice` is `SYSTEM`, not `ROOT`.
3. **MINE** / **MINE-BG** — `loginuid == my_uid`. `MINE` if it has a controlling TTY, `MINE-BG` otherwise (nohup, disown, `systemd --user` children of your login session).
4. **USER-SVC** — `uid == my_uid` but `loginuid != my_uid`. Typically processes spawned by a `systemd --user` instance that started outside your current login chain.
5. **ROOT** — root-owned and not already classified as `SYSTEM` or `KERNEL`. Worth a second look.
6. **OTHER** — owned by some other regular user.

`MINE-BG` will include things like `vncsession`, `Xvnc`, and `(sd-pam)` — they are technically correct (started during your login session) but can be noisy. The detail panel's `Cgroup:` line is how you tell a real detached job (`session.slice`) from a managed user service (`user@UID.service`).

## CPU% needs two samples

`Collector.collect()` returns 0% CPU on the first call because it has no baseline. `App.run()` calls `collect()` twice with a 100 ms gap on startup so the first frame the user sees has real values. If you refactor the run loop, keep this priming step.

## /proc files relied on

If any of these change shape, the parser breaks. They're stable across modern kernels but worth knowing:

- `/proc/<pid>/stat` — parsed with care: `comm` is in parens and may contain spaces or parens itself, so the parser uses `rindex(')')`, not `split()`.
- `/proc/<pid>/status` — UID and Threads.
- `/proc/<pid>/loginuid` — single integer; `4294967295` means unset.
- `/proc/<pid>/cgroup` — substring-matched for `system.slice`; do not assume a particular cgroup hierarchy version.
- `/proc/<pid>/cmdline` — NUL-separated; empty for kernel threads and a few exotic userspace daemons.
- `/proc/stat`, `/proc/meminfo` — for CPU% denominator and total memory.

## Process description library

`library.json` (next to `monitor.py`) maps process `comm` names to short human-written descriptions, displayed in the detail panel as the `About:` line. Two lookup paths:

- **`entries`** — exact-match by `comm` (the 15-char-truncated name from `/proc/<pid>/stat`).
- **`patterns`** — fnmatch globs evaluated in file order; first match wins. Used for families like `kworker/*`, `gsd-*`, `gvfsd-*`.

Lookup tries `entries` first, then `patterns`. Any `comm` seen at runtime that has no curated entry and no pattern match gets auto-stubbed (`description: null, source: "auto", first_seen: <date>`) and the file is rewritten on exit. Stubs are how we keep a record of "what we've seen but haven't documented" — future curation work is `grep '"description": null' library.json`, research, fill in, set `"source": "curated"`.

When matching, remember `comm` is truncated to 15 chars in `/proc/<pid>/stat`. So the key for `gnome-session-binary` is `gnome-session-b`, not the full name.

`library.json` is committed; the tool rewrites it in place when stubs are added. `git diff library.json` after a run shows what new processes were observed.

## Conventions

- No external dependencies. Keep it stdlib-only so the script works on a fresh Linux box without `pip`.
- Errors from disappearing PIDs (process exited mid-collection) must be swallowed silently. Race-y reads return `None` from the `read_*` helpers; callers handle that.
- All curses writes go through `App._safe_addstr` to tolerate undersized terminals.
