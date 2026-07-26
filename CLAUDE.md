# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**myne** — a single-file curses TUI (`myne.py`) that lists Linux processes and lets the user kill them. Python 3, stdlib only — no dependencies, no build step, no test suite.

The name comes from the central question the tool answers: "is this **mine**?" — answered correctly even for nohup'd / disowned / sudo'd processes via `/proc/<pid>/loginuid` (see below).

## Run

```
./myne.py        # or: python3 myne.py
```

Linux only. Reads `/proc` directly; no `psutil`, no shelling out to `ps`.

## The central design decision: loginuid, not TTY

The whole reason this exists (vs. `top`/`htop`) is to answer "did *I* start this?" correctly even when the process was `nohup`'d, `disown`'d, double-forked, or escalated through `sudo`. The naive signal — controlling TTY — fails for all of those.

The tool uses **`/proc/<pid>/loginuid`** instead. PAM stamps this at login, the kernel inherits it across `fork`/`exec`/`setuid`, and **nothing in userspace can reset it without `CAP_AUDIT_CONTROL`**. So a nohup'd process that lost its TTY hours ago still reports your original login uid.

If you change the categorization logic, preserve this: TTY presence only distinguishes `MINE` from `MINE-BG` *within* the loginuid-matches-me bucket. It is never the primary signal.

## Category taxonomy

Buckets are decided in this fixed order (`categorize()` in `myne.py`). Order matters — earlier rules win:

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
- `/proc/<pid>/cwd` — symlink, read with `os.readlink`; only fetched for processes whose `comm` is in `SHELL_COMMS`.
- `/proc/<pid>/wchan` — kernel function name the task is sleeping in; only fetched when `state == 'D'` (uninterruptible sleep — usually disk I/O).
- `/proc/stat`, `/proc/meminfo` — for CPU% denominator and total memory.

## COMMAND-column enrichment

The cmdline alone is rarely enough — `bash` doesn't say where it is, `agent` doesn't say it's the OCI agent. The row appends one annotation chosen by priority (first match wins, so the row stays one-line):

1. **`[wchan:<fn>]`** when the process is in D-state. Almost always a stuck I/O — the kernel function names what it's blocked on.
2. **`▶ <fg cmdline>`** for shells with a foreground job (resolved via `tpgid` → leader of that pgrp).
3. **`· <cwd>`** for idle shells.
4. **`[container:<id12>]`** when `cgroup` matches a container scope (`libpod-`, `crun-`, `docker-`, or a bare 32+ hex segment). 12-char short id.
5. **`[unit:<name>]`** for the deepest systemd unit (`.service`/`.scope`/`.target`/...) in the cgroup path, *unless* it's redundant with `comm` (e.g. `sshd` in `sshd.service`) *or* matches a noise pattern — `vte-spawn-*` (gnome-terminal tabs), `session-*.scope`, `app-*.scope`, `init.scope`, or any `*.slice`. See `is_unit_redundant_with_comm` and `is_noisy_unit`. Without the noise filter, MINE rows get drowned in vte-spawn UUIDs.

The detail panel shows all that apply, not just the winning one.

## Process description library

`library.json` (next to `myne.py`) maps process `comm` names to short human-written descriptions, displayed in the detail panel as the `About:` line. Two lookup paths:

- **`entries`** — exact-match by `comm` (the 15-char-truncated name from `/proc/<pid>/stat`).
- **`patterns`** — fnmatch globs evaluated in file order; first match wins. Used for families like `kworker/*`, `gsd-*`, `gvfsd-*`.

Lookup tries `entries` first, then `patterns`. Any `comm` seen at runtime that has no curated entry, no pattern match, and isn't in `STUB_DENYLIST` (transient shell utilities and Firefox sub-process thread names — see `Library.record`) gets auto-stubbed (`description: null, source: "auto", first_seen: <date>`) and the file is rewritten on exit. Stubs are how we keep a record of "what we've seen but haven't documented" — future curation work is `grep '"description": null' library.json`, research, fill in, set `"source": "curated"`.

When matching, remember `comm` is truncated to 15 chars in `/proc/<pid>/stat`. So the key for `gnome-session-binary` is `gnome-session-b`, not the full name.

`library.json` is committed; the tool rewrites it in place when stubs are added. `git diff library.json` after a run shows what new processes were observed.

## Cursor tracks the PID, not the row index

`self.cursor_pid` is the source of truth for what's selected; `self.cursor` is recomputed from it every frame in `_resolve_cursor()`. This is what lets the highlight stay glued to a specific process when the list reorders (CPU% changes, sort cycles, filter toggles). If the PID isn't in the visible list (filtered out, or aged past `ghost_ttl`), the cursor falls back to the top row. Ghosts retain their PID, so a just-died process is still selectable for the visibility window — useful when you want to read its detail panel before it disappears.

If you change the navigation handlers, go through `_move(delta)` / `_jump('home'|'end')` — they update `cursor_pid`. Don't poke the index directly or the next refresh will undo you.

## Fresh and ghost markers

Process churn is otherwise invisible between refreshes. The App keeps two pieces of state alongside `self.procs`:

- `first_seen[pid]` — set on first sighting, used to render a bold `+` marker for `fresh_ttl` seconds (default 3.0).
- `ghosts[pid]` — a snapshot of processes that vanished since the last refresh, kept for `ghost_ttl` seconds (default 5.0) and drawn with a `†` prefix in two stages: red + bold (the `_DYING` pair) for the first `dying_ttl` seconds (default 1.0), then dim for the rest. Timed from `_ghost_at`, stamped at the refresh that noticed the death — so the flash is anchored to detection, not to the actual exit.

On the **very first refresh** (`is_first = not self.first_seen`), every PID's `first_seen` is back-dated past `fresh_ttl` so existing processes don't all flash as new — only genuinely new ones do. Preserve that guard if you change the priming step.

Ghosts are merged into the filtered list *after* live processes, so they participate in category and text filters but are skipped in tree mode (parent links may be stale). Their cpu/mem values are frozen at last-sample time.

The dying flash is only visible because `draw()` runs on every loop iteration and `stdscr.timeout(500)` caps the idle gap at 500 ms — comfortably under `dying_ttl`. Raising that timeout above `dying_ttl` would silently drop the flash on idle frames.

## Conventions

- No external dependencies. Keep it stdlib-only so the script works on a fresh Linux box without `pip`.
- Errors from disappearing PIDs (process exited mid-collection) must be swallowed silently. Race-y reads return `None` from the `read_*` helpers; callers handle that.
- All curses writes go through `App._safe_addstr` to tolerate undersized terminals.
