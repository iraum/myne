# myne

a Linux process viewer that knows which processes are actually yours.

`top` and `htop` use TTY presence to guess. that fails the moment you `nohup` something, or escalate through `sudo`, or close the shell that started a job. **myne** uses `/proc/<pid>/loginuid` instead — the kernel-enforced mark PAM stamps at login, inherited across every fork/exec/setuid. nothing in userspace can reset it without `CAP_AUDIT_CONTROL`.

so a `nohup`'d job from a shell you closed yesterday still shows up as **MINE-BG**. exactly where it should be.

## run

```
git clone https://github.com/iraum/myne
cd myne
./myne.py
```

linux only. python 3, stdlib only — no `pip install`, no `psutil`, no shelling out to `ps`. just `/proc`.

## what's in the list

every process gets bucketed:

| category | what it means | colour |
|---|---|---|
| **MINE** | you started it, has a TTY (your shell, vim, ...) | green |
| **MINE-BG** | you started it, no TTY (nohup, disown, your `systemd --user` services) | cyan |
| **USER-SVC** | runs as your uid but PAM didn't see you start it | blue |
| **SYSTEM** | a `system.slice` service (sshd, NetworkManager, ...) | yellow |
| **ROOT** | root-owned, not a system service — worth a second look | red |
| **OTHER** | some other regular user | magenta |
| **KERNEL** | kernel thread (hidden by default, press `7`) | dim |

## keys

```
↑↓ / jk        move (cursor follows the PID across reorderings)
1..8           jump to category filter — same digit again toggles off
                 1 MINE      5 ROOT       8 YOURS (MINE + MINE-BG)
                 2 MINE-BG   6 OTHER
                 3 USER-SVC  7 KERNEL
                 4 SYSTEM
0              clear filter
Tab            cycle through filters
s              cycle sort (cpu / mem / pid / name)
T              tree mode (children indented under parents)
/              text search
Enter          detail panel
K              SIGTERM (with confirm)
9              SIGKILL (with confirm)
r              force refresh
q              quit
```

## the COMMAND column knows things

bash's cmdline is rarely useful (`bash`, `-bash`, `/bin/bash`). so myne adds a contextual tail:

```
460029 opc    MINE     bash  ▶ claude --resume
467631 opc    MINE     bash  · ~/projects/hexfall
398828 opc    OTHER    /usr/libexec/oracle-cloud-agent/agent  [unit:oracle-cloud-agent.service]
 77188 100000 MINE-BG  /bin/sh /usr/bin/entrypoint  [container:b9681db3e99b]
 12345 root   SYSTEM   dd  [wchan:io_schedule]
```

priority on the row: D-state `wchan` > shell foreground job > shell cwd > container id > systemd unit. the detail panel shows every applicable line, not just the winner.

## ghosts and births

processes that came and went between refreshes used to be invisible:

- `+` (bold) — appeared in the last 3 seconds
- `†` (dim) — vanished since the last refresh; lingers for 5 seconds before fading

the cursor stays glued to its PID across reorderings, and follows it into the ghost window so you can pop the detail panel on something that just died.

## the process description library

`library.json` ships with curated one-line descriptions of ~120 common Linux daemons, kernel-thread families, GNOME components, podman runtimes, Oracle Cloud agents, Performance Co-Pilot, CrowdStrike Falcon — anything that's likely to show up on a real RHEL-family box. the detail panel renders that as the `About:` line.

unknown `comm` names get auto-stubbed (`description: null`) and the file is rewritten on exit, so it accumulates a record of "things this tool has seen but doesn't know yet". curating is `grep '"description": null' library.json` and filling them in. patches welcome.

## why

`top` shows you a wall of identical-looking processes. you stare at it. you can't tell which are yours, which are system services, which are kernel threads, which are weird. you can't tell at a glance whether something belongs there.

myne tries to answer those questions before you ask them.

## license

MIT. do whatever.
