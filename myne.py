#!/usr/bin/env python3
import curses
import datetime
import fnmatch
import json
import os
import pwd
import re
import signal
import time

PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
CLK_TCK = os.sysconf('SC_CLK_TCK')
NUM_CPUS = os.cpu_count() or 1
LOGINUID_UNSET = 4294967295

CAT_MINE = 'MINE'
CAT_MINE_BG = 'MINE-BG'
CAT_USER_SVC = 'USER-SVC'
CAT_SYSTEM = 'SYSTEM'
CAT_ROOT = 'ROOT'
CAT_OTHER = 'OTHER'
CAT_KERNEL = 'KERNEL'

CAT_ORDER = [CAT_MINE, CAT_MINE_BG, CAT_USER_SVC, CAT_SYSTEM, CAT_ROOT, CAT_OTHER, CAT_KERNEL]

# Filter presets keyed by hotkey digit. 1-7 are single categories matching
# CAT_ORDER. 8 is the "everything you launched" combo (MINE + MINE-BG) — handy
# because nohup'd / disowned shell jobs land in MINE-BG, not MINE.
FILTER_PRESETS = {
    1: ('MINE',     frozenset({CAT_MINE})),
    2: ('MINE-BG',  frozenset({CAT_MINE_BG})),
    3: ('USER-SVC', frozenset({CAT_USER_SVC})),
    4: ('SYSTEM',   frozenset({CAT_SYSTEM})),
    5: ('ROOT',     frozenset({CAT_ROOT})),
    6: ('OTHER',    frozenset({CAT_OTHER})),
    7: ('KERNEL',   frozenset({CAT_KERNEL})),
    8: ('YOURS',    frozenset({CAT_MINE, CAT_MINE_BG})),
}

SORT_CPU = 'cpu'
SORT_MEM = 'mem'
SORT_PID = 'pid'
SORT_NAME = 'name'
SORT_ORDER = [SORT_CPU, SORT_MEM, SORT_PID, SORT_NAME]


def read_text(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def total_mem_kb():
    data = read_text('/proc/meminfo') or ''
    for line in data.splitlines():
        if line.startswith('MemTotal:'):
            return int(line.split()[1])
    return 1


def read_total_jiffies():
    data = read_text('/proc/stat') or ''
    line = data.split('\n', 1)[0]
    return sum(int(p) for p in line.split()[1:]) if line else 0


def read_cmdline(pid):
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            data = f.read()
    except OSError:
        return ''
    return data.replace(b'\x00', b' ').decode('utf-8', 'replace').strip()


def read_stat(pid):
    data = read_text(f'/proc/{pid}/stat')
    if data is None:
        return None
    try:
        lparen = data.index('(')
        rparen = data.rindex(')')
        comm = data[lparen + 1:rparen]
        rest = data[rparen + 2:].split()
        return {
            'pid': int(data[:lparen].strip()),
            'comm': comm,
            'state': rest[0],
            'ppid': int(rest[1]),
            'pgrp': int(rest[2]),
            'tty_nr': int(rest[4]),
            'tpgid': int(rest[5]),
            'utime': int(rest[11]),
            'stime': int(rest[12]),
            'starttime': int(rest[19]),
            'rss_pages': int(rest[21]),
        }
    except (ValueError, IndexError):
        return None


def read_status(pid):
    data = read_text(f'/proc/{pid}/status')
    if data is None:
        return {}
    out = {}
    for line in data.splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            out[k.strip()] = v.strip()
    return out


def read_loginuid(pid):
    # The whole reason this tool exists: loginuid is set by PAM at login and
    # inherited by all descendants, so nohup'd / disowned / sudo'd processes
    # still report the original login uid.
    data = read_text(f'/proc/{pid}/loginuid')
    if data is None:
        return LOGINUID_UNSET
    try:
        return int(data.strip())
    except ValueError:
        return LOGINUID_UNSET


def read_cgroup(pid):
    data = read_text(f'/proc/{pid}/cgroup')
    return data.strip() if data else ''


def read_cwd(pid):
    try:
        return os.readlink(f'/proc/{pid}/cwd')
    except OSError:
        return None


def read_wchan(pid):
    data = read_text(f'/proc/{pid}/wchan')
    if not data:
        return None
    s = data.strip()
    return s if s and s != '0' else None


SHELL_COMMS = {'bash', 'zsh', 'sh', 'fish', 'dash', 'ksh', 'tcsh', 'csh', 'mksh'}

UNIT_SUFFIXES = ('.service', '.scope', '.socket', '.target', '.timer', '.path', '.mount')

# Unit names that always carry zero signal: gnome-terminal tab scopes,
# logind session scopes, generic GNOME app scopes, and the catch-all init.scope.
NOISY_UNIT_PREFIXES = ('vte-spawn-', 'session-', 'app-')
NOISY_UNITS = {'init.scope'}

# Container scope segments emitted by container runtimes inside cgroup paths.
_CONTAINER_RE = re.compile(r'(?:libpod|libcrun|crun|docker|runc|cri-containerd)[-:]([0-9a-f]{12,})')
_BARE_CONTAINER_RE = re.compile(r'/([0-9a-f]{32,})(?:[/.]|$)')


def parse_systemd_unit(cgroup):
    if not cgroup:
        return None
    for line in cgroup.splitlines():
        path = line.rsplit(':', 1)[-1] if ':' in line else line
        for seg in reversed([s for s in path.split('/') if s]):
            if seg.endswith(UNIT_SUFFIXES):
                return seg
    return None


def parse_container_id(cgroup):
    if not cgroup:
        return None
    for line in cgroup.splitlines():
        m = _CONTAINER_RE.search(line) or _BARE_CONTAINER_RE.search(line)
        if m:
            return m.group(1)[:12]
    return None


def is_unit_redundant_with_comm(unit, comm):
    # Strip .service/.scope/.target etc. and any @instance from the unit base,
    # then compare with the (possibly 15-char-truncated) comm.
    base = unit.rsplit('.', 1)[0].split('@', 1)[0]
    if not base or not comm:
        return False
    return base == comm or base.startswith(comm) or comm.startswith(base)


def is_noisy_unit(unit):
    if not unit:
        return False
    if unit in NOISY_UNITS or unit.endswith('.slice'):
        return True
    return any(unit.startswith(p) for p in NOISY_UNIT_PREFIXES)


def abbreviate_home(path, home):
    if not path:
        return path
    if home and (path == home or path.startswith(home + '/')):
        return '~' + path[len(home):]
    return path


_user_cache = {}


def uid_name(uid):
    if uid not in _user_cache:
        try:
            _user_cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            _user_cache[uid] = str(uid)
    return _user_cache[uid]


def tty_name(tty_nr):
    if tty_nr == 0:
        return '?'
    # Linux encodes tty_nr as: high 12 bits = minor high, mid 8 bits = major,
    # low 8 bits = minor low. See proc(5).
    major = (tty_nr >> 8) & 0xff
    minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00)
    if major == 136:
        return f'pts/{minor}'
    if major == 4:
        return f'tty{minor}'
    if major == 5 and minor == 0:
        return 'tty'
    return f'{major}:{minor}'


def categorize(uid, loginuid, has_tty, cgroup, is_kernel, my_uid):
    if is_kernel:
        return CAT_KERNEL
    if 'system.slice' in cgroup:
        return CAT_SYSTEM
    if loginuid == my_uid:
        return CAT_MINE if has_tty else CAT_MINE_BG
    if uid == my_uid:
        return CAT_USER_SVC
    if uid == 0:
        return CAT_ROOT
    return CAT_OTHER


class Collector:
    def __init__(self):
        self.prev_proc = {}
        self.prev_total = 0
        self.total_mem_kb = total_mem_kb()
        self.my_uid = os.getuid()
        try:
            self.home = pwd.getpwuid(self.my_uid).pw_dir or ''
        except KeyError:
            self.home = os.environ.get('HOME', '')

    def collect(self):
        cur_total = read_total_jiffies()
        delta_total = cur_total - self.prev_total if self.prev_total else 0
        new_prev_proc = {}
        procs = []
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            pid = int(entry)
            stat = read_stat(pid)
            if stat is None:
                continue
            proc_jiff = stat['utime'] + stat['stime']
            new_prev_proc[pid] = proc_jiff
            prev = self.prev_proc.get(pid)
            if prev is not None and delta_total > 0:
                cpu_pct = max(0.0, (proc_jiff - prev) / delta_total * NUM_CPUS * 100)
            else:
                cpu_pct = 0.0
            status = read_status(pid)
            try:
                uid = int(status.get('Uid', '0').split()[0])
            except (ValueError, IndexError):
                uid = 0
            try:
                threads = int(status.get('Threads', '1'))
            except ValueError:
                threads = 1
            loginuid = read_loginuid(pid)
            cgroup = read_cgroup(pid)
            cmdline = read_cmdline(pid)
            is_kernel = stat['ppid'] == 2 or pid == 2
            display_cmd = cmdline if cmdline else f'[{stat["comm"]}]'
            tty = tty_name(stat['tty_nr'])
            has_tty = stat['tty_nr'] != 0
            rss_kb = stat['rss_pages'] * PAGE_SIZE // 1024
            mem_pct = rss_kb / self.total_mem_kb * 100 if self.total_mem_kb else 0.0
            cat = categorize(uid, loginuid, has_tty, cgroup, is_kernel, self.my_uid)
            cwd = abbreviate_home(read_cwd(pid), self.home) if stat['comm'] in SHELL_COMMS else None
            if is_kernel:
                unit = container_id = None
            else:
                unit = parse_systemd_unit(cgroup)
                container_id = parse_container_id(cgroup)
                if unit and (is_unit_redundant_with_comm(unit, stat['comm']) or is_noisy_unit(unit)):
                    unit = None
            wchan = read_wchan(pid) if stat['state'] == 'D' else None
            procs.append({
                'pid': pid,
                'ppid': stat['ppid'],
                'pgrp': stat['pgrp'],
                'tpgid': stat['tpgid'],
                'comm': stat['comm'],
                'state': stat['state'],
                'uid': uid,
                'user': uid_name(uid),
                'loginuid': loginuid,
                'tty': tty,
                'has_tty': has_tty,
                'cgroup': cgroup,
                'cmdline': display_cmd,
                'cwd': cwd,
                'fg_cmdline': None,
                'systemd_unit': unit,
                'container_id': container_id,
                'wchan': wchan,
                'cpu_pct': cpu_pct,
                'mem_pct': mem_pct,
                'rss_kb': rss_kb,
                'threads': threads,
                'category': cat,
                'is_kernel': is_kernel,
                'starttime': stat['starttime'],
            })
        # Second pass: resolve each shell's foreground job via tpgid (the
        # foreground process-group id of its controlling TTY). Leader of that
        # pgrp has pid == pgrp; if it's the shell itself, the shell is idle.
        by_pgrp_leader = {p['pid']: p for p in procs if p['pid'] == p['pgrp']}
        for p in procs:
            if p['comm'] in SHELL_COMMS and p['tpgid'] > 0 and p['tpgid'] != p['pgrp']:
                fg = by_pgrp_leader.get(p['tpgid'])
                if fg is not None:
                    p['fg_cmdline'] = fg['cmdline']
                    p['fg_pid'] = fg['pid']
        self.prev_proc = new_prev_proc
        self.prev_total = cur_total
        return procs


def sort_procs(procs, mode):
    if mode == SORT_CPU:
        procs.sort(key=lambda p: -p['cpu_pct'])
    elif mode == SORT_MEM:
        procs.sort(key=lambda p: -p['mem_pct'])
    elif mode == SORT_PID:
        procs.sort(key=lambda p: p['pid'])
    elif mode == SORT_NAME:
        procs.sort(key=lambda p: p['comm'].lower())


def build_tree(procs):
    by_pid = {p['pid']: p for p in procs}
    children = {}
    for p in procs:
        children.setdefault(p['ppid'], []).append(p['pid'])
    for kids in children.values():
        kids.sort()

    visited = set()
    out = []

    def walk(pid, depth):
        if pid in visited or pid not in by_pid:
            return
        visited.add(pid)
        p = dict(by_pid[pid])
        p['_depth'] = depth
        out.append(p)
        for kid in children.get(pid, []):
            walk(kid, depth + 1)

    roots = sorted({p['ppid'] for p in procs if p['ppid'] not in by_pid})
    for r in roots:
        for kid in children.get(r, []):
            walk(kid, 0)
    for p in procs:
        walk(p['pid'], 0)
    return out


def wrap_text(text, width):
    if not text:
        return ['']
    out = []
    for paragraph in text.splitlines() or [text]:
        words = paragraph.split(' ')
        line = ''
        for w in words:
            if not line:
                line = w
            elif len(line) + 1 + len(w) <= width:
                line += ' ' + w
            else:
                out.append(line)
                line = w
        if line:
            out.append(line)
    return out or ['']


def parent_chain(procs, pid):
    by_pid = {p['pid']: p for p in procs}
    chain = []
    cur = pid
    seen = set()
    while cur in by_pid and cur not in seen:
        seen.add(cur)
        p = by_pid[cur]
        chain.append(p)
        if p['ppid'] in (0, cur):
            break
        cur = p['ppid']
    return chain


class Library:
    def __init__(self, path):
        self.path = path
        self.entries = {}
        self.patterns = []
        self.dirty = False
        self.load()

    def load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        self.entries = data.get('entries', {}) or {}
        self.patterns = data.get('patterns', []) or []

    def save(self):
        if not self.dirty:
            return
        data = {'version': 1, 'patterns': self.patterns, 'entries': self.entries}
        tmp = self.path + '.tmp'
        try:
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.write('\n')
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError:
            pass

    def lookup(self, comm):
        e = self.entries.get(comm)
        if e:
            return e
        for p in self.patterns:
            if fnmatch.fnmatchcase(comm, p.get('glob', '')):
                return p
        return None

    def record(self, comm):
        if comm in self.entries:
            return
        for p in self.patterns:
            if fnmatch.fnmatchcase(comm, p.get('glob', '')):
                return
        self.entries[comm] = {
            'description': None,
            'source': 'auto',
            'first_seen': datetime.date.today().isoformat(),
        }
        self.dirty = True


CAT_COLOR_PAIR = {}


def setup_colors():
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    pairs = [
        (CAT_MINE, curses.COLOR_GREEN),
        (CAT_MINE_BG, curses.COLOR_CYAN),
        (CAT_USER_SVC, curses.COLOR_BLUE),
        (CAT_SYSTEM, curses.COLOR_YELLOW),
        (CAT_ROOT, curses.COLOR_RED),
        (CAT_OTHER, curses.COLOR_MAGENTA),
        (CAT_KERNEL, curses.COLOR_WHITE),
    ]
    i = 1
    for cat, fg in pairs:
        curses.init_pair(i, fg, bg)
        CAT_COLOR_PAIR[cat] = curses.color_pair(i)
        i += 1
    curses.init_pair(i, curses.COLOR_BLACK, curses.COLOR_WHITE)
    CAT_COLOR_PAIR['_HEADER'] = curses.color_pair(i) | curses.A_BOLD


class App:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.collector = Collector()
        self.library = Library(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'library.json'))
        self.procs = []
        self.sort_mode = SORT_CPU
        self.cat_filter = None
        self.text_filter = ''
        self.tree_mode = False
        self.cursor = 0
        self.cursor_pid = None
        self.scroll = 0
        self.detail_pid = None
        self.last_refresh = 0.0
        self.refresh_interval = 2.0
        self.message = ''
        self.message_until = 0.0
        self.first_seen = {}
        self.ghosts = {}
        self.ghost_ttl = 5.0
        self.fresh_ttl = 3.0
        self.hide_kernel = True

    def set_message(self, msg, dur=3.0):
        self.message = msg
        self.message_until = time.time() + dur

    def refresh(self):
        old = list(self.procs)
        is_first = not self.first_seen
        try:
            self.procs = self.collector.collect()
        except Exception as e:
            self.set_message(f'collect error: {e}')
        now = time.time()
        new_pids = {p['pid'] for p in self.procs}
        # On first launch, backdate first_seen so existing processes don't all
        # flash as "fresh" — they predate the tool, not the run.
        default_first = (now - self.fresh_ttl - 1) if is_first else now
        for p in self.procs:
            self.first_seen.setdefault(p['pid'], default_first)
            self.library.record(p['comm'])
        for op in old:
            if op['pid'] not in new_pids and op['pid'] not in self.ghosts:
                g = dict(op)
                g['_ghost_at'] = now
                self.ghosts[op['pid']] = g
        cutoff = now - self.ghost_ttl
        self.ghosts = {pid: g for pid, g in self.ghosts.items() if g['_ghost_at'] > cutoff}
        alive = new_pids | set(self.ghosts)
        self.first_seen = {pid: t for pid, t in self.first_seen.items() if pid in alive}
        self.last_refresh = now

    def filtered(self):
        now = time.time()
        ps = []
        for p in self.procs:
            q = p
            if now - self.first_seen.get(p['pid'], now) < self.fresh_ttl:
                q = dict(p)
                q['_fresh'] = True
            ps.append(q)
        if not self.tree_mode:
            for g in self.ghosts.values():
                gp = dict(g)
                gp['_ghost'] = True
                ps.append(gp)
        if self.cat_filter:
            cats = FILTER_PRESETS[self.cat_filter][1]
            ps = [p for p in ps if p['category'] in cats]
        elif self.hide_kernel:
            ps = [p for p in ps if p['category'] != CAT_KERNEL]
        if self.text_filter:
            t = self.text_filter.lower()
            ps = [p for p in ps if t in p['cmdline'].lower() or t in str(p['pid'])]
        if self.tree_mode:
            ps = build_tree(ps)
        else:
            sort_procs(ps, self.sort_mode)
        return ps

    def _resolve_cursor(self, ps):
        if not ps:
            self.cursor_pid = None
            return 0
        if self.cursor_pid is None:
            self.cursor_pid = ps[0]['pid']
            return 0
        for i, p in enumerate(ps):
            if p['pid'] == self.cursor_pid:
                return i
        self.cursor_pid = ps[0]['pid']
        return 0

    def _move(self, delta):
        ps = self.filtered()
        if not ps:
            self.cursor_pid = None
            return
        cur = self._resolve_cursor(ps)
        new = max(0, min(len(ps) - 1, cur + delta))
        self.cursor_pid = ps[new]['pid']

    def _jump(self, where):
        ps = self.filtered()
        if not ps:
            self.cursor_pid = None
            return
        self.cursor_pid = ps[0 if where == 'home' else -1]['pid']

    def draw(self):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if self.detail_pid is not None:
            self.draw_detail(h, w)
        else:
            self.draw_list(h, w)
        self.stdscr.refresh()

    def draw_header(self, h, w):
        my_user = uid_name(self.collector.my_uid)
        bits = [f'myne', f'you: {my_user}({self.collector.my_uid})', f'procs: {len(self.procs)}', f'sort: {self.sort_mode}']
        if self.cat_filter:
            label = FILTER_PRESETS[self.cat_filter][0]
            bits.append(f'cat: [{self.cat_filter}]{label}')
        elif self.hide_kernel:
            bits.append('cat: -KERNEL (7 to show)')
        if self.text_filter:
            bits.append(f'/{self.text_filter}')
        if self.tree_mode:
            bits.append('TREE')
        title = ' ' + '  '.join(bits)
        self._safe_addstr(0, 0, title.ljust(w)[:w], CAT_COLOR_PAIR['_HEADER'])
        cols = '   PID USER       CAT       CPU%   MEM% TTY      COMMAND'
        self._safe_addstr(1, 0, cols.ljust(w)[:w], curses.A_BOLD)

    def draw_list(self, h, w):
        self.draw_header(h, w)
        ps = self.filtered()
        body_top = 2
        body_h = max(1, h - 4)
        if not ps:
            self._safe_addstr(body_top, 0, '(no processes match)')
            self.cursor_pid = None
        else:
            self.cursor = self._resolve_cursor(ps)
            if self.cursor < self.scroll:
                self.scroll = self.cursor
            if self.cursor >= self.scroll + body_h:
                self.scroll = self.cursor - body_h + 1
            for i in range(body_h):
                idx = self.scroll + i
                if idx >= len(ps):
                    break
                self.draw_row(body_top + i, w, ps[idx], idx == self.cursor)
        self.draw_status(h, w)

    def draw_row(self, y, w, p, selected):
        depth = p.get('_depth', 0)
        indent = '  ' * depth
        cmd = indent + p['cmdline']
        if p.get('wchan'):
            cmd += f'  [wchan:{p["wchan"]}]'
        elif p.get('fg_cmdline'):
            cmd += f'  ▶ {p["fg_cmdline"]}'
        elif p.get('cwd'):
            cmd += f'  · {p["cwd"]}'
        elif p.get('container_id'):
            cmd += f'  [container:{p["container_id"]}]'
        elif p.get('systemd_unit'):
            cmd += f'  [unit:{p["systemd_unit"]}]'
        if p.get('_ghost'):
            marker = '†'
        elif p.get('_fresh'):
            marker = '+'
        else:
            marker = ' '
        cpu_s = f'{p["cpu_pct"]:5.1f}' if p['cpu_pct'] >= 0.05 else '     '
        mem_s = f'{p["mem_pct"]:5.1f}' if p['mem_pct'] >= 0.05 else '     '
        line = f'{marker}{p["pid"]:>5} {p["user"][:10]:<10} {p["category"]:<9} {cpu_s} {mem_s} {p["tty"][:8]:<8} {cmd}'
        line = line.ljust(w)[:w]
        attr = CAT_COLOR_PAIR.get(p['category'], 0)
        if p.get('_ghost'):
            attr |= curses.A_DIM
        elif p.get('_fresh'):
            attr |= curses.A_BOLD
        if selected:
            attr |= curses.A_REVERSE | curses.A_BOLD
        self._safe_addstr(y, 0, line, attr)

    def draw_status(self, h, w):
        keys = 'jk move  s sort  1-8/Tab cat (0 clear, 8=YOURS)  / search  T tree  Enter detail  K SIGTERM  9 SIGKILL  r refresh  q quit'
        if time.time() < self.message_until and self.message:
            line = ' ' + self.message
        else:
            line = ' ' + keys
        self._safe_addstr(h - 1, 0, line.ljust(w)[:w], CAT_COLOR_PAIR['_HEADER'])

    def draw_detail(self, h, w):
        p = next((x for x in self.procs if x['pid'] == self.detail_pid), None)
        if not p:
            self.detail_pid = None
            return
        self._safe_addstr(0, 0, f' detail PID {p["pid"]}'.ljust(w)[:w], CAT_COLOR_PAIR['_HEADER'])
        loginuid_disp = 'unset' if p['loginuid'] == LOGINUID_UNSET else f'{p["loginuid"]} ({uid_name(p["loginuid"])})'
        lib_entry = self.library.lookup(p['comm'])
        if lib_entry and lib_entry.get('description'):
            about = lib_entry['description']
            about_src = lib_entry.get('glob') or lib_entry.get('source', '')
        else:
            about = '(no description yet — added to library; ask Claude to research)'
            about_src = 'unknown'
        rows = [
            f'PID:       {p["pid"]}',
            f'PPID:      {p["ppid"]}',
            f'Comm:      {p["comm"]}',
            f'State:     {p["state"]}',
            f'User:      {p["user"]} (uid={p["uid"]})',
            f'LoginUID:  {loginuid_disp}',
            f'TTY:       {p["tty"]}',
            f'Category:  {p["category"]}',
            f'Threads:   {p["threads"]}',
            f'RSS:       {p["rss_kb"]:,} KB ({p["mem_pct"]:.1f}%)',
            f'CPU:       {p["cpu_pct"]:.1f}%',
            f'Cmdline:   {p["cmdline"]}',
        ]
        if p.get('cwd'):
            rows.append(f'Cwd:       {p["cwd"]}')
        if p.get('fg_cmdline'):
            rows.append(f'Foreground: pid {p.get("fg_pid","?"):<6}  {p["fg_cmdline"]}')
        if p.get('systemd_unit'):
            rows.append(f'Unit:      {p["systemd_unit"]}')
        if p.get('container_id'):
            rows.append(f'Container: {p["container_id"]}')
        if p.get('wchan'):
            rows.append(f'Wchan:     {p["wchan"]}  (uninterruptible sleep — usually I/O wait)')
        rows.append('')
        wrap_w = max(20, w - 11)
        about_lines = wrap_text(about, wrap_w)
        rows.append(f'About:     {about_lines[0] if about_lines else ""}')
        for cont in about_lines[1:]:
            rows.append(f'           {cont}')
        rows.append(f'           [source: {about_src}]')
        rows.append('')
        rows.append('Cgroup:')
        for line in p['cgroup'].splitlines():
            rows.append(f'  {line}')
        rows.append('')
        rows.append('Parent chain (this proc up to PID 1):')
        for cp in parent_chain(self.procs, p['pid']):
            tail = cp['cmdline'][:max(10, w - 35)]
            rows.append(f'  {cp["pid"]:>6} {cp["user"][:10]:<10} {cp["category"]:<9} {tail}')
        for i, line in enumerate(rows):
            if 1 + i >= h - 1:
                break
            self._safe_addstr(1 + i, 0, line[:w])
        msg = ' Press q/Esc to return  K SIGTERM  9 SIGKILL'
        self._safe_addstr(h - 1, 0, msg.ljust(w)[:w], CAT_COLOR_PAIR['_HEADER'])

    def _safe_addstr(self, y, x, s, attr=0):
        try:
            self.stdscr.addstr(y, x, s, attr)
        except curses.error:
            pass

    def prompt(self, msg):
        h, w = self.stdscr.getmaxyx()
        curses.echo()
        curses.curs_set(1)
        try:
            self._safe_addstr(h - 1, 0, (' ' + msg).ljust(w)[:w], CAT_COLOR_PAIR['_HEADER'])
            self.stdscr.refresh()
            raw = self.stdscr.getstr(h - 1, len(msg) + 2, max(1, w - len(msg) - 3))
        except curses.error:
            raw = b''
        finally:
            curses.noecho()
            curses.curs_set(0)
        return raw.decode('utf-8', 'replace') if raw else ''

    def confirm(self, msg):
        h, w = self.stdscr.getmaxyx()
        self._safe_addstr(h - 1, 0, (' ' + msg + ' [y/N]').ljust(w)[:w], CAT_COLOR_PAIR['_HEADER'])
        self.stdscr.refresh()
        ch = self.stdscr.getch()
        return ch in (ord('y'), ord('Y'))

    def selected_proc(self):
        if self.detail_pid is not None:
            return next((x for x in self.procs if x['pid'] == self.detail_pid), None)
        if self.cursor_pid is None:
            return None
        return next((p for p in self.filtered() if p['pid'] == self.cursor_pid), None)

    def kill_selected(self, sig):
        p = self.selected_proc()
        if not p:
            return
        signame = 'SIGTERM' if sig == signal.SIGTERM else 'SIGKILL'
        if not self.confirm(f'send {signame} to PID {p["pid"]} ({p["comm"]})?'):
            self.set_message('cancelled')
            return
        try:
            os.kill(p['pid'], sig)
            self.set_message(f'sent {signame} to {p["pid"]}')
        except PermissionError:
            self.set_message('permission denied (try sudo)')
        except ProcessLookupError:
            self.set_message(f'process {p["pid"]} already gone')
        except OSError as e:
            self.set_message(f'kill failed: {e}')

    def cycle_sort(self):
        i = SORT_ORDER.index(self.sort_mode)
        self.sort_mode = SORT_ORDER[(i + 1) % len(SORT_ORDER)]

    def cycle_cat(self):
        opts = [None] + sorted(FILTER_PRESETS)
        i = opts.index(self.cat_filter) if self.cat_filter in opts else 0
        self.cat_filter = opts[(i + 1) % len(opts)]

    def run(self):
        curses.curs_set(0)
        self.stdscr.timeout(500)
        # Two quick samples so first visible refresh has real CPU% values.
        self.refresh()
        time.sleep(0.1)
        self.refresh()
        while True:
            if time.time() - self.last_refresh > self.refresh_interval:
                self.refresh()
            self.draw()
            try:
                ch = self.stdscr.getch()
            except KeyboardInterrupt:
                break
            if ch == -1:
                continue
            if self.detail_pid is not None:
                if ch in (ord('q'), 27):
                    self.detail_pid = None
                elif ch == ord('K'):
                    self.kill_selected(signal.SIGTERM)
                elif ch == ord('9'):
                    self.kill_selected(signal.SIGKILL)
                elif ch == ord('r'):
                    self.refresh()
                continue
            if ch == ord('q'):
                break
            elif ch in (curses.KEY_UP, ord('k')):
                self._move(-1)
            elif ch in (curses.KEY_DOWN, ord('j')):
                self._move(1)
            elif ch == curses.KEY_PPAGE:
                self._move(-20)
            elif ch == curses.KEY_NPAGE:
                self._move(20)
            elif ch == curses.KEY_HOME:
                self._jump('home')
            elif ch == curses.KEY_END:
                self._jump('end')
            elif ch == ord('r'):
                self.refresh()
                self.set_message('refreshed')
            elif ch == ord('s'):
                self.cycle_sort()
            elif ch == ord('\t'):
                self.cycle_cat()
            elif ord('0') <= ch <= ord('8'):
                n = ch - ord('0')
                if n == 0:
                    self.cat_filter = None
                elif n in FILTER_PRESETS:
                    self.cat_filter = None if self.cat_filter == n else n
            elif ch == ord('T'):
                self.tree_mode = not self.tree_mode
            elif ch == ord('/'):
                self.text_filter = self.prompt('filter (empty = clear): /').strip()
            elif ch in (curses.KEY_ENTER, 10, 13):
                p = self.selected_proc()
                if p:
                    self.detail_pid = p['pid']
            elif ch == ord('K'):
                self.kill_selected(signal.SIGTERM)
            elif ch == ord('9'):
                self.kill_selected(signal.SIGKILL)


def main(stdscr):
    setup_colors()
    app = App(stdscr)
    try:
        app.run()
    finally:
        app.library.save()


if __name__ == '__main__':
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
