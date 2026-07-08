#!/usr/bin/env python3
"""
mde_perf_report.py — Performance & troubleshooting report generator for
Microsoft Defender for Endpoint (MDE) on Linux.

Consumes the output directory produced by the MDE Client Analyzer
(XMDEClientAnalyzer / MDESupportTool) and renders a single, self-contained
HTML report focused on performance diagnostics and troubleshooting.

Requirements:
  * Python 3.7+ — the only prerequisite.
  * No additional Python packages. Standard library only: argparse, gzip, html,
    json, os, re, sys, zipfile, xml.etree.ElementTree, datetime, collections.
    No pip install, no virtualenv, no requirements.txt.

Design goals:
  * Stdlib only (json/re/os/...). No pip install required.
  * Tolerant: any missing/extra file is skipped, never fatal.
  * Reusable: point it at any analyzer output directory.

Generate the analyzer bundle first (on the affected Linux host):

  cd /opt/microsoft/mdatp/tools/client_analyzer/binary/
  sudo ./MDESupportTool -d

  The results are written to /tmp by default (a *_output.zip); the tool prints
  the path when it finishes. Official docs on running the client analyzer:
    Windows: https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-windows
    Linux: https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-linux
    macOS: https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-macos
    Overview / requirements: https://learn.microsoft.com/en-us/defender-endpoint/overview-client-analyzer

Then render the report:
  python3 mde_perf_report.py <diag_dir_or_zip> [-o report.html] [--max-age-days N]

  The input may be either the analyzer output directory or the analyzer
  output .zip bundle. A zip is extracted to a sibling folder (named after the
  zip, minus .zip) and reused on later runs instead of being re-extracted.

  --max-age-days N  excludes log events older than N days (relative to the
  capture time) from the syslog/kernel/MDC archives and MDE product logs.
"""

from __future__ import annotations

import argparse
import gzip
import html
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

OK, WARN, CRIT, INFO = "ok", "warn", "crit", "info"
SEV_RANK = {OK: 0, INFO: 0, WARN: 1, CRIT: 2}

# Linux x86_64 syscall number -> name. Generated from the kernel ABI header
# (arch/x86/entry/syscalls/syscall_64.tbl / asm/unistd_64.h); authoritative and
# stable. Only valid for x86_64 — arm64 uses a different numbering, so callers
# must check the captured host's architecture before applying this map.
SYSCALLS_X86_64 = {
    0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat', 5: 'fstat',
    6: 'lstat', 7: 'poll', 8: 'lseek', 9: 'mmap', 10: 'mprotect', 11: 'munmap',
    12: 'brk', 13: 'rt_sigaction', 14: 'rt_sigprocmask', 15: 'rt_sigreturn', 16: 'ioctl', 17: 'pread64',
    18: 'pwrite64', 19: 'readv', 20: 'writev', 21: 'access', 22: 'pipe', 23: 'select',
    24: 'sched_yield', 25: 'mremap', 26: 'msync', 27: 'mincore', 28: 'madvise', 29: 'shmget',
    30: 'shmat', 31: 'shmctl', 32: 'dup', 33: 'dup2', 34: 'pause', 35: 'nanosleep',
    36: 'getitimer', 37: 'alarm', 38: 'setitimer', 39: 'getpid', 40: 'sendfile', 41: 'socket',
    42: 'connect', 43: 'accept', 44: 'sendto', 45: 'recvfrom', 46: 'sendmsg', 47: 'recvmsg',
    48: 'shutdown', 49: 'bind', 50: 'listen', 51: 'getsockname', 52: 'getpeername', 53: 'socketpair',
    54: 'setsockopt', 55: 'getsockopt', 56: 'clone', 57: 'fork', 58: 'vfork', 59: 'execve',
    60: 'exit', 61: 'wait4', 62: 'kill', 63: 'uname', 64: 'semget', 65: 'semop',
    66: 'semctl', 67: 'shmdt', 68: 'msgget', 69: 'msgsnd', 70: 'msgrcv', 71: 'msgctl',
    72: 'fcntl', 73: 'flock', 74: 'fsync', 75: 'fdatasync', 76: 'truncate', 77: 'ftruncate',
    78: 'getdents', 79: 'getcwd', 80: 'chdir', 81: 'fchdir', 82: 'rename', 83: 'mkdir',
    84: 'rmdir', 85: 'creat', 86: 'link', 87: 'unlink', 88: 'symlink', 89: 'readlink',
    90: 'chmod', 91: 'fchmod', 92: 'chown', 93: 'fchown', 94: 'lchown', 95: 'umask',
    96: 'gettimeofday', 97: 'getrlimit', 98: 'getrusage', 99: 'sysinfo', 100: 'times', 101: 'ptrace',
    102: 'getuid', 103: 'syslog', 104: 'getgid', 105: 'setuid', 106: 'setgid', 107: 'geteuid',
    108: 'getegid', 109: 'setpgid', 110: 'getppid', 111: 'getpgrp', 112: 'setsid', 113: 'setreuid',
    114: 'setregid', 115: 'getgroups', 116: 'setgroups', 117: 'setresuid', 118: 'getresuid', 119: 'setresgid',
    120: 'getresgid', 121: 'getpgid', 122: 'setfsuid', 123: 'setfsgid', 124: 'getsid', 125: 'capget',
    126: 'capset', 127: 'rt_sigpending', 128: 'rt_sigtimedwait', 129: 'rt_sigqueueinfo', 130: 'rt_sigsuspend', 131: 'sigaltstack',
    132: 'utime', 133: 'mknod', 134: 'uselib', 135: 'personality', 136: 'ustat', 137: 'statfs',
    138: 'fstatfs', 139: 'sysfs', 140: 'getpriority', 141: 'setpriority', 142: 'sched_setparam', 143: 'sched_getparam',
    144: 'sched_setscheduler', 145: 'sched_getscheduler', 146: 'sched_get_priority_max', 147: 'sched_get_priority_min', 148: 'sched_rr_get_interval', 149: 'mlock',
    150: 'munlock', 151: 'mlockall', 152: 'munlockall', 153: 'vhangup', 154: 'modify_ldt', 155: 'pivot_root',
    156: '_sysctl', 157: 'prctl', 158: 'arch_prctl', 159: 'adjtimex', 160: 'setrlimit', 161: 'chroot',
    162: 'sync', 163: 'acct', 164: 'settimeofday', 165: 'mount', 166: 'umount2', 167: 'swapon',
    168: 'swapoff', 169: 'reboot', 170: 'sethostname', 171: 'setdomainname', 172: 'iopl', 173: 'ioperm',
    174: 'create_module', 175: 'init_module', 176: 'delete_module', 177: 'get_kernel_syms', 178: 'query_module', 179: 'quotactl',
    180: 'nfsservctl', 181: 'getpmsg', 182: 'putpmsg', 183: 'afs_syscall', 184: 'tuxcall', 185: 'security',
    186: 'gettid', 187: 'readahead', 188: 'setxattr', 189: 'lsetxattr', 190: 'fsetxattr', 191: 'getxattr',
    192: 'lgetxattr', 193: 'fgetxattr', 194: 'listxattr', 195: 'llistxattr', 196: 'flistxattr', 197: 'removexattr',
    198: 'lremovexattr', 199: 'fremovexattr', 200: 'tkill', 201: 'time', 202: 'futex', 203: 'sched_setaffinity',
    204: 'sched_getaffinity', 205: 'set_thread_area', 206: 'io_setup', 207: 'io_destroy', 208: 'io_getevents', 209: 'io_submit',
    210: 'io_cancel', 211: 'get_thread_area', 212: 'lookup_dcookie', 213: 'epoll_create', 214: 'epoll_ctl_old', 215: 'epoll_wait_old',
    216: 'remap_file_pages', 217: 'getdents64', 218: 'set_tid_address', 219: 'restart_syscall', 220: 'semtimedop', 221: 'fadvise64',
    222: 'timer_create', 223: 'timer_settime', 224: 'timer_gettime', 225: 'timer_getoverrun', 226: 'timer_delete', 227: 'clock_settime',
    228: 'clock_gettime', 229: 'clock_getres', 230: 'clock_nanosleep', 231: 'exit_group', 232: 'epoll_wait', 233: 'epoll_ctl',
    234: 'tgkill', 235: 'utimes', 236: 'vserver', 237: 'mbind', 238: 'set_mempolicy', 239: 'get_mempolicy',
    240: 'mq_open', 241: 'mq_unlink', 242: 'mq_timedsend', 243: 'mq_timedreceive', 244: 'mq_notify', 245: 'mq_getsetattr',
    246: 'kexec_load', 247: 'waitid', 248: 'add_key', 249: 'request_key', 250: 'keyctl', 251: 'ioprio_set',
    252: 'ioprio_get', 253: 'inotify_init', 254: 'inotify_add_watch', 255: 'inotify_rm_watch', 256: 'migrate_pages', 257: 'openat',
    258: 'mkdirat', 259: 'mknodat', 260: 'fchownat', 261: 'futimesat', 262: 'newfstatat', 263: 'unlinkat',
    264: 'renameat', 265: 'linkat', 266: 'symlinkat', 267: 'readlinkat', 268: 'fchmodat', 269: 'faccessat',
    270: 'pselect6', 271: 'ppoll', 272: 'unshare', 273: 'set_robust_list', 274: 'get_robust_list', 275: 'splice',
    276: 'tee', 277: 'sync_file_range', 278: 'vmsplice', 279: 'move_pages', 280: 'utimensat', 281: 'epoll_pwait',
    282: 'signalfd', 283: 'timerfd_create', 284: 'eventfd', 285: 'fallocate', 286: 'timerfd_settime', 287: 'timerfd_gettime',
    288: 'accept4', 289: 'signalfd4', 290: 'eventfd2', 291: 'epoll_create1', 292: 'dup3', 293: 'pipe2',
    294: 'inotify_init1', 295: 'preadv', 296: 'pwritev', 297: 'rt_tgsigqueueinfo', 298: 'perf_event_open', 299: 'recvmmsg',
    300: 'fanotify_init', 301: 'fanotify_mark', 302: 'prlimit64', 303: 'name_to_handle_at', 304: 'open_by_handle_at', 305: 'clock_adjtime',
    306: 'syncfs', 307: 'sendmmsg', 308: 'setns', 309: 'getcpu', 310: 'process_vm_readv', 311: 'process_vm_writev',
    312: 'kcmp', 313: 'finit_module', 314: 'sched_setattr', 315: 'sched_getattr', 316: 'renameat2', 317: 'seccomp',
    318: 'getrandom', 319: 'memfd_create', 320: 'kexec_file_load', 321: 'bpf', 322: 'execveat', 323: 'userfaultfd',
    324: 'membarrier', 325: 'mlock2', 326: 'copy_file_range', 327: 'preadv2', 328: 'pwritev2', 329: 'pkey_mprotect',
    330: 'pkey_alloc', 331: 'pkey_free', 332: 'statx', 333: 'io_pgetevents', 334: 'rseq', 424: 'pidfd_send_signal',
    425: 'io_uring_setup', 426: 'io_uring_enter', 427: 'io_uring_register', 428: 'open_tree', 429: 'move_mount', 430: 'fsopen',
    431: 'fsconfig', 432: 'fsmount', 433: 'fspick', 434: 'pidfd_open', 435: 'clone3', 436: 'close_range',
    437: 'openat2', 438: 'pidfd_getfd', 439: 'faccessat2', 440: 'process_madvise', 441: 'epoll_pwait2', 442: 'mount_setattr',
    443: 'quotactl_fd', 444: 'landlock_create_ruleset', 445: 'landlock_add_rule', 446: 'landlock_restrict_self', 447: 'memfd_secret', 448: 'process_mrelease',
    449: 'futex_waitv', 450: 'set_mempolicy_home_node', 451: 'cachestat', 452: 'fchmodat2', 453: 'map_shadow_stack', 454: 'futex_wake',
    455: 'futex_wait', 456: 'futex_requeue', 457: 'statmount', 458: 'listmount', 459: 'lsm_get_self_attr', 460: 'lsm_set_self_attr',
    461: 'lsm_list_modules',
}


def syscall_name(sid, arch="x86_64"):
    """Resolve a syscall number to a name for the given architecture.
    Only x86_64 is mapped; other arches return None (numbering differs)."""
    if arch != "x86_64":
        return None
    try:
        return SYSCALLS_X86_64.get(int(sid))
    except (ValueError, TypeError):
        return None


# counters whose non-zero value indicates a problem (drops, failures, denials)
_NEG_RE = re.compile(r"drop|deni|fail|timed?[\s_-]*out|truncat|invalid|blocked|error|refus", re.I)
NEG_EXCESSIVE = 1000  # counter value at/above which a negative counter becomes CRIT (tunable)


def _neg_sev(key, val):
    """Return 'warn'/'crit'/None for a counter based on whether it is a
    negative signal and how large it is."""
    if not isinstance(val, (int, float)) or val <= 0:
        return None
    if not _NEG_RE.search(key):
        return None
    return CRIT if val >= NEG_EXCESSIVE else WARN


class Finding:
    """A single derived signal with a severity and human explanation."""

    def __init__(self, severity, title, detail="", code=None):
        self.severity = severity
        self.title = title
        self.detail = detail
        self.code = code  # stable key for remediation lookup

    def __repr__(self):
        return f"Finding({self.severity}, {self.title!r})"


# ---------------------------------------------------------------------------
# Low-level file helpers
# ---------------------------------------------------------------------------

# strip ANSI / terminal escape sequences (service_status.txt etc.)
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07|[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _clean(text):
    return _ANSI.sub("", text)


def read_text(diag_dir, name):
    """Return cleaned file text, or None if the file is absent/unreadable."""
    path = os.path.join(diag_dir, name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return _clean(fh.read())
    except OSError:
        return None


def read_json(diag_dir, name):
    text = read_text(diag_dir, name)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def parse_colon_kv(text):
    """Parse 'key : value' aligned lines (health.txt, health_details_features)."""
    out = {}
    if not text:
        return out
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if key:
            out[key] = val
    return out


# ---------------------------------------------------------------------------
# Individual parsers  (each returns a plain dict/list; never raises)
# ---------------------------------------------------------------------------

def parse_health(diag_dir):
    """health.txt — aligned 'key : value' pairs, values may end with [managed]."""
    kv = parse_colon_kv(read_text(diag_dir, "health.txt"))
    managed = {}
    clean = {}
    for k, v in kv.items():
        m = v.endswith("[managed]")
        managed[k] = m
        v = v.replace("[managed]", "").strip().strip('"')
        clean[k] = v
    return {"values": clean, "managed": managed} if clean else None


def parse_features(diag_dir):
    kv = parse_colon_kv(read_text(diag_dir, "health_details_features.txt"))
    if not kv:
        return None
    return {k: v.replace("[managed]", "").strip().strip('"') for k, v in kv.items()}


def parse_installation_report(diag_dir):
    data = read_json(diag_dir, "installation_report.json")
    if not data:
        return None
    return data.get("installation_report", data)


_TOP_HEADER = re.compile(r"^top\s+-\s+(\S+)\s+up")
_LOAD = re.compile(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)")
_CPU_LINE = re.compile(r"%Cpu\(s\):\s*(.+)")
_MEM_LINE = re.compile(r"MiB Mem\s*:\s*([\d.]+)\s+total,\s*([\d.]+)\s+free,\s*([\d.]+)\s+used,\s*([\d.]+)\s+buff")


def _parse_cpu_fields(s):
    """'14.6 us, 14.6 sy, 0.0 ni, 70.7 id, ...' -> dict."""
    out = {}
    for m in re.finditer(r"([\d.]+)\s+([a-z]+)", s):
        out[m.group(2)] = float(m.group(1))
    return out


def parse_top_single(diag_dir):
    """top.txt — one snapshot. Returns header stats + process rows."""
    text = read_text(diag_dir, "top.txt")
    if not text:
        return None
    return _parse_top_block(text)


def _parse_top_block(block):
    stats = {}
    procs = []
    in_table = False
    for line in block.splitlines():
        if _TOP_HEADER.search(line):
            m = _LOAD.search(line)
            if m:
                stats["load"] = [float(m.group(1)), float(m.group(2)), float(m.group(3))]
            tm = _TOP_HEADER.search(line)
            stats["time"] = tm.group(1)
            continue
        cm = _CPU_LINE.search(line)
        if cm:
            stats["cpu"] = _parse_cpu_fields(cm.group(1))
            continue
        mm = _MEM_LINE.search(line)
        if mm:
            stats["mem"] = {
                "total": float(mm.group(1)), "free": float(mm.group(2)),
                "used": float(mm.group(3)), "buff_cache": float(mm.group(4)),
            }
            continue
        if line.strip().startswith("PID") and "COMMAND" in line:
            in_table = True
            continue
        if in_table:
            parts = line.split(None, 11)
            if len(parts) < 12:
                continue
            try:
                procs.append({
                    "pid": parts[0], "user": parts[1],
                    "cpu": float(parts[8]), "mem": float(parts[9]),
                    "time": parts[10], "command": parts[11].strip(),
                })
            except (ValueError, IndexError):
                continue
    return {"stats": stats, "procs": procs}


def parse_top_series(diag_dir):
    """top_output.txt — many stacked top snapshots. Returns per-snapshot header
    stats (for time-series charts), the last full snapshot, and a wda cpu/mem track."""
    text = read_text(diag_dir, "top_output.txt")
    if not text:
        return None
    # split on each 'top - ... up' header
    blocks = re.split(r"(?=^top\s+-\s)", text, flags=re.MULTILINE)
    series = []
    last = None
    for b in blocks:
        if not b.strip():
            continue
        parsed = _parse_top_block(b)
        st = parsed["stats"]
        if not st:
            continue
        if parsed["procs"]:
            last = parsed
        # wdavdaemon aggregate cpu in this snapshot
        wda = sum(p["cpu"] for p in parsed["procs"] if p["command"].startswith("wdavdaemon"))
        point = {
            "time": st.get("time"),
            "load1": st.get("load", [None])[0],
            "cpu_used": None,
            "mem_used_pct": None,
            "wda_cpu": round(wda, 1),
        }
        cpu = st.get("cpu")
        if cpu:
            idle = cpu.get("id", 0.0)
            point["cpu_used"] = round(100.0 - idle, 1)
        mem = st.get("mem")
        if mem and mem["total"]:
            point["mem_used_pct"] = round(100.0 * mem["used"] / mem["total"], 1)
        series.append(point)
    return {"points": series, "last": last} if series else None


def parse_rtp_statistics(diag_dir):
    """rtp_statistics.txt — per-process scan blocks (files scanned + scan time)."""
    text = read_text(diag_dir, "rtp_statistics.txt")
    if not text:
        return None
    procs = []
    cur = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("====="):
            if cur:
                procs.append(cur)
                cur = {}
            continue
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip().strip('"')
        if k == "Process id":
            cur["pid"] = v
        elif k == "Name":
            cur["name"] = v
        elif k == "Path":
            cur["path"] = v
        elif k == "Total files scanned":
            cur["files"] = int(v) if v.isdigit() else 0
        elif k == "Scan time (ns)":
            cur["scan_ns"] = int(re.sub(r"\D", "", v) or 0)
        elif k == "Status":
            cur["status"] = v
    if cur:
        procs.append(cur)
    return {"procs": procs} if procs else None


def parse_event_statistics(diag_dir):
    """mde_event_statistics.txt — flat 'label count' counters."""
    text = read_text(diag_dir, "mde_event_statistics.txt")
    if not text:
        return None
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(.*?):\s*(\d+)\s*$", line.strip())
        if m:
            out[m.group(1).strip()] = int(m.group(2))
    return out or None


def parse_ebpf_statistics(diag_dir):
    """mde_ebpf_statistics.txt — syscall id counts + drop counters."""
    text = read_text(diag_dir, "mde_ebpf_statistics.txt")
    if not text:
        return None
    out = {"session_syscalls": {}, "top_syscalls": {}, "counters": {},
           "top_files": [], "top_initiators": []}
    section = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Top file paths"):
            section = "files"
            continue
        if s.startswith("Top initiator paths"):
            section = "initiators"
            continue
        if s.startswith("Top syscall ids"):
            section = "top"
            continue
        if s.startswith("Session syscall ids"):
            section = "session"
            continue
        m = re.match(r"^(\d+)\s*:\s*(\d+)$", s)
        if m and section == "top":
            out["top_syscalls"][m.group(1)] = int(m.group(2))
            continue
        if m and section == "session":
            out["session_syscalls"][m.group(1)] = int(m.group(2))
            continue
        cm = re.match(r"^([a-z_]+_count)\s*:\s*(\d+)$", s)
        if cm:
            out["counters"][cm.group(1)] = int(cm.group(2))
            continue
        # 'path : count'  or  'count : path'  or  'path <spaces> count'
        pm = re.match(r"^(.*\S)\s*:\s*(\d+)$", s) or re.match(r"^(\d+)\s*:\s*(.*\S)$", s)
        if pm and section in ("files", "initiators"):
            a, b = pm.group(1), pm.group(2)
            path, cnt = (b, a) if a.isdigit() else (a, b)
            try:
                out["top_" + section].append({"path": path, "count": int(cnt)})
            except ValueError:
                pass
    return out


def parse_process_information(diag_dir):
    """process_information.txt — ps aux style table."""
    text = read_text(diag_dir, "process_information.txt")
    if not text:
        return None
    # columns: PID PPID USER %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
    procs = []
    for line in text.splitlines()[1:]:
        parts = line.split(None, 11)
        if len(parts) < 12:
            continue
        try:
            procs.append({
                "pid": parts[0], "ppid": parts[1], "user": parts[2],
                "cpu": float(parts[3]), "mem": float(parts[4]),
                "vsz": int(parts[5]), "rss": int(parts[6]),
                "stat": parts[8], "command": parts[11].strip(),
            })
        except (ValueError, IndexError):
            continue
    return {"procs": procs} if procs else None


def parse_free(diag_dir):
    """memory.txt — `free` output."""
    text = read_text(diag_dir, "memory.txt")
    if not text:
        return None
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(Mem|Swap):\s+(\d+)\s+(\d+)\s+(\d+)", line)
        if m:
            out[m.group(1).lower()] = {
                "total": int(m.group(2)), "used": int(m.group(3)), "free": int(m.group(4)),
            }
    return out or None


def parse_disk_usage(diag_dir):
    text = read_text(diag_dir, "disk_usage.txt")
    if not text:
        return None
    rows = []
    for line in text.splitlines()[1:]:
        m = re.match(r"^(.*?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(.+)$", line)
        if m:
            rows.append({
                "fs": m.group(1).strip(), "size": m.group(2), "used": m.group(3),
                "avail": m.group(4), "use_pct": int(m.group(5)), "mount": m.group(6).strip(),
            })
    return {"rows": rows} if rows else None


def parse_uptime(diag_dir):
    text = read_text(diag_dir, "uptime_info.txt")
    return text.strip() if text else None


def parse_uname(diag_dir):
    """uname.txt — extract CPU architecture (drives syscall-name mapping)."""
    text = read_text(diag_dir, "uname.txt")
    if not text:
        return None
    arch = None
    for tok in ("x86_64", "aarch64", "arm64", "s390x", "ppc64le", "i686"):
        if re.search(rf"\b{re.escape(tok)}\b", text):
            arch = "x86_64" if tok == "x86_64" else ("arm64" if tok in ("aarch64", "arm64") else tok)
            break
    return {"arch": arch, "raw": text.strip()}


def parse_network_interfaces(diag_dir):
    """network_info.txt — parse `ip link show` + `ip address show` sections."""
    text = read_text(diag_dir, "network_info.txt")
    if not text:
        return None
    ifaces = {}
    order = []
    cur = None
    for line in text.splitlines():
        im = re.match(r"^\d+:\s+([\w.@-]+):\s+<([^>]*)>.*?mtu\s+(\d+)", line)
        if im:
            name = im.group(1).split("@")[0]
            cur = name
            if name not in ifaces:
                order.append(name)
            st = re.search(r"state\s+(\S+)", line)
            ifaces[name] = {"name": name, "flags": im.group(2), "mtu": im.group(3),
                            "state": st.group(1) if st else "?", "mac": "", "addrs": []}
            continue
        mm = re.search(r"link/\w+\s+([0-9a-f:]{17})", line)
        if mm and cur:
            ifaces[cur]["mac"] = mm.group(1)
        am = re.search(r"inet6?\s+(\S+)", line)
        if am and cur and cur in ifaces:
            ifaces[cur]["addrs"].append(am.group(1))
    return {"ifaces": [ifaces[n] for n in order]} if order else None


def parse_lsmod(diag_dir):
    text = read_text(diag_dir, "lsmod.txt")
    if not text:
        return None
    mods = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            mods.append({"name": parts[0], "size": int(parts[1]),
                         "used_by": parts[3] if len(parts) > 3 else ""})
    return {"count": len(mods), "modules": mods} if mods else None


def parse_lsns(diag_dir):
    text = read_text(diag_dir, "lsns_info.txt")
    if not text:
        return None
    by_type = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            by_type[parts[1]] = by_type.get(parts[1], 0) + 1
    return {"by_type": by_type, "count": sum(by_type.values())} if by_type else None


def parse_mounts(diag_dir):
    text = read_text(diag_dir, "mount.txt")
    if not text:
        return None
    by_type = {}
    total = 0
    for line in text.splitlines():
        tm = re.search(r"\btype\s+(\S+)", line)
        if tm:
            total += 1
            by_type[tm.group(1)] = by_type.get(tm.group(1), 0) + 1
    return {"count": total, "by_type": by_type} if total else None


_LAST_LOGIN_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\S+)\s+"
    r"((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2})\s*(.*)$")


def parse_last(diag_dir):
    """last_info.txt — `last` output: reboot (boot) history + user logins."""
    text = read_text(diag_dir, "last_info.txt")
    if not text:
        return None
    boots = []
    logins = []
    for line in text.splitlines():
        line = line.rstrip()
        if line.startswith("reboot"):
            boots.append(line.strip())
            continue
        if line.startswith("wtmp begins") or not line.strip():
            continue
        m = _LAST_LOGIN_RE.match(line)
        if not m:
            continue
        status = m.group(5).strip()
        logins.append({
            "user": m.group(1), "tty": m.group(2), "host": m.group(3),
            "at": m.group(4), "status": status,
            "active": "logged in" in status.lower(),
        })
    if not boots and not logins:
        return None
    return {
        "boot_count": len(boots), "recent": boots[:8],
        "login_count": len(logins), "logins": logins,
        "active_sessions": sum(1 for l in logins if l["active"]),
    }


def parse_sestatus(diag_dir):
    text = read_text(diag_dir, "sestatus.txt")
    if not text:
        return None
    if "could not run" in text.lower() or "not found" in text.lower():
        return {"available": False, "status": "not available"}
    m = re.search(r"SELinux status:\s*(\S+)", text)
    return {"available": True, "status": m.group(1) if m else text.strip()[:40]}


def parse_mde_xml(diag_dir):
    """mde.xml — analyzer summary: device_info fields, process statuses, events."""
    text = read_text(diag_dir, "mde.xml")
    if not text:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    out = {"general": {}, "device": {}, "events": []}
    gen = root.find("general")
    if gen is not None:
        for el in gen:
            out["general"][el.tag] = (el.text or "").strip()
    dev = root.find("device_info")
    if dev is not None:
        for el in dev:
            out["device"][el.tag] = {
                "label": el.get("display_name", el.tag),
                "value": (el.text or "").strip(),
            }
    evs = root.find("events")
    if evs is not None:
        for el in evs.findall("event"):
            eid = el.get("id")
            if eid:
                out["events"].append(eid)
    return out


def parse_cpuinfo(diag_dir):
    """cpuinfo.txt — may be `lscpu` output OR raw /proc/cpuinfo. Handle both."""
    text = read_text(diag_dir, "cpuinfo.txt")
    if not text:
        return None
    model = None
    count = 0
    for line in text.splitlines():
        low = line.strip().lower()
        # lscpu format
        if low.startswith("model name") and not model:
            model = line.partition(":")[2].strip()
        m = re.match(r"^CPU\(s\):\s*(\d+)", line.strip())
        if m and not count:
            count = int(m.group(1))
        # /proc/cpuinfo format (one 'processor' line per logical cpu)
        if re.match(r"^processor\s*:", low):
            count += 1
    return {"model": model, "logical_cpus": count} if (model or count) else None


def parse_exclusions(diag_dir):
    """exclusions.txt — block list of configured AV exclusions.

    Entries are separated by '---' and wrapped in '=====' rules. Each entry
    starts with a header line (the exclusion kind) followed by 'key: value'
    fields; the Scope field is a JSON array:

        Excluded process
        Process name: nikto
        Scope: ["epp"]
        ---
        Excluded process
        Process name: /usr/bin/nikto
        Scope: ["global"]
    """
    text = read_text(diag_dir, "exclusions.txt")
    if not text:
        return None
    stripped = re.sub(r"[=\s]", "", text).lower()
    if "noexclusion" in stripped:
        return {"none": True, "count": 0, "items": [], "raw": text.strip()}

    items = []
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if not s or set(s) <= {"="} or s == "---":
            # blank line, '=====' rule or '---' separator all close the entry
            if cur:
                items.append(cur)
                cur = None
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            k, v = k.strip(), v.strip()
            if cur is None:
                cur = {}
            if k.lower() == "scope":
                try:
                    v = json.loads(v)
                except (ValueError, TypeError):
                    v = [x for x in re.split(r'[\[\]",\s]+', v) if x]
            cur[k] = v
        else:
            # header line (e.g. "Excluded process") begins a new entry
            if cur:
                items.append(cur)
            cur = {"kind": s}
    if cur:
        items.append(cur)

    return {"none": not items, "count": len(items), "items": items, "raw": text.strip()}


def parse_conflicts(diag_dir):
    text = read_text(diag_dir, "conflicting_processes_information.txt")
    if not text:
        return None
    none = "no known conflict" in text.lower()
    return {"none": none, "raw": text.strip()}


def parse_service_status(diag_dir):
    """service_status.txt — `systemctl status mdatp` output."""
    text = read_text(diag_dir, "service_status.txt")
    if not text:
        return None
    active = bool(re.search(r"active\s*\(running\)", text, re.I))
    timed_out = "timed out" in text.lower()

    def find(rx):
        m = re.search(rx, text, re.I)
        return m.group(1).strip() if m else None

    # Loaded: loaded (...; disabled; preset: enabled)
    loaded = None
    lm = re.search(r"Loaded:\s*(\S+)\s*\(.*?;\s*(enabled|disabled|static|masked)", text, re.I)
    if lm:
        loaded = lm.group(2).lower()      # enabled/disabled at boot
    active_state = find(r"Active:\s*(.+?)\s+since") or find(r"Active:\s*([^\n]+)")
    since = find(r"Active:.*?since\s+(.+?);")
    ago = find(r"Active:.*?;\s*([^\n]+ ago)")
    main_pid = find(r"Main PID:\s*(\d+)")
    tasks = find(r"Tasks:\s*(\d+)")
    tasks_limit = find(r"Tasks:.*?limit:\s*(\d+)")
    cpu = find(r"\n\s*CPU:\s*([^\n]+)")

    # Memory: 87.8M (peak: 709.5M swap: 43.6M swap peak: 45.5M)
    mem_cur = find(r"Memory:\s*([\d.]+\w)")
    mem_peak = find(r"Memory:.*?peak:\s*([\d.]+\w)")
    mem_swap = find(r"Memory:.*?\bswap:\s*([\d.]+\w)")
    mem_swap_peak = find(r"Memory:.*?swap peak:\s*([\d.]+\w)")

    return {
        "active": active, "timed_out": timed_out,
        "loaded": loaded, "active_state": active_state, "since": since, "ago": ago,
        "main_pid": main_pid, "tasks": tasks, "tasks_limit": tasks_limit, "cpu": cpu,
        "mem_current": mem_cur, "mem_peak": mem_peak,
        "mem_swap": mem_swap, "mem_swap_peak": mem_swap_peak,
        "raw": text.strip(),
    }


# Curated MDE-relevant kernel tunables. Matched by substring against sysctl keys.
_SYSCTL_KEYS = (
    "fs.fanotify.", "fs.inotify.", "fs.epoll.max_user_watches",
    "fs.file-max", "fs.file-nr", "fs.nr_open",
    "kernel.pid_max", "kernel.threads-max", "kernel.unprivileged_bpf_disabled",
    "kernel.perf_event_paranoid", "kernel.dmesg_restrict", "kernel.yama.ptrace_scope",
    "vm.max_map_count", "vm.swappiness",
    "user.max_fanotify_groups", "user.max_fanotify_marks",
    "user.max_inotify_instances", "user.max_inotify_watches",
    "user.max_user_namespaces",
)


def parse_sysctl(diag_dir):
    """sysctl_info.txt — full `sysctl -a`; keep only MDE-relevant tunables."""
    text = read_text(diag_dir, "sysctl_info.txt")
    if not text:
        return None
    values = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if key and any(key.startswith(p) or key == p for p in _SYSCTL_KEYS):
            values.setdefault(key, val)   # first wins (some keys repeat, e.g. cdrom.info)
    return {"values": values} if values else None


def parse_threat_list(diag_dir):
    """threat_list.txt — `mdatp threat list`. 'No threats.' means clean."""
    text = read_text(diag_dir, "threat_list.txt")
    if not text:
        return None
    if re.search(r"\bno\s+threats?\b", text, re.I):
        return {"none": True, "threats": [], "raw": text.strip()}
    threats = []
    cur = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or set(s) <= {"-", "="}:
            if cur:
                threats.append(cur)
                cur = {}
            continue
        if ":" in s:
            k, _, v = s.partition(":")
            cur[k.strip()] = v.strip()
    if cur:
        threats.append(cur)
    return {"none": not threats, "threats": threats, "raw": text.strip()}


def parse_analyzer_log(diag_dir):
    """log.txt — analyzer run log; extract ERROR/WARNING lines."""
    text = read_text(diag_dir, "log.txt")
    if not text:
        return None
    errors, warnings, version = [], [], None
    for line in text.splitlines():
        vm = re.search(r"XMDEClientAnalyzer Version:\s*(\S+)", line)
        if vm:
            version = vm.group(1)
        if "[ERROR]" in line:
            errors.append(line.strip())
        elif "[WARNING]" in line:
            warnings.append(line.strip())
    return {"version": version, "errors": errors, "warnings": warnings}


# lsof: known TYPE tokens to anchor column parsing
_LSOF_TYPES = {
    "DIR", "REG", "CHR", "BLK", "FIFO", "unix", "IPv4", "IPv6", "sock",
    "a_inode", "netlink", "pack", "unknown", "KQUEUE", "PIPE", "FSEVENT",
}
# NB: lsof truncates COMMAND (default ~9 chars), so match on short prefixes
_MDATP_CMDS = ("wdav", "mdatp", "telemetr", "crashpad")
_NET_FS_HINT = re.compile(r"nfs|cifs|smb|fuse\.|\.gvfs|:/", re.I)


_LSOF_FD_RE = re.compile(r"^\d+[rwuWRU]?$")


def parse_lsof(diag_dir):
    """lsof.txt — system-wide open-file analysis, with an MDE-focused view.
    Per process: unique open FDs (deduped by (pid,fd) to undo thread listing),
    memory-mapped files, network/socket handles and deleted-but-open files."""
    path = os.path.join(diag_dir, "lsof.txt")
    if not os.path.isfile(path):
        return None
    # pid -> aggregate record
    per = {}             # pid -> {"cmd","fds":set,"mmap":set,"net":int,"deleted":int}
    net_all = []         # system-wide network/socket handles (capped)
    deleted_all = []     # system-wide deleted-but-open files (capped)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line[:1].strip():  # data rows start with COMMAND (no leading space)
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                # anchor on TYPE token; FD column is immediately before it
                type_idx = next((i for i, p in enumerate(parts) if p in _LSOF_TYPES), None)
                if type_idx is None or type_idx < 3:
                    continue
                cmd = parts[0]
                pid = parts[1]
                fd = parts[type_idx - 1]
                ftype = parts[type_idx]
                name = " ".join(parts[type_idx + 4:]) if len(parts) > type_idx + 4 else ""
                rec = per.get(pid)
                if rec is None:
                    rec = per[pid] = {"cmd": cmd, "fds": set(), "mmap": set(),
                                      "net": 0, "deleted": 0}
                if _LSOF_FD_RE.match(fd):
                    rec["fds"].add(fd)                 # real numeric descriptor
                elif fd in ("mem", "txt", "DEL", "ltx", "mmap"):
                    rec["mmap"].add(name)              # memory-mapped file (not an fd)
                if ftype in ("IPv4", "IPv6") or _NET_FS_HINT.search(name):
                    rec["net"] += 1
                    if len(net_all) < 500:
                        net_all.append({"pid": pid, "cmd": cmd, "type": ftype, "name": name})
                if name.endswith("(deleted)"):
                    rec["deleted"] += 1
                    if len(deleted_all) < 500:
                        deleted_all.append({"pid": pid, "cmd": cmd, "name": name})
    except OSError:
        return None
    if not per:
        return None

    procs = [{"pid": pid, "cmd": r["cmd"], "fds": len(r["fds"]), "mmap": len(r["mmap"]),
              "net": r["net"], "deleted": r["deleted"]} for pid, r in per.items()]
    procs.sort(key=lambda p: -p["fds"])

    is_mde = lambda c: c.startswith(_MDATP_CMDS)
    mde = [p for p in procs if is_mde(p["cmd"])]
    mde_net = [n for n in net_all if is_mde(n["cmd"])]
    mde_del = [d for d in deleted_all if is_mde(d["cmd"])]

    return {
        # --- MDE-focused (kept for existing findings/section) ---
        "total_fds": sum(p["fds"] for p in mde),
        "mmap_count": sum(p["mmap"] for p in mde),
        "fd_by_pid": {p["pid"]: p["fds"] for p in mde},
        "net_hits": mde_net,
        "net_count": len(mde_net),
        "deleted": mde_del,
        "deleted_count": len(mde_del),
        # --- system-wide ---
        "procs": procs,
        "proc_count": len(procs),
        "system_total_fds": sum(p["fds"] for p in procs),
        "net_all": net_all,
        "deleted_all": deleted_all,
    }


# Curated MDE-relevant log event rules: (category, severity, label, regex).
# Ordered by importance. AuditD is intentionally excluded (deprecated for MDE).
_LOG_RULES = [
    ("crash", CRIT, "wdavdaemon crash (segfault / fatal signal)",
     re.compile(r"wdavdaemon.*(segfault|potentially unexpected fatal signal|general protection|core dumped)", re.I)),
    ("oom", CRIT, "Out-of-memory kill",
     re.compile(r"out of memory|oom-kill|killed process", re.I)),
    ("hung", CRIT, "Hung / blocked task",
     re.compile(r"blocked for more than \d+ seconds|hung task", re.I)),
    ("onboarding", WARN, "Onboarding / health failure",
     re.compile(r"not healthy after onboarding|failed to configure microsoft defender", re.I)),
    ("installer", WARN, "Installer / packaging error",
     re.compile(r"install_script_errors|failed while executing pre-remove|WARN: Failed to (stop|start)", re.I)),
    ("ebpf", WARN, "eBPF load / attach error",
     re.compile(r"\bbpf\b.*(error|fail|unable|cannot)|failed to load.*bpf", re.I)),
    ("fanotify", WARN, "fanotify error",
     re.compile(r"fanotify.*(error|fail|denied|cannot)", re.I)),
    ("telemetry", INFO, "Telemetry submission failure",
     re.compile(r"telemetry.*(failed|aborted)", re.I)),
]

_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")


def _archive_lines(path):
    """Yield decoded text lines from a .zip (handling inner .gz members)."""
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        try:
            raw = zf.read(name)
            if name.endswith(".gz"):
                raw = gzip.decompress(raw)
            text = raw.decode("utf-8", "replace")
        except Exception:
            continue
        base = name.rsplit("/", 1)[-1]
        for line in text.splitlines():
            yield base, line


def parse_log_archives(diag_dir, cutoff=None):
    """Scan every *.zip in the directory for curated MDE events.
    Returns per-category {count, first, last, sample[]} plus scanned file list.
    `cutoff` (normalized 'YYYY-MM-DD HH:MM:SS') drops older timestamped lines."""
    zips = [f for f in sorted(os.listdir(diag_dir)) if f.endswith(".zip")]
    if not zips:
        return None
    cats = {}
    scanned = []
    MAX_SAMPLES = 6
    for z in zips:
        # skip the agent diagnostic bundle (binary/internal), keep OS + MDC logs
        if z == "mde_diagnostic.zip":
            continue
        scanned.append(z)
        for base, line in _archive_lines(os.path.join(diag_dir, z)):
            if cutoff:
                tm = _TS.search(line)
                if tm and tm.group(1).replace("T", " ") < cutoff:
                    continue  # event older than the age window
            for cat, sev, label, rx in _LOG_RULES:
                if rx.search(line):
                    e = cats.setdefault(cat, {
                        "severity": sev, "label": label, "count": 0,
                        "first": None, "last": None, "sample": [],
                    })
                    e["count"] += 1
                    tm = _TS.search(line)
                    ts = tm.group(1).replace("T", " ") if tm else None
                    if ts:
                        if not e["first"] or ts < e["first"]:
                            e["first"] = ts
                        if not e["last"] or ts > e["last"]:
                            e["last"] = ts
                    if len(e["sample"]) < MAX_SAMPLES:
                        e["sample"].append(f"[{base}] {line.strip()[:200]}")
                    break  # one rule per line
    return {"categories": cats, "scanned": scanned} if scanned else None


# log level tag inside MDE product logs, e.g. [...][...][ts UTC][error]: msg
_PLOG_LINE = re.compile(r"\]\[(error|warning|warn)\]:\s*(.*)$", re.I)
_PLOG_TS = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
# product log files worth summarising (under var/log/microsoft/mdatp/)
_PLOG_PREFIX = "var/log/microsoft/mdatp/"


def _normalize_err(msg):
    """Collapse a log message into a signature so recurring errors group together."""
    m = msg
    m = re.sub(r"0x[0-9a-fA-F]+", "0x#", m)
    m = re.sub(r"\b[0-9a-fA-F]{16,}\b", "#", m)      # hashes / long ids
    m = re.sub(r"\b\d+\b", "#", m)                    # numbers
    m = re.sub(r'"/[^"]*"', '"<path>"', m)            # quoted paths
    m = re.sub(r"/\S+", "<path>", m)                  # bare paths
    return m.strip()[:180]


def parse_mde_diagnostic(diag_dir, cutoff=None):
    """Extract mde_diagnostic.zip in-memory and mine the MDE product logs +
    structured state files. Signature blobs (enginedb/RtSigs) are ignored.
    `cutoff` (normalized 'YYYY-MM-DD HH:MM:SS') drops older log lines."""
    path = os.path.join(diag_dir, "mde_diagnostic.zip")
    if not os.path.isfile(path):
        return None
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return None

    from collections import Counter
    logs = []
    err_sigs = Counter()
    err_example = {}
    err_last = {}   # signature -> most recent occurrence timestamp (for live age filter)

    for name in zf.namelist():
        if name.endswith("/") or "/RtSigs/" in name:
            continue
        base = name.rsplit("/", 1)[-1]

        # ---- product logs: count error/warn lines, group recurring errors ----
        # (crashes are covered by the kernel-log scan; recurring product errors
        #  surface via the error-signature grouping below, so no per-line rule
        #  matching is needed here — that kept ~35 MB of scanning off the hot path)
        if name.startswith(_PLOG_PREFIX) and (name.endswith(".log") or ".log000" in name):
            try:
                text = zf.read(name).decode("utf-8", "replace")
            except Exception:
                continue
            errs = warns = 0
            first_ts = last_ts = None
            samples = []
            for line in text.splitlines():
                lm = _PLOG_LINE.search(line)
                if not lm:
                    continue
                if cutoff:
                    ptm = _PLOG_TS.search(line)
                    if ptm and ptm.group(1) < cutoff:
                        continue  # log line older than the age window
                tm = _PLOG_TS.search(line)
                ts = tm.group(1) if tm else None
                if lm.group(1).lower().startswith("error"):
                    errs += 1
                    sig = _normalize_err(lm.group(2))
                    err_sigs[sig] += 1
                    example = f"[{base}] {line.strip()[:220]}"
                    # show the MOST RECENT occurrence so the example's date matches
                    # the signature's last-seen time (and the live age filter)
                    if ts and ts >= err_last.get(sig, ""):
                        err_last[sig] = ts
                        err_example[sig] = example
                    err_example.setdefault(sig, example)
                    if len(samples) < 4:
                        samples.append(line.strip()[:220])
                else:
                    warns += 1
                if ts:
                    if not first_ts or ts < first_ts:
                        first_ts = ts
                    if not last_ts or ts > last_ts:
                        last_ts = ts
            if errs or warns:
                logs.append({"file": base, "size": zf.getinfo(name).file_size,
                             "errors": errs, "warns": warns,
                             "first": first_ts, "last": last_ts, "samples": samples})

    # ---- structured state files ----
    def read_member(n):
        try:
            return zf.read(n).decode("utf-8", "replace")
        except Exception:
            return None

    counters = None
    ct = read_member(_PLOG_PREFIX + "microsoft_defender_diagnostic_event_provider_counters.json")
    if ct:
        try:
            counters = json.loads(ct)
        except ValueError:
            counters = None

    crash_state = None
    cs = read_member("var/opt/microsoft/mdatp/wdav_crash_state")
    if cs:
        try:
            crash_state = json.loads(cs)
        except ValueError:
            crash_state = None

    os_pretty = None
    osr = read_member("usr/lib/os-release") or read_member("etc/os-release")
    if osr:
        mo = re.search(r'PRETTY_NAME="?([^"\n]+)"?', osr)
        if mo:
            os_pretty = mo.group(1)

    def read_json_member(n):
        t = read_member(n)
        if not t:
            return None
        try:
            return json.loads(t)
        except ValueError:
            return None

    # managed attach config (AV / cloud enforcement)
    managed = read_json_member("etc/opt/microsoft/mdatp/managed/mdeattach_managed.json")

    # security management (Intune/MDM) policy application report
    policy_report = read_json_member("var/opt/microsoft/mdatp/security_management/current_report")
    policy_settings = []
    if policy_report:
        for pol in policy_report.get("policyInfo", []):
            for s in pol.get("settings", []):
                policy_settings.append({"name": s.get("name", ""), "value": s.get("value", "")})
    # signed policy bundle (opaque) — count only
    pol_bundle = read_json_member("var/opt/microsoft/mdatp/security_management/policy")
    policy_count = len(pol_bundle.get("policies", [])) if isinstance(pol_bundle, dict) else 0

    # scan history
    def ems(v):
        try:
            return int(v) / 1000.0
        except (ValueError, TypeError):
            return None
    scans = []
    hist = read_json_member("var/opt/microsoft/mdatp/wdavhistory")
    if isinstance(hist, dict):
        for sc in hist.get("scans", []):
            start, end = ems(sc.get("startTime")), ems(sc.get("endTime"))
            scans.append({
                "type": sc.get("type", "?"),
                "state": sc.get("state", "?"),
                "files": int(sc.get("filesScanned", 0) or 0),
                "scheduled": bool(sc.get("scheduled")),
                "threats": sc.get("threats") or [],
                "start": start, "end": end,
                "duration": (end - start) if (start and end) else None,
            })

    top_errors = [{"sig": s, "count": c, "example": err_example.get(s, ""),
                   "last": err_last.get(s, "")}
                  for s, c in err_sigs.most_common(15)]

    return {
        "logs": sorted(logs, key=lambda x: -x["errors"]),
        "top_errors": top_errors,
        "total_errors": sum(l["errors"] for l in logs),
        "counters": counters,
        "crash_state": crash_state,
        "os_pretty": os_pretty,
        "managed": managed,
        "policy_settings": policy_settings,
        "policy_count": policy_count,
        "scans": scans,
    }


# ---------------------------------------------------------------------------
# Master parse
# ---------------------------------------------------------------------------

def _age_cutoff(mx, max_age_days):
    """Normalized 'YYYY-MM-DD HH:MM:SS' cutoff N days before capture time
    (from mde.xml script_run_time, else local now), or None if disabled."""
    if not max_age_days:
        return None
    ref = None
    srt = ((mx or {}).get("general") or {}).get("script_run_time")
    if srt:
        try:
            ref = datetime.fromisoformat(srt).replace(tzinfo=None)
        except ValueError:
            ref = None
    if ref is None:
        ref = datetime.now()
    return (ref - timedelta(days=max_age_days)).strftime("%Y-%m-%d %H:%M:%S")


def parse_all(diag_dir, max_age_days=None):
    mx = parse_mde_xml(diag_dir)
    cutoff = _age_cutoff(mx, max_age_days)
    return {
        "health": parse_health(diag_dir),
        "features": parse_features(diag_dir),
        "install": parse_installation_report(diag_dir),
        "top": parse_top_single(diag_dir),
        "top_series": parse_top_series(diag_dir),
        "rtp": parse_rtp_statistics(diag_dir),
        "events": parse_event_statistics(diag_dir),
        "ebpf": parse_ebpf_statistics(diag_dir),
        "procs": parse_process_information(diag_dir),
        "free": parse_free(diag_dir),
        "disk": parse_disk_usage(diag_dir),
        "uptime": parse_uptime(diag_dir),
        "uname": parse_uname(diag_dir),
        "mde_xml": mx,
        "netifaces": parse_network_interfaces(diag_dir),
        "lsmod": parse_lsmod(diag_dir),
        "lsns": parse_lsns(diag_dir),
        "mounts": parse_mounts(diag_dir),
        "last": parse_last(diag_dir),
        "sysctl": parse_sysctl(diag_dir),
        "threats": parse_threat_list(diag_dir),
        "sestatus": parse_sestatus(diag_dir),
        "cpuinfo": parse_cpuinfo(diag_dir),
        "exclusions": parse_exclusions(diag_dir),
        "conflicts": parse_conflicts(diag_dir),
        "service": parse_service_status(diag_dir),
        "log": parse_analyzer_log(diag_dir),
        "lsof": parse_lsof(diag_dir),
        "logarch": parse_log_archives(diag_dir, cutoff),
        "mdediag": parse_mde_diagnostic(diag_dir, cutoff),
    }


# ---------------------------------------------------------------------------
# Analyzers — turn parsed data into Findings
# ---------------------------------------------------------------------------

# thresholds (tunable)
WDA_CPU_WARN = 40.0     # aggregate wdavdaemon %CPU
WDA_CPU_CRIT = 70.0
SCAN_MS_WARN = 100.0    # per-process scan time
SCAN_MS_CRIT = 500.0
DISK_WARN = 85
DISK_CRIT = 95
FD_WARN = 5000
FD_CRIT = 20000


def _is_pseudo_mount(r):
    """Read-only / virtual mounts that report misleading usage (snap, loop, tmpfs)."""
    mount = r.get("mount", "")
    fs = r.get("fs", "")
    if mount.startswith(("/snap/", "/sys", "/proc", "/dev", "/run", "/init", "/mnt/wsl")):
        return True
    if fs in ("none", "tmpfs", "overlay", "rootfs", "squashfs", "drivers"):
        return True
    return False


def analyze(data):
    findings = []
    f = findings.append

    # --- MDE health ---
    h = (data.get("health") or {}).get("values", {})
    if h:
        if h.get("healthy") == "true":
            f(Finding(OK, "MDE reports healthy"))
        else:
            issues = h.get("health_issues", "")
            f(Finding(CRIT, "MDE reports unhealthy", issues))
        if h.get("real_time_protection_enabled") == "true":
            subsys = h.get("real_time_protection_subsystem", "?")
            f(Finding(INFO, f"Real-time protection ON (subsystem: {subsys})"))
        if h.get("passive_mode_enabled") == "true":
            f(Finding(INFO, "Passive mode enabled"))
        if h.get("definitions_status") and h["definitions_status"] != "up_to_date":
            f(Finding(WARN, f"Definitions not up to date: {h['definitions_status']}"))
        try:
            mins = int(h.get("definitions_updated_minutes_ago", "0"))
            if mins > 1440:
                f(Finding(WARN, f"Definitions last updated {mins} min ago (>24h)"))
        except ValueError:
            pass
        conflicts = h.get("conflicting_applications", "")
        if conflicts and conflicts not in ("[]", ""):
            f(Finding(WARN, "Conflicting applications reported", conflicts))

    # --- wdavdaemon CPU footprint ---
    wda_cpu = _wda_cpu(data)
    if wda_cpu is not None:
        if wda_cpu >= WDA_CPU_CRIT:
            f(Finding(CRIT, f"wdavdaemon CPU high: {wda_cpu:.0f}% aggregate",
                      "Sustained high AV CPU. Review exclusions & scanned paths.", code="wda_cpu"))
        elif wda_cpu >= WDA_CPU_WARN:
            f(Finding(WARN, f"wdavdaemon CPU elevated: {wda_cpu:.0f}% aggregate",
                      "Check scan hotspots and consider exclusions.", code="wda_cpu"))
        else:
            f(Finding(OK, f"wdavdaemon CPU nominal: {wda_cpu:.0f}% aggregate"))

    # --- scan hotspots (rtp_statistics) ---
    rtp = data.get("rtp")
    if rtp:
        hottest = sorted(rtp["procs"], key=lambda p: p.get("scan_ns", 0), reverse=True)
        for p in hottest[:1]:
            ms = p.get("scan_ns", 0) / 1e6
            if ms >= SCAN_MS_CRIT:
                f(Finding(CRIT, f"High scan time: {p.get('name')} {ms:.0f} ms ({p.get('files')} files)",
                          p.get("path", ""), code="scan_hot"))
            elif ms >= SCAN_MS_WARN:
                f(Finding(WARN, f"Elevated scan time: {p.get('name')} {ms:.0f} ms ({p.get('files')} files)",
                          p.get("path", ""), code="scan_hot"))

    # --- eBPF / event drops ---
    ev = data.get("events") or {}
    ebpf = data.get("ebpf") or {}
    drop_keys = [k for k in ev if "dropped" in k.lower() or "timed out" in k.lower()]
    for k in drop_keys:
        if ev[k] > 0:
            f(Finding(WARN, f"Event drops: {k} = {ev[k]}",
                      "Dropped/timed-out events can mean load or queue pressure."))
    for k, v in (ebpf.get("counters") or {}).items():
        if "dropped" in k and v > 0:
            f(Finding(WARN, f"eBPF drop counter {k} = {v}"))

    # --- exclusions ---
    exc = data.get("exclusions")
    if exc and exc.get("none") and wda_cpu is not None and wda_cpu >= WDA_CPU_WARN:
        f(Finding(WARN, "No AV exclusions configured while AV CPU is elevated",
                  "Consider excluding high-churn dev/build/DB paths.", code="no_excl"))

    # --- conflicts ---
    conf = data.get("conflicts")
    if conf and not conf.get("none"):
        f(Finding(WARN, "Potential conflicting processes detected", conf.get("raw", "")))

    # --- service ---
    svc = data.get("service")
    if svc:
        if svc.get("timed_out"):
            f(Finding(WARN, "mdatp service status command timed out",
                      "Daemon may be slow/unresponsive under load.", code="svc_timeout"))
        if svc.get("active") is False:
            f(Finding(CRIT, "mdatp.service not active (running)"))
        if svc.get("loaded") == "disabled":
            f(Finding(WARN, "mdatp.service not enabled at boot",
                      "Service is 'disabled'; MDE will not start automatically after reboot.",
                      code="svc_disabled"))

    # --- threats (mdatp threat list) ---
    thr = data.get("threats")
    if thr and thr.get("threats"):
        f(Finding(CRIT, f"Active threats listed: {len(thr['threats'])}",
                  "mdatp threat list is not empty — review and respond.", code="threats"))

    # --- connectivity (installation_report) ---
    inst = data.get("install") or {}
    conn = inst.get("connectivitytest") or {}
    failed = [u for u, r in conn.items() if "[ERROR]" in r or "[FAIL]" in r]
    if failed:
        f(Finding(WARN, f"Connectivity test failures: {len(failed)} endpoint(s)",
                  "; ".join(failed), code="conn_fail"))
    elif conn:
        f(Finding(OK, f"All {len(conn)} connectivity endpoints reachable"))
    distro = inst.get("distro") or {}
    if distro and distro.get("is_supported") is False:
        f(Finding(CRIT, "Distro reported unsupported", distro.get("reason") or ""))

    # --- disk (ignore read-only snap/loop/pseudo mounts; always 100% by design) ---
    disk = data.get("disk")
    if disk:
        for r in disk["rows"]:
            if _is_pseudo_mount(r):
                continue
            if r["use_pct"] >= DISK_CRIT:
                f(Finding(CRIT, f"Disk nearly full: {r['mount']} {r['use_pct']}%"))
            elif r["use_pct"] >= DISK_WARN:
                f(Finding(WARN, f"Disk high: {r['mount']} {r['use_pct']}%"))

    # --- lsof scoped ---
    lsof = data.get("lsof")
    if lsof:
        total = lsof["total_fds"]
        if total >= FD_CRIT:
            f(Finding(CRIT, f"MDE open file descriptors very high: {total}",
                      "Possible handle leak.", code="fd_high"))
        elif total >= FD_WARN:
            f(Finding(WARN, f"MDE open file descriptors elevated: {total}"))
        if lsof["net_count"] > 0:
            f(Finding(WARN, f"MDE holds {lsof['net_count']} network-fs/socket handle(s)",
                      "Scanning network filesystems is a common slowdown source.", code="net_fs"))
        if lsof["deleted_count"] > 20:
            f(Finding(WARN, f"MDE holds {lsof['deleted_count']} deleted-but-open files",
                      "Can inflate memory/disk usage."))

    # --- historical events from log archives (syslog / kernel / MDC) ---
    la = data.get("logarch")
    if la:
        for cat, e in sorted(la["categories"].items(), key=lambda kv: -SEV_RANK[kv[1]["severity"]]):
            span = ""
            if e["first"] and e["last"]:
                span = (f" — first {e['first']}, last {e['last']}"
                        if e["first"] != e["last"] else f" — {e['first']}")
            detail = (e["sample"][0] if e["sample"] else "") + span
            f(Finding(e["severity"], f"{e['label']} ×{e['count']} (logs)", detail, code=f"log_{cat}"))

    # --- MDE product logs (mde_diagnostic.zip) ---
    md = data.get("mdediag")
    if md:
        # dropped event-provider messages
        c = md.get("counters") or {}
        for k, v in c.items():
            try:
                iv = int(v)
            except (ValueError, TypeError):
                continue
            if k.lower().startswith("dropped") and iv > 0:
                sev = CRIT if iv >= NEG_EXCESSIVE else WARN
                f(Finding(sev, f"Event provider {k} = {iv}",
                          "Dropped provider messages mean events are being lost under load.",
                          code="ebpf_drop"))
        # recurring product-log errors
        te = md.get("top_errors") or []
        if te and te[0]["count"] >= 50:
            f(Finding(WARN, f"Recurring product-log error ×{te[0]['count']}",
                      te[0]["example"], code="prod_err"))
        # pending crash uploads
        cs = md.get("crash_state") or {}
        try:
            if int(cs.get("uploadCount", 0)) > 0:
                f(Finding(WARN, f"Pending wdavdaemon crash uploads: {cs['uploadCount']}",
                          code="log_crash"))
        except (ValueError, TypeError):
            pass

    # --- mde.xml process statuses + conflicting agents ---
    mx = data.get("mde_xml")
    if mx:
        dev = mx.get("device", {})
        ca = (dev.get("conflicting_agents") or {}).get("value", "")
        if str(ca).strip().strip('"') not in ("", "[]", "{}", "none", "null"):
            f(Finding(CRIT, "Conflicting agents detected", ca, code="conflict"))
        for key in ("edr_process_status", "av_process_status", "telemetry_process_status"):
            item = dev.get(key)
            if not item:
                continue
            val = item["value"]
            label = item["label"]
            if val.lower() in ("running", "active", "up"):
                continue
            # telemetry down is less severe than AV/EDR down
            sev = WARN if key == "telemetry_process_status" else CRIT
            f(Finding(sev, f"{label}: {val}",
                      "Component not running." if sev == CRIT else "Telemetry channel down.",
                      code="proc_down"))

    # --- policy application (Intune/MDM) results ---
    md = data.get("mdediag") or {}
    ps = md.get("policy_settings") or []
    failed_pol = [p for p in ps if p["value"].lower() not in ("success", "applied", "")]
    if failed_pol:
        names = "; ".join(p["name"] for p in failed_pol[:5])
        f(Finding(WARN, f"Management policy settings not applied: {len(failed_pol)}",
                  names, code="policy_fail"))
    elif ps:
        f(Finding(OK, f"All {len(ps)} management policy settings applied successfully"))

    # --- scan history ---
    scans = md.get("scans") or []
    if scans:
        failed = [s for s in scans if s["state"].lower() not in ("succeeded", "completed")]
        threats = [s for s in scans if s["threats"]]
        if threats:
            f(Finding(CRIT, f"Threats recorded in scan history: {len(threats)} scan(s)",
                      code="threats"))
        if failed:
            f(Finding(WARN, f"Failed/incomplete scans in history: {len(failed)} of {len(scans)}",
                      code="scan_fail"))
        if not failed and not threats:
            f(Finding(OK, f"Scan history clean: {len(scans)} scans, no threats"))

    # --- analyzer log errors ---
    log = data.get("log")
    if log and log.get("errors"):
        f(Finding(INFO, f"Analyzer logged {len(log['errors'])} error(s) during collection",
                  "May indicate missing tools on host, not necessarily MDE issues."))

    return findings


def _top_snapshot(data):
    """Return the best available single top snapshot {stats,procs}."""
    top = data.get("top")
    if top and top.get("procs"):
        return top
    series = data.get("top_series")
    if series and series.get("last"):
        return series["last"]
    return None


def _wda_cpu(data):
    """Aggregate wdavdaemon %CPU from the best available top snapshot."""
    snap = _top_snapshot(data)
    if snap and snap.get("procs"):
        return sum(p["cpu"] for p in snap["procs"] if p["command"].startswith("wdavdaemon"))
    procs = data.get("procs")
    if procs:
        return sum(p["cpu"] for p in procs["procs"] if "wdavdaemon" in p["command"])
    return None


def overall_verdict(findings):
    worst = max((SEV_RANK[f.severity] for f in findings), default=0)
    if worst >= 2:
        return CRIT, "Critical issues found"
    if worst >= 1:
        return WARN, "Warnings found — review recommended"
    return OK, "No significant issues detected"


def health_score(findings):
    """Weighted 0-100 posture score derived from finding severities."""
    score = 100
    weights = {CRIT: 22, WARN: 7, INFO: 0, OK: 0}
    for f in findings:
        score -= weights.get(f.severity, 0)
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Remediation & correlation
# ---------------------------------------------------------------------------

# per-finding remediation: code -> (why, [commands])
REMEDIATION = {
    "wda_cpu": ("Real-time scanning is burning CPU. Identify the churn source and exclude it.",
                ["sudo mdatp diagnostic real-time-protection-statistics --sort --top 20",
                 "sudo mdatp exclusion folder add --path /path/to/high-churn-dir"]),
    "scan_hot": ("A specific process/path dominates scan time. Add a targeted exclusion.",
                 ["sudo mdatp exclusion folder add --path <hot_path>",
                  "sudo mdatp exclusion process add --name <process_name>"]),
    "no_excl": ("No exclusions while AV CPU is elevated. Exclude build/DB/container dirs.",
                ["sudo mdatp exclusion folder add --path /var/lib/docker",
                 "sudo mdatp exclusion extension add --extension .log"]),
    "svc_timeout": ("Daemon slow/unresponsive. Restart and re-check health.",
                    ["sudo systemctl restart mdatp",
                     "mdatp health --field healthy"]),
    "svc_disabled": ("mdatp.service is disabled and will not start after a reboot. Enable it.",
                     ["sudo systemctl enable mdatp",
                      "systemctl is-enabled mdatp"]),
    "conn_fail": ("One or more required cloud endpoints are unreachable. Fix egress/proxy.",
                  ["mdatp connectivity test",
                   "# allow the failing URLs through the firewall/proxy"]),
    "fd_high": ("Open file-descriptor count is high — possible handle leak. Restart & watch.",
                ["sudo systemctl restart mdatp",
                 "ls /proc/$(pgrep -f wdavdaemon | head -1)/fd | wc -l"]),
    "net_fs": ("MDE holds network-filesystem handles; scanning remote mounts is slow.",
               ["sudo mdatp exclusion folder add --path /mnt/<network_mount>"]),
    "log_crash": ("wdavdaemon crashed previously. Collect the dump and update to the latest build.",
                  ["sudo mdatp health --field app_version",
                   "sudo apt-get update && sudo apt-get install --only-upgrade mdatp",
                   "ls -la /var/opt/microsoft/mdatp/crash/"]),
    "log_oom": ("Out-of-memory kill in logs. Add RAM or cap MDE memory; check host pressure.",
                ["free -h", "dmesg -T | grep -i oom"]),
    "log_onboarding": ("Onboarding/health failures recorded. Re-run onboarding and verify.",
                       ["sudo mdatp health --field org_id",
                        "sudo /opt/microsoft/mdatp/sbin/mdatp_onboard.sh  # or re-apply the Azure extension"]),
    "log_installer": ("Installer/packaging errors recorded. Re-run install/upgrade cleanly.",
                      ["sudo apt-get install --reinstall mdatp",
                       "journalctl -u mdatp --no-pager | tail -50"]),
    "log_ebpf": ("eBPF load/attach errors. Verify kernel eBPF support and provider config.",
                 ["mdatp health --field supplementary_events_subsystem",
                  "sudo mdatp config ebpf-supplementary-event-provider --value enabled"]),
    "log_fanotify": ("fanotify errors. Check RTP subsystem and kernel fanotify support.",
                     ["mdatp health --field real_time_protection_subsystem"]),
    "ebpf_drop": ("The event provider is dropping messages — events lost under load. "
                  "Check CPU pressure and provider config.",
                  ["mdatp health --field supplementary_events_subsystem",
                   "sudo mdatp diagnostic real-time-protection-statistics --sort --top 20"]),
    "prod_err": ("A product-log error is repeating frequently. Inspect the MDE logs.",
                 ["sudo tail -n 200 /var/log/microsoft/mdatp/microsoft_defender_err.log",
                  "sudo tail -n 200 /var/log/microsoft/mdatp/microsoft_defender_core_err.log"]),
    "proc_down": ("An MDE component process is not running. Restart the service and re-check.",
                  ["sudo systemctl restart mdatp",
                   "mdatp health --field edr_early_preview_enabled",
                   "sudo systemctl status mdatp"]),
    "policy_fail": ("One or more Intune/MDM security-management settings did not apply.",
                    ["sudo mdatp health --field managed_by",
                     "cat /var/opt/microsoft/mdatp/security_management/current_report"]),
    "scan_fail": ("Scans failed or did not complete. Review scan history and run a fresh scan.",
                  ["mdatp scan quick",
                   "mdatp health --field definitions_status"]),
    "threats": ("Threats were recorded in scan history. Review and respond.",
                ["mdatp threat list",
                 "mdatp threat quarantine list"]),
    "conflict": ("Another security/AV agent is running alongside MDE — this causes "
                 "high CPU and instability. Remove the conflicting agent or set MDE to passive mode.",
                 ["mdatp health --field conflicting_applications",
                  "# uninstall the third-party AV, or:",
                  "sudo mdatp config passive-mode --value enabled"]),
}


def recommendations(data, findings):
    """Correlate findings into higher-level, actionable recommendation cards.
    Each card: {severity, title, why, commands[]}."""
    cards = []
    codes = {f.code for f in findings if f.code}
    folded = set()   # per-finding codes already absorbed into a correlation card

    # correlation: elevated AV CPU + hot scan + no exclusions => one root cause
    if ("wda_cpu" in codes or "scan_hot" in codes) and "no_excl" in codes:
        hot = ""
        rtp = data.get("rtp")
        if rtp:
            top = max(rtp["procs"], key=lambda p: p.get("scan_ns", 0), default=None)
            if top and top.get("scan_ns"):
                hot = f" The hottest scanner is {top.get('name')} ({top.get('path','')})."
        cards.append({
            "severity": WARN,
            "title": "AV CPU is elevated and no exclusions are configured",
            "why": "High wdavdaemon scan cost with zero exclusions strongly suggests a "
                   "high-churn path being scanned repeatedly." + hot,
            "commands": [
                "sudo mdatp diagnostic real-time-protection-statistics --sort --top 20",
                "sudo mdatp exclusion folder add --path <hot_path_from_above>",
            ],
        })
        folded |= {"wda_cpu", "scan_hot", "no_excl"}

    # correlation: crashes + onboarding failures => version/stability problem
    if "log_crash" in codes:
        la = (data.get("logarch") or {}).get("categories", {}).get("crash", {})
        h = (data.get("health") or {}).get("values", {})
        ver = h.get("app_version", "?")
        cards.append({
            "severity": CRIT,
            "title": f"wdavdaemon has crashed (current build {ver})",
            "why": f"{la.get('count','?')} crash signal(s) in kernel logs "
                   f"(last {la.get('last','?')}). Crashes in libwdavdaemon_core usually "
                   "mean a defect fixed in a newer build.",
            "commands": [
                "sudo apt-get update && sudo apt-get install --only-upgrade mdatp",
                "ls -la /var/opt/microsoft/mdatp/crash/",
                "# open a support case with the crash dump if it persists on the latest build",
            ],
        })
        folded.add("log_crash")

    # per-finding remediation cards (skip ones already folded into a correlation)
    seen = set()
    for f in sorted(findings, key=lambda x: -SEV_RANK[x.severity]):
        if not f.code or f.code in folded or f.code in seen:
            continue
        rem = REMEDIATION.get(f.code)
        if not rem:
            continue
        seen.add(f.code)
        why, cmds = rem
        cards.append({"severity": f.severity, "title": f.title, "why": why, "commands": cmds})
    return cards


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def esc(x):
    return html.escape(str(x))


def _fmt_ts(epoch):
    """Epoch seconds (float) -> 'YYYY-MM-DD HH:MM:SS UTC'."""
    if not epoch:
        return "?"
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError, OverflowError):
        return "?"


# value-semantics coloring for config/health cells
_STATUS_POS = {"true", "enabled", "enable", "on", "running", "active", "available",
               "up", "yes", "succeeded", "success", "up_to_date", "healthy", "normal", "optimal"}
_STATUS_WARN = {"false", "disabled", "disable", "off", "no", "unavailable",
                "not_available", "none", "paused", "pending"}
_STATUS_CRIT = {"stopped", "stop", "failed", "failure", "error", "unhealthy",
                "down", "expired", "critical"}
# keys where the boolean meaning is inverted (false is the *good* state)
_STATUS_INVERTED = {"passive_mode_enabled"}


def _status_sev(key, value):
    """Map a config/health value to ok/warn/crit, or None if not a status value.
    Honors inverted keys (e.g. passive_mode_enabled=false is good)."""
    v = str(value).strip().strip('"').lower()
    if not v:
        return None
    if v in _STATUS_POS:
        base = OK
    elif v in _STATUS_CRIT:
        base = CRIT
    elif v in _STATUS_WARN:
        base = WARN
    else:
        return None
    if key in _STATUS_INVERTED and base in (OK, WARN):
        base = WARN if base == OK else OK
    return base


def _status_cell(key, value):
    """Render a value as a colored pill when it carries enabled/disabled/stopped
    semantics, otherwise plain escaped text."""
    sev = _status_sev(key, value)
    if sev:
        return f'<span class="pill {sev}">{esc(value)}</span>'
    return esc(value)


def _capture_now(data):
    """Reference 'now' taken from the capture itself (not the local clock)."""
    srt = ((data.get("mde_xml") or {}).get("general") or {}).get("script_run_time")
    if srt:
        try:
            dt = datetime.fromisoformat(srt)
            return dt.replace(tzinfo=None)
        except ValueError:
            pass
    return datetime.now()


def _expiry_sev(value, asof):
    """Severity for a product-expiration date string like
    'Mar 14, 2027 at 01:44:16 PM': red if expired, orange if <3 months, else green."""
    for fmt in ("%b %d, %Y at %I:%M:%S %p", "%b %d, %Y at %H:%M:%S",
                "%b %d, %Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(str(value).strip(), fmt)
            break
        except (ValueError, AttributeError):
            dt = None
    if dt is None:
        return None
    days = (dt - asof).days
    if days < 0:
        return CRIT
    if days < 90:        # < ~3 months
        return WARN
    return OK


CSS = """
/* accent colors are shared across themes */
:root{--ok:#2ea043;--warn:#d29922;--crit:#f85149;--info:#388bfd;--accent:#58a6ff;}
/* dark = default */
:root,:root[data-theme="dark"]{--bg:#0f1115;--card:#171a21;--fg:#e6e8ec;
--muted:#9aa3af;--border:#262b36;}
/* light when the OS asks for it AND the user hasn't overridden */
@media(prefers-color-scheme:light){:root:not([data-theme]){--bg:#f6f8fa;--card:#fff;
--fg:#1f2328;--muted:#57606a;--border:#d0d7de;}}
/* explicit user choice always wins */
:root[data-theme="light"]{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;
--muted:#57606a;--border:#d0d7de;}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--fg);transition:background .2s,color .2s}
/* fluid width: scales with viewport, capped so it stays readable on huge screens */
.wrap{width:100%;max-width:min(1680px,94vw);margin:0 auto;padding:clamp(16px,3vw,40px)}
.theme-toggle{position:fixed;top:14px;right:14px;z-index:50;width:40px;height:40px;
border-radius:50%;border:1px solid var(--border);background:var(--card);color:var(--fg);
font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;
box-shadow:0 2px 8px rgba(0,0,0,.18);transition:background .2s,border-color .2s}
.theme-toggle:hover{border-color:var(--accent)}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0}
.sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.banner{padding:16px 20px;border-radius:10px;font-weight:600;margin-bottom:20px;border:1px solid var(--border)}
.banner.ok{background:rgba(46,160,67,.12);border-color:var(--ok)}
.banner.warn{background:rgba(210,153,34,.12);border-color:var(--warn)}
.banner.crit{background:rgba(248,81,73,.12);border-color:var(--crit)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px}
.kpi .v{font-size:22px;font-weight:700}.kpi .l{color:var(--muted);font-size:12px}
details{background:var(--card);border:1px solid var(--border);border-radius:10px;margin-bottom:12px;overflow:hidden}
details>summary{cursor:pointer;padding:14px 18px;font-weight:600;list-style:none;display:flex;
justify-content:space-between;align-items:center}
details>summary::-webkit-details-marker{display:none}
details[open]>summary{border-bottom:1px solid var(--border)}
.body{padding:14px 18px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);white-space:nowrap}
th{color:var(--muted);font-weight:600}
.pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
.pill.ok{background:rgba(46,160,67,.18);color:var(--ok)}
.pill.warn{background:rgba(210,153,34,.18);color:var(--warn)}
.pill.crit{background:rgba(248,81,73,.18);color:var(--crit)}
.pill.info{background:rgba(56,139,253,.18);color:var(--info)}
.find{padding:10px 12px;border-left:3px solid var(--border);margin-bottom:8px;background:var(--bg);border-radius:0 8px 8px 0}
.find.ok{border-color:var(--ok)}.find.warn{border-color:var(--warn)}
.find.crit{border-color:var(--crit)}.find.info{border-color:var(--info)}
.find .t{font-weight:600}.find .d{color:var(--muted);font-size:12px;margin-top:2px;white-space:pre-wrap}
.bar{height:8px;background:var(--border);border-radius:4px;overflow:hidden;min-width:80px}
.bar>span{display:block;height:100%;background:var(--accent)}
.muted{color:var(--muted)}code{background:var(--bg);padding:1px 5px;border-radius:4px}
svg{max-width:100%}
.legend{font-size:12px;color:var(--muted);margin-top:6px}
.legend b{font-weight:700}
.heat{display:flex;flex-wrap:wrap;gap:5px}
.heat .cell{flex:1 1 90px;min-width:84px;min-height:58px;border-radius:7px;padding:7px 9px;
color:#0b0d10;overflow:hidden;display:flex;flex-direction:column;justify-content:space-between;
border:1px solid rgba(0,0,0,.15)}
.heat .cell .n{font-size:11px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.heat .cell .m{font-size:13px;font-weight:800}
.heat .cell .s{font-size:10px;opacity:.8}
.heatscale{display:flex;align-items:center;gap:8px;margin-top:10px;font-size:12px;color:var(--muted)}
.heatscale .grad{height:10px;width:180px;border-radius:5px;
background:linear-gradient(90deg,#2ea043,#d29922,#f85149)}
.hero{display:flex;gap:20px;align-items:center;flex-wrap:wrap;background:var(--card);
border:1px solid var(--border);border-radius:12px;padding:18px 22px;margin-bottom:20px}
.hero .gauge{flex:0 0 auto}.hero .htext{flex:1 1 260px;min-width:240px}
.hero .htext .vt{font-size:18px;font-weight:700}.hero .htext .vs{color:var(--muted);font-size:13px}
.rec{border:1px solid var(--border);border-left-width:4px;border-radius:0 10px 10px 0;
background:var(--bg);padding:12px 14px;margin-bottom:12px}
.rec.ok{border-left-color:var(--ok)}.rec.warn{border-left-color:var(--warn)}
.rec.crit{border-left-color:var(--crit)}.rec.info{border-left-color:var(--info)}
.rec .rt{font-weight:700;margin-bottom:4px}.rec .rw{color:var(--muted);font-size:13px;margin-bottom:8px}
.cmd{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border);
border-radius:7px;padding:6px 8px;margin:5px 0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:12px;overflow-x:auto}
.cmd code{background:none;padding:0;white-space:pre;flex:1}
.cmd button{flex:0 0 auto;border:1px solid var(--border);background:var(--bg);color:var(--muted);
border-radius:5px;padding:2px 8px;font-size:11px;cursor:pointer}
.cmd button:hover{border-color:var(--accent);color:var(--accent)}
.evt{padding:8px 10px;border-left:3px solid var(--border);margin-bottom:8px;background:var(--bg);border-radius:0 8px 8px 0}
.evt.crit{border-color:var(--crit)}.evt.warn{border-color:var(--warn)}.evt.info{border-color:var(--info)}
.evt .et{font-weight:600}.evt .em{color:var(--muted);font-size:12px;margin-top:2px}
.evt pre{margin:6px 0 0;font-size:11px;color:var(--muted);white-space:pre-wrap;word-break:break-all}
@media print{.theme-toggle{display:none}details{break-inside:avoid}details>div.body{display:block!important}}
"""


def _pill(sev):
    return f'<span class="pill {sev}">{sev.upper()}</span>'


def _pid_names(data):
    """Build a pid -> process name map from every source that carries one."""
    m = {}
    # rtp_statistics: short authoritative names
    rtp = data.get("rtp")
    if rtp:
        for p in rtp["procs"]:
            if p.get("pid") and p.get("name"):
                m.setdefault(str(p["pid"]), p["name"])
    # process_information: basename of the command / cmdline
    procs = data.get("procs")
    if procs:
        for p in procs["procs"]:
            pid = str(p.get("pid", ""))
            cmd = p.get("command", "")
            if pid and cmd and pid not in m:
                toks = cmd.split()
                name = toks[0].rsplit("/", 1)[-1] if toks else cmd
                # keep the wdavdaemon sub-role visible (unprivileged sandbox / edr)
                if len(toks) > 1 and toks[1] in ("unprivileged", "edr"):
                    name += f" ({toks[1]})"
                m[pid] = name
    # top snapshot fallback
    snap = _top_snapshot(data)
    if snap:
        for p in snap.get("procs", []):
            pid = str(p.get("pid", ""))
            if pid and pid not in m and p.get("command"):
                m[pid] = p["command"]
    return m


def _sparkline(points, key, color, label, unit=""):
    vals = [p[key] for p in points if p.get(key) is not None]
    if len(vals) < 2:
        return ""
    w, h, pad = 900, 90, 6
    vmax = max(vals) or 1
    vmin = min(vals)
    span = (vmax - vmin) or 1
    n = len(vals)
    pts = []
    for i, v in enumerate(vals):
        x = pad + (w - 2 * pad) * i / (n - 1)
        y = h - pad - (h - 2 * pad) * (v - vmin) / span
        pts.append(f"{x:.1f},{y:.1f}")
    poly = " ".join(pts)
    area = f"{pad},{h-pad} " + poly + f" {w-pad},{h-pad}"
    return (
        f'<div class="muted" style="margin:8px 0 2px"><b>{esc(label)}</b> '
        f'— min {vmin:g}{unit}, max {vmax:g}{unit}, last {vals[-1]:g}{unit}</div>'
        f'<svg viewBox="0 0 {w} {h}" preserveAspectRatio="none" style="width:100%;height:{h}px">'
        f'<polygon points="{area}" fill="{color}" opacity="0.12"/>'
        f'<polyline points="{poly}" fill="none" stroke="{color}" stroke-width="2"/>'
        f'</svg>'
    )


def _gauge(score):
    """Semicircular SVG gauge for a 0-100 score."""
    color = "#2ea043" if score >= 80 else "#d29922" if score >= 50 else "#f85149"
    import math
    # semicircle from 180deg (left) to 0deg (right)
    frac = score / 100.0
    ang = math.pi * (1 - frac)
    cx, cy, r = 100, 100, 84
    x = cx + r * math.cos(ang)
    y = cy - r * math.sin(ang)
    large = 0 if frac <= 0.5 else 1
    return (
        f'<svg viewBox="0 0 200 118" width="200" height="118">'
        f'<path d="M16,100 A84,84 0 0 1 184,100" fill="none" stroke="var(--border)" stroke-width="16" stroke-linecap="round"/>'
        f'<path d="M16,100 A84,84 0 {large} 1 {x:.1f},{y:.1f}" fill="none" stroke="{color}" stroke-width="16" stroke-linecap="round"/>'
        f'<text x="100" y="92" text-anchor="middle" font-size="38" font-weight="800" fill="var(--fg)">{score}</text>'
        f'<text x="100" y="112" text-anchor="middle" font-size="12" fill="var(--muted)">health score</text>'
        f'</svg>'
    )


def _cmd_block(cmd):
    return (f'<div class="cmd"><code>{esc(cmd)}</code>'
            f'<button onclick="cp(this)">copy</button></div>')


def _rec_card(card):
    cmds = "".join(_cmd_block(c) for c in card.get("commands", []))
    return (f'<div class="rec {card["severity"]}"><div class="rt">{esc(card["title"])}</div>'
            f'<div class="rw">{esc(card["why"])}</div>{cmds}</div>')


# ---- redaction -------------------------------------------------------------

# guard on hex only (not \b) so ids embedded in tokens like <guid>_cmd_exec still match
_GUID_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])")
_HEX40_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")  # edr_machine_id etc.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_SUBID_RE = re.compile(r"(/subscriptions/)[0-9a-fA-F-]{36}", re.I)
# username in home-directory paths (source path, log paths, etc.)
_HOME_RE = re.compile(r"(/home/|/Users/|\\Users\\)[^/\\<>\s\"']+")


def redact_html(doc):
    """Mask identifiers before external sharing: GUIDs, machine ids, subscription
    ids, IPs, MAC addresses and usernames in home-directory paths."""
    doc = _SUBID_RE.sub(r"\1<redacted>", doc)
    doc = _GUID_RE.sub("<redacted-guid>", doc)
    doc = _HEX40_RE.sub("<redacted-id>", doc)
    doc = _MAC_RE.sub("<redacted-mac>", doc)
    doc = _IPV4_RE.sub("<redacted-ip>", doc)
    doc = _HOME_RE.sub(r"\1<user>", doc)
    return doc


def _heat_color(t):
    """Map t in [0,1] to a green->yellow->red hex color."""
    t = max(0.0, min(1.0, t))
    stops = [(0.0, (46, 160, 67)), (0.5, (210, 153, 34)), (1.0, (248, 81, 73))]
    for i in range(len(stops) - 1):
        t0, c0 = stops[i]
        t1, c1 = stops[i + 1]
        if t <= t1:
            f = (t - t0) / (t1 - t0) if t1 > t0 else 0
            r = int(c0[0] + (c1[0] - c0[0]) * f)
            g = int(c0[1] + (c1[1] - c0[1]) * f)
            b = int(c0[2] + (c1[2] - c0[2]) * f)
            return f"#{r:02x}{g:02x}{b:02x}"
    return "#f85149"


def _heatmap(procs, max_cells=40):
    """Treemap-style heatmap of scanned processes: cell width ~ files scanned,
    color intensity ~ scan time (green=low, red=high)."""
    active = [p for p in procs if p.get("name")]
    if not active:
        return ""
    # hot processes first; cold (0-scan) ones still shown for coverage context
    active.sort(key=lambda p: (p.get("scan_ns", 0), p.get("files", 0)), reverse=True)
    hot = sum(1 for p in active if p.get("scan_ns", 0) > 0)
    active = active[:max_cells]
    max_ns = max((p.get("scan_ns", 0) for p in active), default=1) or 1
    max_files = max((p.get("files", 0) for p in active), default=1) or 1
    cells = []
    for p in active:
        ns = p.get("scan_ns", 0)
        files = p.get("files", 0)
        ms = ns / 1e6
        # perceptual scaling so a single dominant process doesn't wash out the rest
        t = (ns / max_ns) ** 0.5
        grow = 1 + 6 * (files / max_files)      # bigger scanners get wider cells
        color = _heat_color(t)
        cells.append(
            f'<div class="cell" title="{esc(p.get("path",""))}" '
            f'style="background:{color};flex-grow:{grow:.2f}">'
            f'<div class="n">{esc(p.get("name",""))}</div>'
            f'<div class="m">{ms:.1f} ms</div>'
            f'<div class="s">{files} files · pid {esc(p.get("pid",""))}</div>'
            f'</div>'
        )
    scale = (f'<div class="heatscale">low<span class="grad"></span>high '
             f'&nbsp;· cell width ∝ files scanned, color ∝ scan time '
             f'&nbsp;· {hot} of {len(active)} shown processes actively scanned</div>')
    return f'<div class="heat">{"".join(cells)}</div>{scale}'


def _section(title, sev, inner, open_=False):
    # every section renders collapsed by default (open_ kept for call-site intent)
    o = ""
    right = _pill(sev) if sev else ""
    return f'<details{o}><summary><span>{esc(title)}</span>{right}</summary><div class="body">{inner}</div></details>'


def _table(headers, rows):
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    trs = []
    for r in rows:
        tds = "".join(f"<td>{c}</td>" for c in r)
        trs.append(f"<tr>{tds}</tr>")
    return f'<table><thead><tr>{th}</tr></thead><tbody>{"".join(trs)}</tbody></table>'


def render_html(diag_dir, data, findings, max_age_days=None):
    verdict_sev, verdict_txt = overall_verdict(findings)
    h = (data.get("health") or {}).get("values", {})
    inst = data.get("install") or {}
    parts = []

    # header
    hostname = None
    distro = inst.get("distro") or {}
    parts.append('<button id="themeToggle" class="theme-toggle" aria-label="Toggle light/dark theme" title="Toggle theme">\U0001f319</button>')
    parts.append('<div class="wrap">')
    parts.append(f"<h1>MDE Linux Performance Report</h1>")
    gen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    age_note = (f' · <span class="pill info">log events limited to last {max_age_days} day(s)</span>'
                if max_age_days else "")
    age_sfx = f" · last {max_age_days}d" if max_age_days else ""
    parts.append(f'<div class="sub">Source: <code>{esc(os.path.abspath(diag_dir))}</code> · generated {gen}{age_note}</div>')

    # hero: health-score gauge + verdict summary
    counts = {OK: 0, WARN: 0, CRIT: 0, INFO: 0}
    for fnd in findings:
        counts[fnd.severity] = counts.get(fnd.severity, 0) + 1
    score = health_score(findings)
    distro_name = f'{distro.get("name","")} {distro.get("version_id","")}'.strip() or "?"
    parts.append(
        f'<div class="hero"><div class="gauge">{_gauge(score)}</div>'
        f'<div class="htext"><div class="vt">{esc(verdict_txt)}</div>'
        f'<div class="vs">{counts[CRIT]} critical · {counts[WARN]} warnings · '
        f'{counts[OK]+counts[INFO]} ok/info</div>'
        f'<div class="banner {verdict_sev}" style="margin-top:10px;margin-bottom:0">'
        f'Host: <b>{esc(distro_name)}</b> · MDE {esc(h.get("app_version","?"))} · '
        f'RTP {esc(h.get("real_time_protection_subsystem","?"))}</div>'
        f'</div></div>'
    )

    # KPI grid
    kpis = []
    if h.get("app_version"):
        kpis.append(("MDE version", h["app_version"]))
    os_pretty = (data.get("mdediag") or {}).get("os_pretty")
    if os_pretty:
        kpis.append(("Distro", os_pretty))
    elif distro.get("name"):
        kpis.append(("Distro", f'{distro.get("name")} {distro.get("version_id","")}'))
    if distro.get("kernel_version"):
        kpis.append(("Kernel", distro["kernel_version"]))
    wda = _wda_cpu(data)
    if wda is not None:
        kpis.append(("wdavdaemon CPU", f"{wda:.0f}%"))
    if h.get("real_time_protection_subsystem"):
        kpis.append(("RTP subsystem", h["real_time_protection_subsystem"]))
    if h.get("definitions_version"):
        kpis.append(("Definitions", h["definitions_version"]))
    cpu = data.get("cpuinfo") or {}
    if cpu.get("logical_cpus"):
        kpis.append(("Logical CPUs", cpu["logical_cpus"]))
    procd = data.get("procs")
    if procd and procd.get("procs"):
        plist = procd["procs"]
        kpis.append(("Processes", len(plist)))
        # daemons: background services adopted by / launched from init (PPID 1)
        daemons = sum(1 for p in plist if str(p.get("ppid", "")) == "1")
        kpis.append(("Daemons", daemons))
    free = data.get("free") or {}
    if free.get("mem"):
        gb = free["mem"]["total"] / 1024 / 1024
        kpis.append(("RAM", f"{gb:.1f} GiB"))
    if data.get("uptime"):
        um = re.search(r"up\s+(.+?),\s+\d+\s+user", data["uptime"])
        if um:
            kpis.append(("Uptime", um.group(1)))
    parts.append('<div class="grid">')
    for l, v in kpis:
        parts.append(f'<div class="kpi"><div class="v">{esc(v)}</div><div class="l">{esc(l)}</div></div>')
    parts.append("</div>")

    # findings section
    fnd_html = []
    order = sorted(findings, key=lambda x: -SEV_RANK[x.severity])
    for fnd in order:
        d = f'<div class="d">{esc(fnd.detail)}</div>' if fnd.detail else ""
        fnd_html.append(f'<div class="find {fnd.severity}"><div class="t">{esc(fnd.title)}</div>{d}</div>')
    parts.append(_section(f"Findings ({len(findings)})", verdict_sev, "".join(fnd_html) or "<div class='muted'>No findings.</div>", open_=True))

    # recommendations (correlation + remediation)
    cards = recommendations(data, findings)
    if cards:
        rec_sev = max((c["severity"] for c in cards), key=lambda s: SEV_RANK[s])
        inner = ('<div class="muted" style="margin-bottom:10px">Prioritised actions. '
                 'Commands are starting points — replace placeholder paths with your own.</div>'
                 + "".join(_rec_card(c) for c in cards))
        parts.append(_section(f"Recommended actions ({len(cards)})", rec_sev, inner, open_=True))

    # performance charts
    series = data.get("top_series")
    if series and series["points"]:
        pts = series["points"]
        charts = []
        charts.append(_sparkline(pts, "wda_cpu", "#f85149", "wdavdaemon aggregate %CPU", "%"))
        charts.append(_sparkline(pts, "cpu_used", "#58a6ff", "System CPU used", "%"))
        charts.append(_sparkline(pts, "mem_used_pct", "#2ea043", "Memory used", "%"))
        charts.append(_sparkline(pts, "load1", "#d29922", "Load average (1m)"))
        charts.append(f'<div class="legend">{len(pts)} snapshots from <code>top_output.txt</code></div>')
        sev = WARN if (wda and wda >= WDA_CPU_WARN) else OK
        parts.append(_section("Performance over time", sev, "".join(c for c in charts if c), open_=True))

    # top consumers
    top = _top_snapshot(data)
    if top and top.get("procs"):
        rows = []
        for p in sorted(top["procs"], key=lambda x: -x["cpu"])[:15]:
            bar = f'<div class="bar"><span style="width:{min(p["cpu"],100):.0f}%"></span></div>'
            rows.append([esc(p["pid"]), esc(p["user"]), esc(p["command"]),
                         f'{p["cpu"]:.1f}', f'{p["mem"]:.1f}', bar])
        parts.append(_section("Top CPU consumers (snapshot)", None,
                              _table(["PID", "User", "Command", "%CPU", "%MEM", ""], rows)))

    # full system process list (process_information.txt)
    procs = data.get("procs")
    if procs and procs.get("procs"):
        plist = procs["procs"]
        running = sum(1 for p in plist if p.get("stat", "").startswith("R"))
        zombie = sum(1 for p in plist if "Z" in p.get("stat", ""))
        rows = []
        for p in sorted(plist, key=lambda x: -x.get("rss", 0)):
            rss_mb = p.get("rss", 0) / 1024
            rows.append([esc(p["pid"]), esc(p["ppid"]), esc(p["user"]),
                         f'{p.get("cpu",0):.1f}', f'{p.get("mem",0):.1f}',
                         f'{rss_mb:.1f}', esc(p.get("stat", "")), esc(p["command"])])
        summary = (f'<div class="muted" style="margin-bottom:8px">{len(plist)} processes · '
                   f'{running} running · {zombie} zombie</div>')
        zsev = WARN if zombie else OK
        parts.append(_section(f"System processes ({len(plist)})", zsev,
                              summary + _table(["PID", "PPID", "User", "%CPU", "%MEM",
                                                "RSS MB", "STAT", "Command"], rows)))

    # scan hotspots + heatmap
    rtp = data.get("rtp")
    if rtp:
        inner = []
        # heatmap of scan activity
        heat = _heatmap(rtp["procs"])
        if heat:
            inner.append("<h2>Scan activity heatmap</h2>")
            inner.append('<div class="muted" style="margin:2px 0 10px">Per-process scan cost. '
                         'Bigger + redder = more scan time / files.</div>')
            inner.append(heat)
        # top scanned files / initiators from eBPF (if the capture recorded them)
        eb = data.get("ebpf") or {}
        for label, key in (("Top scanned file paths", "top_files"),
                           ("Top initiator paths", "top_initiators")):
            items = eb.get(key) or []
            if items:
                mx = max(i["count"] for i in items) or 1
                rows = []
                for it in sorted(items, key=lambda x: -x["count"])[:20]:
                    bar = (f'<div class="bar"><span style="width:{100*it["count"]/mx:.0f}%;'
                           f'background:{_heat_color((it["count"]/mx)**0.5)}"></span></div>')
                    rows.append([esc(it["path"]), esc(it["count"]), bar])
                inner.append(f'<h2 style="margin-top:16px">{label}</h2>')
                inner.append(_table(["Path", "Count", ""], rows))
        # full per-process table
        rows = []
        for p in sorted(rtp["procs"], key=lambda x: -x.get("scan_ns", 0))[:20]:
            ms = p.get("scan_ns", 0) / 1e6
            sev = "crit" if ms >= SCAN_MS_CRIT else "warn" if ms >= SCAN_MS_WARN else "ok"
            rows.append([esc(p.get("name", "")), esc(p.get("pid", "")),
                         esc(p.get("files", 0)), f'{ms:.1f}',
                         f'<span class="pill {sev}">{sev.upper()}</span>',
                         f'<span class="muted">{esc(p.get("path",""))}</span>'])
        inner.append('<h2 style="margin-top:16px">Per-process scan detail</h2>')
        inner.append(_table(["Process", "PID", "Files", "Scan ms", "", "Path"], rows))
        worst = max((p.get("scan_ns", 0) for p in rtp["procs"]), default=0) / 1e6
        sev = CRIT if worst >= SCAN_MS_CRIT else WARN if worst >= SCAN_MS_WARN else OK
        parts.append(_section("Scan hotspots & heatmap", sev, "".join(inner), open_=True))

    # eBPF / events
    ev = data.get("events")
    ebpf = data.get("ebpf")
    if ev or ebpf:
        inner = []
        worst = 0

        def counter_rows(d):
            nonlocal worst
            rows = []
            for k, v in d.items():
                sev = _neg_sev(k, v)
                if sev:
                    worst = max(worst, SEV_RANK[sev])
                    val = f'<span class="pill {sev}">{esc(v)}</span>'
                    key = f'<span style="color:var(--{sev})">{esc(k)}</span>'
                else:
                    val = esc(v)
                    key = esc(k)
                rows.append([key, val])
            return rows

        if ev:
            inner.append('<h2>Event statistics</h2>'
                         '<div class="muted" style="margin:2px 0 8px">Drop / denied / failed / '
                         'timed-out counters are highlighted when non-zero '
                         f'(orange &gt;0, red &ge;{NEG_EXCESSIVE}).</div>')
            inner.append(_table(["Counter", "Value"], counter_rows(ev)))
        if ebpf:
            c = ebpf.get("counters") or {}
            if c:
                inner.append("<h2 style='margin-top:12px'>eBPF counters</h2>")
                inner.append(_table(["Counter", "Value"], counter_rows(c)))
            ss = ebpf.get("session_syscalls") or {}
            if ss:
                arch = (data.get("uname") or {}).get("arch") or "x86_64"
                rows = []
                for sid, cnt in sorted(ss.items(), key=lambda x: -x[1])[:15]:
                    name = syscall_name(sid, arch)
                    label = esc(name) if name else f'<span class="muted">syscall {esc(sid)}</span>'
                    rows.append([esc(sid), label, esc(cnt)])
                note = (f' <span class="muted">(names for {esc(arch)})</span>' if arch == "x86_64"
                        else f' <span class="pill warn">names unavailable for arch {esc(arch)}</span>')
                inner.append(f"<h2 style='margin-top:12px'>Top session syscalls{note}</h2>")
                inner.append(_table(["Id", "Syscall", "Count"], rows))
        sev = CRIT if worst >= 2 else WARN if worst >= 1 else OK
        parts.append(_section("eBPF / event provider", sev, "".join(inner)))

    # open files (lsof) — system-wide, with MDE detail
    lsof = data.get("lsof")
    if lsof:
        names = _pid_names(data)

        def pname(pid, fallback):
            return names.get(str(pid)) or fallback or "?"

        inner = []
        inner.append(f'<p>System-wide open file descriptors: <b>{lsof.get("system_total_fds",0)}</b> '
                     f'across <b>{lsof.get("proc_count",0)}</b> processes · '
                     f'MDE-owned: <b>{lsof["total_fds"]}</b> '
                     f'<span class="muted">(+{lsof.get("mmap_count",0)} MDE memory-mapped files)</span></p>')

        # top consumers system-wide
        procs = lsof.get("procs") or []
        max_fds = procs[0]["fds"] if procs else 1
        trows = []
        for p in procs[:40]:
            mde_tag = ' <span class="pill info">MDE</span>' if p["cmd"].startswith(_MDATP_CMDS) else ""
            bar = (f'<div class="bar"><span style="width:{100*p["fds"]/max(max_fds,1):.0f}%"></span></div>')
            trows.append([esc(pname(p["pid"], p["cmd"])) + mde_tag, esc(p["pid"]),
                          esc(p["fds"]), bar, esc(p["mmap"]),
                          esc(p["net"]) if p["net"] else "0",
                          esc(p["deleted"]) if p["deleted"] else "0"])
        inner.append("<h2>Top open-file consumers (system-wide)</h2>")
        inner.append(_table(["Process", "PID", "Open FDs", "", "Mmap", "Net", "Deleted"], trows))

        # MDE per-process breakdown
        mde_rows = [[esc(pname(pid, "")), esc(pid), esc(cnt)]
                    for pid, cnt in sorted(lsof["fd_by_pid"].items(), key=lambda x: -x[1])]
        if mde_rows:
            inner.append("<h2 style='margin-top:14px'>MDE processes</h2>")
            inner.append(_table(["Process", "PID", "Open FDs"], mde_rows))

        # network / socket handles (system-wide, MDE flagged)
        net_all = lsof.get("net_all") or []
        if net_all:
            inner.append(f"<h2 style='margin-top:14px'>Network / socket handles "
                         f"<span class='muted'>({len(net_all)} shown)</span></h2>")
            nrows = []
            for x in net_all[:60]:
                tag = ' <span class="pill info">MDE</span>' if x["cmd"].startswith(_MDATP_CMDS) else ""
                nrows.append([esc(pname(x["pid"], x["cmd"])) + tag, esc(x["pid"]),
                              esc(x["type"]), esc(x["name"])])
            inner.append(_table(["Process", "PID", "Type", "Name"], nrows))

        # deleted-but-open (system-wide)
        del_all = lsof.get("deleted_all") or []
        if del_all:
            inner.append(f'<p class="muted" style="margin-top:12px">Deleted-but-open files: '
                         f'{len(del_all)} (MDE-owned: {lsof["deleted_count"]}).</p>')

        sev = WARN if (lsof["total_fds"] >= FD_WARN or lsof["net_count"] or lsof["deleted_count"] > 20) else OK
        parts.append(_section("Open files (lsof, system-wide)", sev, "".join(inner)))

    # device summary (mde.xml)
    mx = data.get("mde_xml")
    if mx and mx.get("device"):
        dev = mx["device"]
        rows = []
        proc_keys = ("edr_process_status", "av_process_status", "telemetry_process_status")
        worst = 0
        for k, item in dev.items():
            val, label = item["value"], item["label"]
            # conflicting agents: red when any present, green when none
            if k in ("conflicting_agents", "conflicting_applications"):
                empty = str(val).strip().strip('"') in ("", "[]", "{}", "none", "null")
                if not empty:
                    worst = max(worst, SEV_RANK[CRIT])
                cell = f'<span class="pill {"ok" if empty else "crit"}">{esc(val) if val else "none"}</span>'
            elif not val:
                cell = '<span class="muted">—</span>'
            elif k in proc_keys:
                good = val.lower() in ("running", "active", "up")
                psev = "ok" if good else ("warn" if k == "telemetry_process_status" else "crit")
                if not good:
                    worst = max(worst, SEV_RANK[psev])
                cell = f'<span class="pill {psev}">{esc(val)}</span>'
            else:
                cell = _status_cell(k, val)
            rows.append([esc(label), cell])
        inner = _table(["Property", "Value"], rows)
        if mx.get("events"):
            inner += ('<h2 style="margin-top:12px">Reported event ids</h2>'
                      '<div class="muted">' + ", ".join(esc(e) for e in mx["events"]) + "</div>")
        if mx.get("general"):
            g = mx["general"]
            inner += (f'<p class="muted" style="margin-top:10px">Analyzer {esc(g.get("script_version","?"))} · '
                      f'run {esc(g.get("script_run_time","?"))}</p>')
        sev = CRIT if worst >= 2 else WARN if worst >= 1 else OK
        parts.append(_section("Device summary (mde.xml)", sev, inner, open_=(worst >= 1)))

    # health detail
    if h:
        rows = []
        managed = (data.get("health") or {}).get("managed", {})
        try:
            def_mins = int(h.get("definitions_updated_minutes_ago", "")) if \
                h.get("definitions_updated_minutes_ago", "").isdigit() else None
        except (ValueError, AttributeError):
            def_mins = None
        asof = _capture_now(data)
        for k, v in h.items():
            m = ' <span class="pill info">managed</span>' if managed.get(k) else ""
            if k == "health_issues":
                # any reported health issue is critical; empty ([]) is good
                empty = str(v).strip().strip('"') in ("", "[]", "{}", "null", "none")
                cell = f'<span class="pill {"ok" if empty else "crit"}">{esc(v)}</span>'
            elif k == "healthy":
                cell = f'<span class="pill {"ok" if str(v).lower() == "true" else "crit"}">{esc(v)}</span>'
            # licence expiry: green if >3 months out, orange if sooner, red if expired
            elif k == "product_expiration":
                esev = _expiry_sev(v, asof)
                cell = f'<span class="pill {esev}">{esc(v)}</span>' if esev else _status_cell(k, v)
            # definitions freshness: green if updated < 1 day ago, else orange
            elif k in ("definitions_updated", "definitions_updated_minutes_ago") and def_mins is not None:
                fresh = "ok" if def_mins < 1440 else "warn"
                cell = f'<span class="pill {fresh}">{esc(v)}</span>'
            else:
                cell = _status_cell(k, v)
            rows.append([esc(k), cell + m])
        parts.append(_section("MDE health (full)", None, _table(["Key", "Value"], rows)))

    # connectivity
    conn = inst.get("connectivitytest") or {}
    if conn:
        rows = []
        for u, r in conn.items():
            ok = "[OK]" in r
            pill = '<span class="pill ok">OK</span>' if ok else '<span class="pill warn">FAIL</span>'
            rows.append([esc(u), pill])
        failed = sum(1 for r in conn.values() if "[OK]" not in r)
        parts.append(_section(f"Connectivity ({len(conn)} endpoints, {failed} failed)",
                              WARN if failed else OK, _table(["Endpoint", "Status"], rows)))

    # mdatp service status (systemd)
    svc = data.get("service")
    if svc:
        srows = []
        def _svc_row(label, val, sev=None):
            if val in (None, ""):
                return
            cell = f'<span class="pill {sev}">{esc(val)}</span>' if sev else esc(val)
            srows.append([label, cell])
        _svc_row("Active", svc.get("active_state"),
                 "ok" if svc.get("active") else "crit")
        _svc_row("Enabled at boot", svc.get("loaded"),
                 "ok" if svc.get("loaded") == "enabled" else "warn")
        if svc.get("since"):
            _svc_row("Since", svc["since"] + (f' ({svc["ago"]})' if svc.get("ago") else ""))
        _svc_row("Main PID", svc.get("main_pid"))
        _svc_row("Tasks", (f'{svc["tasks"]} / {svc["tasks_limit"]}'
                           if svc.get("tasks_limit") else svc.get("tasks")))
        _svc_row("CPU time", svc.get("cpu"))
        mem = svc.get("mem_current")
        if mem:
            extra = []
            if svc.get("mem_peak"):
                extra.append(f'peak {svc["mem_peak"]}')
            if svc.get("mem_swap"):
                extra.append(f'swap {svc["mem_swap"]}')
            if svc.get("mem_swap_peak"):
                extra.append(f'swap peak {svc["mem_swap_peak"]}')
            _svc_row("Memory", mem + (f' ({", ".join(extra)})' if extra else ""))
        if svc.get("timed_out"):
            _svc_row("Status query", "timed out", "warn")
        if srows:
            ssev = OK if svc.get("active") else CRIT
            parts.append(_section("mdatp service status (systemd)", ssev,
                                  _table(["Field", "Value"], srows)))

    # threats (mdatp threat list)
    thr = data.get("threats")
    if thr:
        if thr.get("none"):
            inner = '<p><span class="pill ok">clean</span> No threats listed.</p>'
            parts.append(_section("Threats (mdatp threat list)", OK, inner))
        else:
            trows = []
            for t in thr["threats"]:
                name = t.get("Name") or t.get("Threat") or t.get("name") or "?"
                trows.append([esc(name),
                              esc(t.get("Status", "")),
                              esc(t.get("Id") or t.get("ID") or "")])
            parts.append(_section(f"Threats (mdatp threat list) — {len(thr['threats'])}",
                                  CRIT, _table(["Name", "Status", "Id"], trows)))

    # kernel tunables relevant to MDE (sysctl)
    sc = data.get("sysctl")
    if sc and sc.get("values"):
        crows = [[esc(k), esc(v)] for k, v in sc["values"].items()]
        parts.append(_section(f"Kernel tunables (sysctl) — {len(crows)} relevant",
                              None, _table(["Key", "Value"], crows)))

    # config / exclusions / conflicts
    misc = []
    exc = data.get("exclusions")
    if exc:
        if exc["none"] or not exc.get("items"):
            misc.append('<p><b>Exclusions:</b> none configured</p>')
        else:
            rows = []
            for it in exc["items"]:
                name = next((it[k] for k in ("Process name", "Path", "Name",
                                             "File name", "Extension") if it.get(k)), "")
                scope = it.get("Scope")
                scope_s = ", ".join(scope) if isinstance(scope, list) else str(scope or "")
                rows.append([esc(it.get("kind", "")), esc(name), esc(scope_s)])
            misc.append(f'<p><b>Exclusions ({len(exc["items"])} configured):</b></p>')
            misc.append(_table(["Type", "Name / path", "Scope"], rows))
    conf = data.get("conflicts")
    if conf:
        misc.append(f'<p><b>Conflicting processes:</b> {esc(conf["raw"])}</p>')
    feats = data.get("features")
    if feats:
        rows = [[esc(k), _status_cell(k, v)] for k, v in feats.items()]
        misc.append(_table(["Feature", "State"], rows))
    # managed attach config from mde_diagnostic.zip
    md = data.get("mdediag") or {}
    if md.get("managed"):
        def flat(d, prefix=""):
            out = []
            for k, v in d.items():
                if isinstance(v, dict):
                    out += flat(v, f"{prefix}{k}.")
                else:
                    out.append([esc(prefix + k), _status_cell(k, v)])
            return out
        misc.append('<h2 style="margin-top:12px">Managed attach config '
                    '<span class="muted">(mdeattach_managed.json)</span></h2>')
        misc.append(_table(["Setting", "Value"], flat(md["managed"])))
    if misc:
        parts.append(_section("Config, exclusions & features", None, "".join(misc)))

    # general system information
    sysinfo = []
    dev = (data.get("mde_xml") or {}).get("device", {})
    rows = []
    def _dev(k):
        return dev.get(k, {}).get("value", "")
    for label, val in (
        ("Hostname", _dev("host_name") or _dev("device_name")),
        ("OS", (data.get("mdediag") or {}).get("os_pretty") or _dev("os_name")),
        ("Kernel", _dev("os_kernel_version") or (data.get("install") or {}).get("distro", {}).get("kernel_version", "")),
        ("Architecture", (data.get("uname") or {}).get("arch") or _dev("architecture")),
        ("CPU", (data.get("cpuinfo") or {}).get("model", "")),
        ("Logical CPUs", (data.get("cpuinfo") or {}).get("logical_cpus", "")),
        ("Uptime", (re.search(r"up\s+(.+?),\s+\d+\s+user", data.get("uptime") or "") or [None, ""])[1]
                    if data.get("uptime") else ""),
    ):
        if val:
            rows.append([label, esc(val)])
    se = data.get("sestatus")
    if se:
        rows.append(["SELinux", _status_cell("selinux", se["status"]) if se.get("available") else esc(se["status"])])
    if rows:
        sysinfo.append(_table(["Property", "Value"], rows))

    # network interfaces
    ni = data.get("netifaces")
    if ni:
        nrows = []
        for i in ni["ifaces"]:
            up = "UP" in i["flags"] or i["state"].upper() == "UP"
            state = f'<span class="pill {"ok" if up else "warn"}">{esc(i["state"])}</span>'
            nrows.append([esc(i["name"]), state, esc(i["mtu"]), esc(i["mac"] or "—"),
                          esc(", ".join(i["addrs"]) or "—")])
        sysinfo.append("<h2 style='margin-top:14px'>Network interfaces</h2>")
        sysinfo.append(_table(["Interface", "State", "MTU", "MAC", "Addresses"], nrows))

    # counts: modules / namespaces / mounts / boots
    chips = []
    lm = data.get("lsmod")
    if lm:
        chips.append(f'{lm["count"]} kernel modules')
    ns = data.get("lsns")
    if ns:
        chips.append(f'{ns["count"]} namespaces (' +
                     ", ".join(f'{t}:{n}' for t, n in sorted(ns["by_type"].items())) + ")")
    mt = data.get("mounts")
    if mt:
        top_types = ", ".join(f'{t}:{n}' for t, n in sorted(mt["by_type"].items(), key=lambda x: -x[1])[:5])
        chips.append(f'{mt["count"]} mounts ({top_types})')
    lb = data.get("last")
    if lb:
        chips.append(f'{lb["boot_count"]} boots recorded')
        if lb.get("login_count"):
            chips.append(f'{lb["login_count"]} logins recorded'
                         + (f' ({lb["active_sessions"]} active)' if lb.get("active_sessions") else ""))
    if chips:
        sysinfo.append('<h2 style="margin-top:14px">System summary</h2>')
        sysinfo.append('<ul>' + "".join(f'<li>{esc(c)}</li>' for c in chips) + '</ul>')

    # boot / login history
    if lb and lb.get("recent"):
        sysinfo.append('<h2 style="margin-top:14px">Recent boots</h2>')
        sysinfo.append("".join(f'<div class="cmd"><code>{esc(b)}</code></div>' for b in lb["recent"]))

    if sysinfo:
        parts.append(_section("System information", None, "".join(sysinfo)))

    # last logins (from last_info.txt)
    if lb and lb.get("logins"):
        lrows = []
        for l in lb["logins"][:25]:
            status = (f'<span class="pill ok">{esc(l["status"])}</span>'
                      if l["active"] else esc(l["status"] or "—"))
            lrows.append([esc(l["user"]), esc(l["tty"]), esc(l["host"]),
                          esc(l["at"]), status])
        parts.append(_section(
            f"Last logins — {lb['login_count']}"
            + (f" ({lb['active_sessions']} active)" if lb.get("active_sessions") else ""),
            None, _table(["User", "TTY", "From", "When", "Status"], lrows)))

    # management policy application (Intune/MDM)
    ps = md.get("policy_settings") or []
    if ps or md.get("policy_count"):
        # flatten managed config to dotted keys so we can show the enforced value
        enforced = {}

        def _flatten(d, prefix=""):
            for k, v in d.items():
                if isinstance(v, dict):
                    _flatten(v, f"{prefix}{k}.")
                else:
                    enforced[f"{prefix}{k}"] = v
        if md.get("managed"):
            _flatten(md["managed"])

        rows = []
        nfail = 0
        for p in ps:
            ok = p["value"].lower() in ("success", "applied", "")
            if not ok:
                nfail += 1
            result = f'<span class="pill {"ok" if ok else "warn"}">{esc(p["value"])}</span>'
            # setting name is like "Linux:None:antivirusEngine.behaviorMonitoring"
            path = p["name"].split(":", 2)[-1]
            short = path.split(".", 1)[-1] if "." in path else path
            val = enforced.get(path)
            value_cell = _status_cell(short, val) if val is not None else '<span class="muted">—</span>'
            rows.append([esc(path), value_cell, result])
        inner = (f'<div class="muted" style="margin-bottom:8px">{md.get("policy_count",0)} signed '
                 f'policy bundle(s); {len(ps)} applied setting(s). '
                 f'Enforced value is the effective managed configuration '
                 f'(<code>mdeattach_managed.json</code>).</div>')
        if rows:
            inner += _table(["Setting", "Enforced value", "Apply result"], rows)
        parts.append(_section(f"Management policy (security_management)",
                              WARN if nfail else OK, inner))

    # scan history (wdavhistory)
    scans = md.get("scans") or []
    if scans:
        total_files = sum(s["files"] for s in scans)
        by_type = {}
        for s in scans:
            by_type[s["type"]] = by_type.get(s["type"], 0) + 1
        failed = [s for s in scans if s["state"].lower() not in ("succeeded", "completed")]
        threats = [s for s in scans if s["threats"]]
        summary = (f'<div class="muted" style="margin-bottom:8px">{len(scans)} scans · '
                   f'{total_files} files scanned · '
                   f'{", ".join(f"{t}: {n}" for t, n in sorted(by_type.items()))} · '
                   f'{len(failed)} failed · {len(threats)} with threats</div>')
        rows = []
        for s in sorted(scans, key=lambda x: x["end"] or 0, reverse=True)[:30]:
            # a scan that found a threat is critical, even if its state is "succeeded"
            if s["threats"]:
                st = "crit"
            elif s["state"].lower() in ("succeeded", "completed"):
                st = "ok"
            else:
                st = "warn"
            dur = f'{s["duration"]:.1f}s' if s["duration"] is not None else "?"
            thr = (f'<span class="pill crit">{len(s["threats"])}</span>' if s["threats"] else "0")
            rows.append([esc(_fmt_ts(s["end"])), esc(s["type"]),
                         "scheduled" if s["scheduled"] else "on-demand",
                         esc(s["files"]), dur,
                         f'<span class="pill {st}">{esc(s["state"])}</span>', thr])
        table = _table(["Finished", "Type", "Trigger", "Files", "Duration", "State", "Threats"], rows)
        sev = CRIT if threats else WARN if failed else OK
        parts.append(_section(f"Scan history (wdavhistory) — {len(scans)} scans",
                              sev, summary + table, open_=(sev != OK)))

    # historical events from log archives
    la = data.get("logarch")
    if la and la.get("categories"):
        inner = [f'<div class="muted" style="margin-bottom:8px">Scanned: '
                 f'{", ".join(esc(z) for z in la["scanned"])}</div>']
        cats = sorted(la["categories"].items(), key=lambda kv: -SEV_RANK[kv[1]["severity"]])
        for cat, e in cats:
            span = ""
            if e["first"] and e["last"]:
                span = (f'first {esc(e["first"])} · last {esc(e["last"])}'
                        if e["first"] != e["last"] else esc(e["first"]))
            samples = "".join(f"<pre>{esc(s)}</pre>" for s in e["sample"][:3])
            inner.append(
                f'<div class="evt {e["severity"]}"><div class="et">{_pill(e["severity"])} '
                f'{esc(e["label"])} — {e["count"]}×</div>'
                f'<div class="em">{span}</div>{samples}</div>'
            )
        worst = max((SEV_RANK[e["severity"]] for e in la["categories"].values()), default=0)
        sev = CRIT if worst >= 2 else WARN if worst >= 1 else OK
        parts.append(_section(f"Historical events (syslog / kernel / MDC){age_sfx}", sev, "".join(inner),
                              open_=(worst >= 2)))
    elif la:
        parts.append(_section(f"Historical events (syslog / kernel / MDC){age_sfx}", OK,
                              f'<div class="muted">No notable events in: '
                              f'{", ".join(esc(z) for z in la["scanned"])}</div>'))

    # MDE product logs (from mde_diagnostic.zip)
    md = data.get("mdediag")
    if md and (md.get("logs") or md.get("counters")):
        inner = []
        total_err = md.get("total_errors", 0)
        inner.append(f'<div class="muted" style="margin-bottom:8px">Extracted from '
                     f'<code>mde_diagnostic.zip</code> · {total_err} error-level log lines total.</div>')

        # per-file error/warning summary
        if md.get("logs"):
            rows = []
            for lg in md["logs"]:
                esev = "crit" if lg["errors"] >= NEG_EXCESSIVE else "warn" if lg["errors"] else "ok"
                ecell = (f'<span class="pill {esev}">{lg["errors"]}</span>' if lg["errors"] else "0")
                span = f'{esc(lg["first"] or "?")} → {esc(lg["last"] or "?")}'
                rows.append([esc(lg["file"]), f'{lg["size"]//1024} KB', ecell,
                             esc(lg["warns"]), f'<span class="muted">{span}</span>'])
            inner.append("<h2>Product log files</h2>")
            inner.append(_table(["Log file", "Size", "Errors", "Warns", "Time span"], rows))

        # top recurring errors (grouped by signature)
        te = md.get("top_errors") or []
        if te:
            inner.append("<h2 style='margin-top:14px'>Top recurring errors</h2>")
            for e in te[:10]:
                esev = "crit" if e["count"] >= NEG_EXCESSIVE else "warn"
                last = e.get("last") or ""
                lastnote = f' · last {esc(last)}' if last else ""
                inner.append(
                    f'<div class="evt {esev}"><div class="et">{_pill(esev)} {e["count"]}× '
                    f'<span class="muted">{esc(e["sig"])}{lastnote}</span></div>'
                    f'<pre>{esc(e["example"])}</pre></div>'
                )

        # event-provider dropped counters (structured JSON)
        c = md.get("counters") or {}
        drop_rows = []
        for k, v in c.items():
            if not isinstance(v, (str, int)):
                continue
            try:
                iv = int(v)
            except (ValueError, TypeError):
                continue
            if "dropped" in k.lower() or "drop" in k.lower():
                sev = _neg_sev(k, iv) if iv else None
                cell = f'<span class="pill {sev}">{iv}</span>' if sev else str(iv)
                drop_rows.append([esc(k), cell])
        if drop_rows:
            inner.append("<h2 style='margin-top:14px'>Event-provider dropped messages</h2>")
            inner.append(_table(["Counter", "Value"], drop_rows))

        # crash upload state
        cs = md.get("crash_state")
        if cs is not None:
            uc = cs.get("uploadCount", 0)
            inner.append(f'<p style="margin-top:12px"><b>Crash upload state:</b> '
                         f'uploadCount={esc(uc)}'
                         + (' <span class="pill warn">pending</span>' if str(uc) not in ("0", "None") else '')
                         + '</p>')

        worst = max((SEV_RANK["crit"] if lg["errors"] >= NEG_EXCESSIVE else
                     SEV_RANK["warn"] if lg["errors"] else 0) for lg in md["logs"]) if md.get("logs") else 0
        sev = CRIT if worst >= 2 else WARN if worst >= 1 else OK
        parts.append(_section(f"MDE product logs (mde_diagnostic.zip){age_sfx}", sev, "".join(inner)))

    # analyzer log
    log = data.get("log")
    if log and (log.get("errors") or log.get("warnings")):
        inner = []
        if log.get("version"):
            inner.append(f'<p class="muted">Analyzer version {esc(log["version"])}</p>')
        for e in log.get("errors", [])[:40]:
            inner.append(f'<div class="find warn"><div class="d">{esc(e)}</div></div>')
        parts.append(_section(f"Analyzer collection log ({len(log.get('errors',[]))} errors)", INFO, "".join(inner)))

    parts.append('<div class="sub" style="margin-top:24px">Generated by mde_perf_report.py · stdlib only</div>')
    parts.append("</div>")

    return f"<style>{CSS}</style>" + "".join(parts) + f"<script>{THEME_JS}</script>"


# theme toggle: persist choice in localStorage, fall back to OS preference
THEME_JS = """
(function(){
  var root=document.documentElement, btn=document.getElementById('themeToggle');
  var SUN='\\u2600\\ufe0f', MOON='\\u{1f319}';
  function apply(t){
    if(t==='light'||t==='dark'){root.setAttribute('data-theme',t);}
    else{root.removeAttribute('data-theme');}
    var dark = t==='dark' || (!t && matchMedia('(prefers-color-scheme:dark)').matches);
    btn.textContent = dark ? SUN : MOON;
  }
  var saved=null;
  try{saved=localStorage.getItem('mdeReportTheme');}catch(e){}
  apply(saved);
  btn.addEventListener('click',function(){
    var cur=root.getAttribute('data-theme');
    if(!cur){cur = matchMedia('(prefers-color-scheme:dark)').matches ? 'dark':'light';}
    var next = cur==='dark' ? 'light':'dark';
    apply(next);
    try{localStorage.setItem('mdeReportTheme',next);}catch(e){}
  });
})();
function cp(b){
  var t=b.previousElementSibling.textContent;
  navigator.clipboard.writeText(t).then(function(){
    var o=b.textContent; b.textContent='copied'; setTimeout(function(){b.textContent=o;},1200);
  }).catch(function(){});
}
"""


# ---------------------------------------------------------------------------
# Input resolution — accept a diag directory OR the analyzer output .zip
# ---------------------------------------------------------------------------

# Files that mark a directory as MDE Client Analyzer output. Presence of any of
# these is enough to treat a folder as (or as containing) the diag directory —
# this is also how an already-extracted bundle is recognized so it is not
# re-extracted.
MARKER_FILES = (
    "health.txt", "mde.xml", "installation_report.json",
    "health_details_features.txt", "process_information.txt",
    "mde_diagnostic.zip", "log.txt",
)


def _find_diag_dir(root):
    """Return the directory under `root` (root itself or a nested subdir) that
    holds the most analyzer marker files, or None if none is found."""
    best = None
    best_score = 0
    for cur, _dirs, files in os.walk(root):
        fset = set(files)
        score = sum(1 for m in MARKER_FILES if m in fset)
        if score > best_score:           # strict '>' keeps the shallowest tie
            best_score, best = score, cur
    return best if best_score else None


def resolve_diag_dir(input_path):
    """Resolve the analyzer output directory from a folder or .zip path.

    * A directory is searched for the marker files (top level or one nesting
      level deep); if none match it is used as-is (tolerant — parsers skip
      whatever is missing).
    * A .zip is extracted to a sibling folder named after the zip (minus the
      .zip suffix). If that folder already exists and looks extracted, it is
      reused rather than re-extracted.

    Returns the directory path, or None if the input is neither.
    """
    if os.path.isdir(input_path):
        return _find_diag_dir(input_path) or input_path

    if os.path.isfile(input_path) and zipfile.is_zipfile(input_path):
        root, _ext = os.path.splitext(input_path)
        dest = root  # sibling folder, e.g. foo_output.zip -> foo_output/
        if os.path.isdir(dest):
            existing = _find_diag_dir(dest)
            if existing:
                print(f"reusing extracted bundle: {dest}", file=sys.stderr)
                return existing
        os.makedirs(dest, exist_ok=True)
        print(f"extracting {input_path} -> {dest}", file=sys.stderr)
        with zipfile.ZipFile(input_path) as zf:
            zf.extractall(dest)          # nested *.zip members stay zipped (as parsers expect)
        return _find_diag_dir(dest) or dest

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MDE Linux performance report generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Generate the analyzer bundle first (on the affected Linux host):\n"
            "  cd /opt/microsoft/mdatp/tools/client_analyzer/binary/\n"
            "  sudo ./MDESupportTool -d\n"
            "The results are written to /tmp by default (a *_output.zip).\n\n"
            "Docs on running the client analyzer:\n"
            "  Windows:       https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-windows\n"
            "  macOS & Linux: https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-macos\n"
            "  Overview:      https://learn.microsoft.com/en-us/defender-endpoint/overview-client-analyzer\n"
        ))
    ap.add_argument("input", help="MDE Client Analyzer output directory or .zip bundle")
    ap.add_argument("-o", "--output", default=None, help="Output HTML path (default: <diag_dir>/mde_perf_report.html)")
    ap.add_argument("--redact", action="store_true",
                    help="Mask GUIDs, machine ids, subscription ids and IPs (for external sharing)")
    ap.add_argument("--max-age-days", type=int, default=None, metavar="N",
                    help="Exclude log events older than N days (relative to capture time). "
                         "Applies to syslog/kernel/MDC archives and MDE product logs.")
    args = ap.parse_args(argv)

    if args.max_age_days is not None and args.max_age_days < 0:
        print("error: --max-age-days must be >= 0", file=sys.stderr)
        return 2

    if not os.path.exists(args.input):
        print(f"error: no such file or directory: {args.input}", file=sys.stderr)
        return 2

    diag_dir = resolve_diag_dir(args.input)
    if not diag_dir or not os.path.isdir(diag_dir):
        print(f"error: not a diag directory or analyzer .zip: {args.input}", file=sys.stderr)
        return 2

    data = parse_all(diag_dir, max_age_days=args.max_age_days)
    findings = analyze(data)
    doc = render_html(diag_dir, data, findings, max_age_days=args.max_age_days)
    if args.redact:
        doc = redact_html(doc)

    # name the report after the input so it is obvious which bundle it belongs to,
    # and write it to the current working directory (not inside the extracted folder).
    # When an age filter is active, tag the filename so filtered/full reports don't clash.
    base = os.path.splitext(os.path.basename(os.path.normpath(args.input)))[0]
    age_tag = f"_last{args.max_age_days}d" if args.max_age_days else ""
    out = args.output or f"{base}_mde_perf_report{age_tag}.html"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><meta charset='utf-8'><title>MDE Linux Performance Report</title>")
        fh.write(doc)

    sev, txt = overall_verdict(findings)
    parsed_n = sum(1 for v in data.values() if v)
    print(f"parsed {parsed_n}/{len(data)} sources · {len(findings)} findings · "
          f"score {health_score(findings)}/100 · verdict: {sev.upper()} ({txt})"
          + (f"  [log events ≤{args.max_age_days}d]" if args.max_age_days else "")
          + ("  [redacted]" if args.redact else ""))
    print(f"report written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
