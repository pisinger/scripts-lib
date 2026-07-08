# MDE Linux Performance Report Generator

`mde_perf_report.py` turns the output of the **Microsoft Defender for Endpoint
(MDE) Client Analyzer** (`XMDEClientAnalyzer` / `MDESupportTool`) into a single,
self-contained HTML report focused on **performance diagnostics and
troubleshooting** on Linux endpoints.

## 1. Collect the diagnostics (on the affected Linux host)

Run the MDE Client Analyzer to produce the diagnostic bundle:

```bash
cd /opt/microsoft/mdatp/tools/client_analyzer/binary/
sudo ./MDESupportTool -d
```

- `-d` collects the **performance / diagnostic** data set.
- **By default the results are written to `/tmp`** — the tool prints the path of
  the produced archive when it finishes (a `*_output.zip`, e.g.
  `/tmp/mde_diagnostic_<timestamp>.zip`). Copy that `.zip` to wherever you run
  this script.

> If `MDESupportTool` is missing, install/refresh the analyzer per the Microsoft
> docs — it ships under `/opt/microsoft/mdatp/tools/client_analyzer/`.

**Official documentation — how to run the client analyzer:**

- Windows: <https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-windows>
- Linux: <https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-linux>
- macOS: <https://learn.microsoft.com/en-us/defender-endpoint/run-analyzer-macos>
- Overview / requirements: <https://learn.microsoft.com/en-us/defender-endpoint/overview-client-analyzer>

## 2. Generate the report

```bash
python3 mde_perf_report.py <input> [-o report.html] [--max-age-days N] [--redact]
```

`<input>` may be **either** the analyzer output **`.zip`** **or** an
**already-extracted folder**:

```bash
# straight from the analyzer zip (extracted automatically)
python3 mde_perf_report.py 08_07_2026_07_08_21_output.zip

# or from an already-extracted folder
python3 mde_perf_report.py 08_07_2026_07_08_21_output/
```

- A `.zip` is extracted to a **sibling folder** (same name, minus `.zip`). On
  later runs that folder is detected and **reused** instead of re-extracting.
- The report is written to the **current working directory**, named after the
  input, e.g. `08_07_2026_07_08_21_output_mde_perf_report.html`.

### Options

| Option | Description |
|--------|-------------|
| `input` | Analyzer output **directory** or **`.zip`** bundle (required). |
| `-o`, `--output PATH` | Write the HTML to a specific path instead of the auto-generated name. |
| `--max-age-days N` | Exclude log events older than **N days** (relative to the capture time) from the syslog/kernel/MDC archives and the MDE product logs. |
| `--redact` | Mask GUIDs, machine ids, subscription ids, IPs, MAC addresses and usernames (in home-directory paths) before sharing the report externally (e.g. with Microsoft support). |

**Age filter & file naming.** `--max-age-days` filters at generation time. The
reference "now" is the **capture time** (from `mde.xml`), not your local clock —
so `--max-age-days 7` means "the 7 days before the bundle was collected". When
the filter is active the output filename gets a suffix so filtered and full
reports never clash:

```bash
python3 mde_perf_report.py bundle.zip                    # ..._mde_perf_report.html
python3 mde_perf_report.py bundle.zip --max-age-days 7   # ..._mde_perf_report_last7d.html
python3 mde_perf_report.py bundle.zip --redact -o report_for_support.html
```

Open the resulting `.html` in any browser. It is fully self-contained (inline
CSS + inline SVG charts), so it can be emailed or archived as one file. Sections
are **collapsed by default** — click a header to expand.

## Requirements

- **Python 3.7+** — that is the only prerequisite.
- **No additional Python packages required.** The script uses the standard
  library only (`argparse`, `gzip`, `html`, `json`, `os`, `re`, `sys`,
  `zipfile`, `xml.etree.ElementTree`, `datetime`, `collections`). No
  `pip install`, no virtualenv, no `requirements.txt`.

## What it reports

| Section | Source file(s) | Signal |
|---|---|---|
| Health-score gauge + verdict | (all) | Weighted 0–100 posture score, OK/WARN/CRIT roll-up |
| Findings | (all) | Severity-ranked list with explanations |
| **Recommended actions** | (correlated) | Root-cause cards + concrete `mdatp`/`systemctl` fix commands with copy buttons |
| KPIs | `health.txt`, `installation_report.json`, `cpuinfo.txt`, `memory.txt`, `os-release` | Version, distro, kernel, RTP subsystem, CPUs, RAM, uptime |
| **Device summary** | `mde.xml` | Device/OS identity, engine & signature versions, EDR/AV/telemetry **process statuses**, reported event ids |
| **Management policy** | `mde_diagnostic.zip` → `security_management/`, `mdeattach_managed.json` | Intune/MDM policy apply results (Success/Error), managed AV & cloud config |
| **Scan history** | `mde_diagnostic.zip` → `wdavhistory` | Every recorded scan: time, type, trigger, files, duration, state, threats |
| Performance over time | `top_output.txt` | Time-series SVG charts: wdavdaemon %CPU, system CPU, memory, load |
| Top CPU consumers | `top_output.txt` (last snapshot) | Highest-CPU processes |
| **System processes** | `process_information.txt` | Full process list (PID/PPID/user/CPU/MEM/RSS/state/command); running & zombie counts |
| **System information** | `network_info.txt`, `lsmod.txt`, `lsns_info.txt`, `mount.txt`, `sestatus.txt`, `mde.xml` | Host/OS/kernel/CPU, network interfaces, kernel-module / namespace / mount counts, SELinux status |
| **Last logins & boots** | `last_info.txt` | Parsed `last` output — user logins (user/TTY/from/when, active sessions) and reboot history |
| **mdatp service status** | `service_status.txt` | systemd status: active/enabled-at-boot, since/uptime, Main PID, tasks, CPU time, memory (current/peak/swap) |
| **Kernel tunables (sysctl)** | `sysctl_info.txt` | Curated MDE-relevant tunables (fanotify/inotify/epoll, file-max, pid_max, bpf, perf_event…) |
| **Threats** | `threat_list.txt` | `mdatp threat list` — clean, or a table of active threats |
| Scan hotspots + heatmap | `rtp_statistics.txt`, `mde_ebpf_statistics.txt` | Treemap heatmap (width ∝ files, color ∝ scan time), top files/initiators |
| eBPF / event provider | `mde_event_statistics.txt`, `mde_ebpf_statistics.txt` | Event/syscall counts, dropped/queued events |
| Open files (lsof, scoped) | `lsof.txt` | MDE-owned open FDs (thread-deduped), network handles, deleted files |
| MDE health (full) | `health.txt` | All health keys, managed flags |
| Connectivity | `installation_report.json` | Per-endpoint reachability |
| Config / exclusions / features | `exclusions.txt`, `conflicting_processes_information.txt`, `health_details_features.txt` | Config posture; exclusions parsed into a Type / Name / Scope table |
| **Historical events** | `syslogs.zip`, `kernel_logs.zip`, `mdc_log.zip` | wdavdaemon crashes, OOM kills, onboarding/installer errors, fanotify/eBPF errors — with timestamps and samples |
| **MDE product logs** | `mde_diagnostic.zip` | Per-file error/warn counts, top recurring errors, event-provider dropped counters, crash-upload state, OS release |
| Analyzer log | `log.txt` | Errors during collection |

### Interactivity

- **Light/dark toggle** (floating button) — persists your choice, defaults to OS theme.
- **Fluid layout** — scales with viewport width up to a readable cap.
- **Copy buttons** on every remediation command.
- **Print/PDF stylesheet** — expands all sections and hides the toggle for clean export.

## Notes on accuracy

- **lsof** is parsed **system-wide** — the report shows the top open-file
  consumers across all processes (open FDs, memory-mapped files, network/socket
  handles, deleted-but-open files), with MDE processes (`wdavdaemon`, `mdatp`, …)
  tagged and broken out separately. It:
  - counts only real numeric file descriptors (ignores `mem`/`txt` memory-mapped
    library entries),
  - deduplicates by `(pid, fd)` because the analyzer runs `lsof` with thread
    listing (the `TID` column), which otherwise multiplies shared FDs by the
    thread count.
- **Disk** alerts ignore read-only pseudo mounts (`/snap/*`, `tmpfs`, `overlay`,
  `squashfs`, WSL `drivers`) that always report 100% by design.
- Every parser is tolerant: a missing or unexpected file is skipped, never fatal.
  The run summary prints `parsed N/M sources`.

## Log archives

- **OS log zips are parsed.** `syslogs.zip`, `kernel_logs.zip` and `mdc_log.zip`
  (including gzipped members) are scanned for a curated set of MDE-relevant
  events: wdavdaemon crashes (segfault / fatal signal), OOM kills, hung tasks,
  onboarding/health failures, installer errors, and fanotify/eBPF errors. Each
  category is reported with count, first/last timestamp and sample lines.
  **AuditD is intentionally excluded** — it is no longer used by MDE on Linux.
  Pass `--max-age-days N` to drop events older than N days (relative to capture
  time) from both these archives and the product logs below. Lines without a
  parseable timestamp cannot be aged, so they are always kept.
- **`mde_diagnostic.zip` is extracted in-memory and parsed** (see below).
- **`mpenginedb.db` is not read** — it is the Defender engine database, sealed/
  encrypted on disk (header is not `SQLite format 3`). Use `mdatp threat list`
  for threat history.

### mde_diagnostic.zip → "MDE product logs" section

The agent's own bundle is the richest troubleshooting source. The report mines:

- **Product logs** under `var/log/microsoft/mdatp/*.log` (incl. rotated) — the
  real Defender logs (`microsoft_defender_err.log`, `_core_err.log`,
  `_enterprise_err.log`, `mplog`, etc.). Per-file **error / warning counts**,
  time span, and **top recurring errors** grouped by a normalized signature
  (paths / hashes / numbers collapsed) so a message repeated thousands of times
  shows as one ranked row.
- **`microsoft_defender_diagnostic_event_provider_counters.json`** — structured
  **dropped-message counters** (behavior-monitoring / IPC / kernel), highlighted
  when non-zero.
- **`wdav_crash_state`** — pending crash-upload count.
- **`usr/lib/os-release`** — exact distro (`PRETTY_NAME`) shown in the KPIs.
- Signature blobs under `enginedb/RtSigs/` are ignored.

This scans ~35 MB of uncompressed logs; the whole report generates in ~1.3 s.

## Tunable thresholds

Severity thresholds live near the top of the analyzer section in
`mde_perf_report.py`:

```python
WDA_CPU_WARN = 40.0    WDA_CPU_CRIT = 70.0    # wdavdaemon aggregate %CPU
SCAN_MS_WARN = 100.0   SCAN_MS_CRIT = 500.0   # per-process scan time
DISK_WARN = 85         DISK_CRIT = 95         # filesystem usage %
FD_WARN = 5000         FD_CRIT = 20000        # MDE open file descriptors
```
