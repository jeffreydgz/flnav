# flnav — The Logfile Navigator (custom fork)

A fork of [lnav](https://github.com/tstack/lnav) with added features for log analysis, security investigation, and forensic triage.

Can be installed alongside the original `lnav` without conflicts — uses separate config directory (`~/.flnav`), database schema (`flnav_db`), and binary name (`flnav`).

---

## Added Features

### Timestamp Normalization

Normalize all displayed log timestamps to UTC `YYYY-MM-DD HH:MM:SS[.sss]` format, regardless of the original timezone or format in the file.

| Interface | How to use |
|---|---|
| Key | `y` — toggle on/off |
| Command | `:normalize-timestamps [on\|off]` |
| SQL | `SELECT normalize_ts('2024-03-25T10:30:00-05:00')` |

Useful when comparing logs from machines in different timezones or with mixed timestamp formats (e.g. syslog + ISO 8601 in the same file). Microsecond/nanosecond precision is preserved.

---

### SSH Traffic Flow Map

Analyze SSH activity across all loaded log files and display a traffic flow report.

| Interface | How to use |
|---|---|
| Key | `0` — toggle the panel |
| Command | `:ssh-stats` |

The panel shows three sections:

1. **SSH Traffic Flow Map** — per-source-IP flow table with destination host, outcome (accepted/failed/disconnected/etc.), authenticated user(s), and auth method detection for 14 methods including: public key, password, SSSD (LDAP/AD), Kerberos/GSSAPI, MFA/Duo, keyboard-interactive, and more.
2. **SSH Event Summary** — counts of accepted, failed password, failed publickey, invalid user, disconnected, too many failures, preauth closed, client disconnect, connection closed, and new connection events.
3. **IP Address Frequency** — all IPs extracted from logs via `data_scanner` token analysis, split into **Public** and **Private** (RFC 1918) sub-groups with occurrence counts.

The view is pre-built in the background after initial file loading, so pressing `0` shows results instantly.

Supports both BSD syslog (`Mar 25 HH:MM:SS host sshd[pid]: ...`) and ISO syslog (`2026-03-25T13:03:20+00:00 host sshd[pid]: ...`) formats.

---

### IOC Highlighting

Flag known malicious IPs from a threat-intelligence file. Matching IPs are highlighted in both the log view and the SSH stats panel.

```console
$ flnav --ioc /path/to/ioc.txt /var/log/auth.log
```

The IOC file is plain text — one IPv4 address per line, `#` comments supported.

---

### Session Trace

Reconstruct a single actor's activity across all loaded log files, grouped into sessions.

| Interface | How to use |
|---|---|
| Command | `:session-trace <actor> [<actor2> ...]` |
| Navigation | `n` / `N` — jump between sessions |

Supports **multiple arguments** — trace by both IP and username simultaneously (e.g. `:session-trace 192.168.1.1 admin`). A line matches if it contains any of the specified targets.

**Forensic summary** at the top of the report:

- First/last seen timestamps and total time span
- Contributing log files
- All IPs and usernames seen
- Authentication accept/fail counts
- Session outcomes (closed/opened/unknown)
- Error and warning counts
- Longest session duration

Lines are grouped into sessions using connection boundaries and a 30-minute inactivity timeout. Each session header shows start/end time, duration, source IP, user, and outcome.

**Syntax highlighting** — log lines are colorized with semantic colors: IPs, hostnames, usernames, PIDs, and process names each get distinct colors; numbers and quoted strings are highlighted; warning/error log levels are colored.

Tab-completion scans the first 50,000 lines to suggest IPs and usernames.

---

### AND Filters

Standard `:filter-in` and `:filter-out` use OR logic (any pattern matches). The AND variants require **all** patterns to match simultaneously.

| Command | Description |
|---|---|
| `:filter-in-and <pattern>` | Line must match ALL `filter-in-and` patterns to be shown |
| `:filter-out-and <pattern>` | Line must match ALL `filter-out-and` patterns to be hidden |

**Combined semantics:** a line is shown if it passes the OR group (any `:filter-in`) AND the AND group (all `:filter-in-and`) AND does not match any `:filter-out` AND does not match all `:filter-out-and` patterns simultaneously.

In the filter panel, AND filters display as `IN+` / `OUT+`. Press `t` to cycle filter types: IN → IN+ → OUT → OUT+ → IN.

---

### Log Gap Detection

Find periods where logging stopped — potential evidence of log tampering, service crashes, or network outages.

| Interface | How to use |
|---|---|
| Command | `:log-gaps [threshold]` (default `5m`) |
| SQL | `SELECT * FROM log_gaps(300)` |
| Navigation | `n` / `N` — jump between gaps |

Threshold supports `s`/`m`/`h` suffixes (e.g. `30s`, `10m`, `2h`).

Gaps are cross-referenced against other loaded files: if other files have log entries during a gap, it is marked **suspicious**; otherwise **normal**.

The `log_gaps()` SQL table-valued function returns columns: `log_file`, `gap_start`, `gap_end`, `gap_duration_seconds`, `other_files_active`, `severity`.

---

### Parallel File Scanning

Files with a detected log format are scanned in parallel using worker threads (up to 8 concurrent), significantly reducing initial load time for large multi-file datasets.

---

### Pac-Man Loading Animation

A Pac-Man animation plays in the bottom status bar during loading, indexing, or searching. Pac-Man bounces across a 13-cell track with trailing ghosts.

---

### Mouse Text Selection

Click+drag to select text in any view. Double-click selects a word. An actions popup appears with Copy, Search, and Filter options. Press `F2` to toggle mouse mode on/off.

---

### Performance & Bug Fixes

- Replaced `find()+emplace()` with `try_emplace()` for map merging
- Cached `get_time()` calls outside hot loops
- Added `std::is_sorted()` guard before `std::stable_sort()` in the render path
- Fixed unchecked `.back()` calls on potentially empty containers
- Fixed pointer arithmetic bug in file identity checks
- Fixed right-arrow scroll becoming stuck after scrolling back from maximum position
- Fixed multi-zip crash: serialized `archive_manager::extract()` with mutex (libarchive not thread-safe)
- Cumulative load progress: bottom bar no longer resets 0-100% per file during multi-file loads

---

## Quick Reference

| Key / Command | Action |
|---|---|
| `y` | Toggle timestamp normalization (UTC) |
| `0` | Toggle SSH Traffic Flow Map |
| `F2` | Toggle mouse mode |
| `n` / `N` | Jump to next/previous session or gap |
| `t` | Cycle filter type (IN → IN+ → OUT → OUT+) |
| `:normalize-timestamps [on\|off]` | Toggle timestamp normalization |
| `:ssh-stats` | Open SSH Traffic Flow Map |
| `:session-trace <target> [...]` | Trace actor activity across logs |
| `:log-gaps [threshold]` | Detect logging gaps |
| `:filter-in-and <pattern>` | AND include filter |
| `:filter-out-and <pattern>` | AND exclude filter |
| `--ioc <file>` | CLI flag to load IOC threat-intel file |

---

## Installation

### Prerequisites

- gcc/clang (C++14-compatible)
- libpcre2
- sqlite >= 3.9.0
- zlib, bz2
- libcurl >= 7.23.0
- libarchive
- libunistring
- wireshark (`tshark`, for pcap support)
- cargo/rust (for PRQL compiler)

### Build

```console
$ ./autogen.sh    # only needed when building from a git clone
$ ./configure
$ make
$ sudo make install
```

## Usage

```console
$ flnav /path/to/file1 /path/to/dir ...
$ flnav --ioc /path/to/ioc.txt /var/log/auth.log
```

See the [upstream documentation](https://docs.lnav.org) for full usage details on base lnav functionality.

### Usage with `systemd-journald`

```console
$ journalctl | flnav
$ journalctl -f | flnav
$ journalctl -o short-iso | flnav
$ journalctl -o json | flnav
```

## Upstream

This fork is based on [tstack/lnav](https://github.com/tstack/lnav).
For issues with base lnav functionality, refer to the upstream project.
