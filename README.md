# flnav

`flnav` is a security-focused fork of
[lnav](https://github.com/tstack/lnav), the terminal-based logfile navigator.
It keeps the core lnav experience for browsing, searching, filtering, and
querying logs, then adds workflows for incident response and forensic triage.

The fork installs as `flnav` and can live beside upstream `lnav` without
conflicts. It uses its own binary name, config directory (`~/.flnav`), and
database namespace (`flnav_db`).

## What It Does

- Opens log files, directories, compressed logs, and piped input in an
  interactive terminal UI.
- Lets you search, filter, bookmark, and inspect structured log fields.
- Provides SQL access to log data and forensic summaries.
- Normalizes timestamps so mixed timezone logs can be compared consistently.
- Maps SSH authentication activity by source IP, destination, user, outcome,
  and authentication source.
- Loads IOC files with exact IPs and CIDR ranges for threat-intel matching.
- Reconstructs actor activity into sessions across multiple logs.
- Detects suspicious logging gaps by comparing timelines across loaded files.
- Adds AND-style filters and mouse text selection for faster investigation.

Forensic triage commands are built in and enabled by default. No special
profile or config file is required.

## Forensic Features

### SSH Traffic Flow Map

Use `:ssh-stats` or press `0` to open an SSH traffic summary for all visible log
lines.

The report includes:

- per-source flow rows with destination host, outcome, top user, auth source,
  event count, and percentage
- event counters for accepted logins, failed auth, preauth closes,
  disconnects, and new connections
- public/private IP frequency counts
- IOC match flags when an IOC file is loaded

The SSH parser handles BSD syslog and ISO syslog SSH logs, including common
OpenSSH, PAM, SSSD, LDAP, Kerberos/GSSAPI, Duo/MFA, RADIUS, and smartcard/PIV
patterns.

The same data is available through SQL and JSON:

```sql
SELECT * FROM ssh_stats;
SELECT * FROM ssh_stats_ip_counts;
SELECT * FROM ssh_stats_summary;
SELECT ssh_stats_json();
```

`ssh_stats_json()` returns one document with `summary`, `ioc`, `flows`, and
`ip_counts` sections.

### IOC Matching

Load threat-intel indicators with `--ioc`:

```console
$ flnav --ioc /path/to/ioc.txt /var/log/auth.log
```

IOC files are plain text. Comments start with `#`. Entries can be exact IPv4 or
IPv6 addresses, or IPv4/IPv6 CIDR ranges:

```text
198.51.100.23
2001:db8::42
198.51.100.0/24
2001:db8::/64
```

Exact IPs are highlighted in the log view. Exact IPs and CIDR ranges are both
used for SSH stats IOC flags and structured SQL/JSON exports.

### Session Trace

Use `:session-trace` to reconstruct an actor's activity across loaded logs:

```text
:session-trace 198.51.100.23 alice
:session-trace --timeout 10m admin
```

You can trace one or more IP addresses or usernames. Matching lines are grouped
into sessions using connection boundaries and an inactivity timeout. The default
timeout is 30 minutes; override it with `--timeout` using `s`, `m`, or `h`
suffixes.

The report summarizes first/last seen timestamps, contributing files, IPs,
usernames, auth accept/fail counts, session outcomes, warnings, errors, and the
longest session duration.

### Log Gap Detection

Use `:log-gaps` to find periods where logging stopped:

```text
:log-gaps
:log-gaps 15m
```

Thresholds support `s`, `m`, and `h` suffixes. Gaps are cross-referenced with
other loaded files. If other files have entries during the gap, the gap is
marked suspicious; otherwise it is marked normal.

The same detector is exposed through SQL:

```sql
SELECT * FROM log_gaps(900);
```

### Timestamp Normalization

Press `y` or use `:normalize-timestamps` to display timestamps in UTC
`YYYY-MM-DD HH:MM:SS[.sss]` form while preserving sub-second precision.

```text
:normalize-timestamps on
:normalize-timestamps off
```

SQL access is also available:

```sql
SELECT normalize_ts('2024-03-25T10:30:00-05:00');
```

### AND Filters

The standard lnav include/exclude filters use OR-style matching. `flnav` adds
AND-style variants:

```text
:filter-in-and sshd
:filter-in-and Failed
:filter-out-and healthcheck
```

In the filter panel these appear as `IN+` and `OUT+`. Press `t` to cycle filter
types between `IN`, `IN+`, `OUT`, and `OUT+`.

### Mouse Selection

Press `F2` to toggle mouse mode. Click and drag to select text, or double-click
to select a word. The popup actions can copy, search, or filter on the
selection.

## Quick Reference

| Key / Command | Action |
|---|---|
| `0` | Toggle SSH Traffic Flow Map |
| `y` | Toggle timestamp normalization |
| `F2` | Toggle mouse mode |
| `n` / `N` | Jump to next/previous session or gap |
| `t` | Cycle filter type |
| `--ioc <file>` | Load exact IP and CIDR IOC entries |
| `:ssh-stats` | Show SSH traffic summary |
| `:session-trace [--timeout 30m] <target> [...]` | Trace actor activity |
| `:log-gaps [threshold]` | Detect logging gaps |
| `:filter-in-and <pattern>` | Add an AND include filter |
| `:filter-out-and <pattern>` | Add an AND exclude filter |
| `ssh_stats`, `ssh_stats_ip_counts`, `ssh_stats_summary` | SQL SSH stats exports |
| `ssh_stats_json()` | JSON SSH stats export |
| `log_gaps(<seconds>)` | SQL log-gap export |
| `normalize_ts(<timestamp>)` | SQL timestamp normalization |

## Examples

Open logs normally:

```console
$ flnav /var/log/auth.log
$ flnav /var/log
```

Load SSH logs with threat-intel matching:

```console
$ flnav --ioc indicators.txt /var/log/auth.log /var/log/secure
```

Export SSH stats as JSON from headless mode:

```console
$ flnav --ioc indicators.txt -n \
    -c ";SELECT ssh_stats_json()" \
    -c ":write-table-to -" \
    /var/log/auth.log
```

Use journald output:

```console
$ journalctl | flnav
$ journalctl -f | flnav
$ journalctl -o short-iso | flnav
$ journalctl -o json | flnav
```

## Build And Install

### Prerequisites

- gcc or clang with C++17 support
- libpcre2
- sqlite >= 3.9.0
- zlib and bzip2
- libcurl >= 7.23.0
- libarchive
- libunistring
- Rust/Cargo and `cxxbridge`
- `tshark` from Wireshark, optional for pcap support

On Ubuntu/Debian, the CI-tested dependency set is:

```console
$ sudo apt-get update
$ sudo apt-get install -y --no-install-recommends \
    autoconf automake autopoint bison build-essential bzip2 cargo \
    ca-certificates flex gettext libarchive-dev libbz2-dev \
    libcurl4-openssl-dev libncurses-dev libpcre2-dev \
    libreadline-dev libsqlite3-dev libtool libunistring-dev \
    pkg-config re2c rustc xz-utils zlib1g-dev
$ cargo install cxxbridge-cmd --locked --version 1.0.194
$ export PATH="$HOME/.cargo/bin:$PATH"
```

### Build

Autotools is the primary documented build path:

```console
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

For a quick local rebuild during development:

```console
$ export PATH="$HOME/.cargo/bin:$PATH"
$ make -j"$(nproc)"
```

CMake metadata is also kept aligned for packagers and toolchains that provide
the required dependencies through CMake.

### Tests

Run the focused forensic regression suite:

```console
$ export PATH="$HOME/.cargo/bin:$PATH"
$ make -C test check TESTS=test_forensics.sh
```

## Relationship To Upstream

`flnav` is based on upstream [lnav](https://github.com/tstack/lnav). The base
viewer, format detection, SQL integration, filtering, and navigation behavior
come from lnav. This fork adds the forensic workflows described above and keeps
the executable/config names separate so both tools can be installed on the same
system.

For general lnav usage, see the upstream documentation:
[https://docs.lnav.org](https://docs.lnav.org).
