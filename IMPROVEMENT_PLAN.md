# flnav Improvement Plan

This file is the shared working checklist for improving `flnav`. It is meant to
survive across chats: update checkboxes, add notes, and append new tasks as the
project evolves.

## How To Use This File

- Check off items as they are completed.
- Add short notes under a task when decisions or blockers come up.
- Keep new tasks scoped enough that they can be completed in one focused pass.
- In a fresh chat, ask the assistant to read this file before continuing work.

## Current Priority

Phases 1 through 12 are complete. The only open planning question is whether
the project should keep CMake as a supported build path or officially recommend
autotools only.

## Phase 1: Stabilize Fork Identity

- [x] Make all build paths produce/install `flnav`, not `lnav`.
- [x] Rename or alias the CMake executable target currently created as `lnav`.
- [x] Update CMake project metadata from upstream `lnav` naming where appropriate.
- [x] Verify autotools and CMake install paths do not conflict with upstream lnav.
- [x] Review help text, docs, contacts, URLs, and generated metadata for stale upstream-only references.
- [x] Add a short note in the README explaining supported build path(s).

Notes:

- 2026-05-14: CMake now uses the `flnav` project and executable target, CMake install/package metadata uses `flnav`, autotools already used `flnav`, and a missing `flnav.1` manpage was added for the existing `dist_man_MANS` entry.
- 2026-05-14: CLI/help contact metadata now points to `https://github.com/jeffreydgz/flnav/issues`. Upstream schema URLs under format/config JSON files intentionally remain `lnav.org` because they identify the upstream schema namespace.
- 2026-05-14: Local autotools build now succeeds after installing the toolchain and adding `~/.cargo/bin` to `PATH` for `cxxbridge`. `/usr/bin/flnav` resolves to the rebuilt `src/flnav` through the existing user-writable symlink chain.

## Phase 2: Add Regression Coverage

- [x] Add small auth/syslog fixtures for forensic features.
- [x] Add direct tests for `:ssh-stats` output.
- [x] Add direct tests for `:session-trace` grouping and summary output.
- [x] Add direct tests for `:log-gaps` command output.
- [x] Add direct tests for `log_gaps()` SQL table-valued function.
- [x] Add tests for AND-filter semantics: `:filter-in-and` and `:filter-out-and`.
- [x] Add tests for IOC file parsing and exact IP matching boundaries.
- [x] Expand `normalize_ts()` tests for timezone, precision, invalid input, and NULL behavior as needed.

Notes:

- 2026-05-14: Added a small fixture corpus for future command and SQL regression tests: `test/logfile_forensic_auth_bsd.0`, `test/logfile_forensic_auth_iso.0`, `test/logfile_forensic_gaps_a.0`, `test/logfile_forensic_gaps_b.0`, `test/ioc_forensic_ipv4.txt`, and `test/ioc_forensic_invalid_ipv4.txt`. These are listed in `test/Makefile.am` so they will be distributed with the test suite.
- 2026-05-14: Added active snapshot coverage in `test/test_forensics.sh` for `:ssh-stats` over the BSD and ISO SSH fixtures with a valid IOC file loaded. The snapshot verifies flow rows, event counters, public/private IP grouping, and IOC match totals.
- 2026-05-14: Added active snapshot coverage in `test/test_forensics.sh` for `:session-trace alice bob` across two fixtures. This verifies summary aggregation, two-session grouping, per-session durations, source/user extraction, and the corrected no-duplicate first-line behavior.
- 2026-05-14: Added active snapshot coverage in `test/test_forensics.sh` for `:log-gaps 15m` across deterministic ISO gap fixtures. This verifies suspicious gap detection when another file has entries during the gap and locks in singular/plural wording for one-gap output.
- 2026-05-14: Added active snapshot coverage for the `log_gaps(900)` SQL table-valued function so SQL gap rows stay aligned with the command fixture corpus.
- 2026-05-14: Added `:filter-in-and` and `:filter-out-and` snapshots proving multiple AND filters include or exclude only lines matching every pattern.
- 2026-05-14: Expanded IOC boundary coverage with invalid/out-of-range IPv4 values, adjacent-text boundary cases, and a close but non-matching valid IP. The snapshot verifies these load as `0 / 1` IOC matches instead of accidentally matching `198.51.100.23`.
- 2026-05-14: Added `normalize_ts()` snapshots for timezone offsets, millisecond/microsecond/nanosecond precision, NULL return behavior, and invalid-input error reporting.

## Phase 3: Extract Forensic Logic

- [x] Create `src/forensic_time.{cc,hh}` for shared forensic timestamp formatting helpers.
- [x] Create `src/log_gap_detector.{cc,hh}` for shared gap detection.
- [x] Create `src/ssh_flow.{cc,hh}` for SSH event parsing, aggregation, and report data.
- [x] Create `src/session_trace.{cc,hh}` for actor matching, session grouping, and summary data.
- [x] Keep `src/lnav_commands.cc` focused on command registration and UI glue.
- [x] Update build files for any new source/header files.

Notes:

- 2026-05-14: Added `src/forensic_time.{cc,hh}`, `src/log_gap_detector.{cc,hh}`, `src/ssh_flow.{cc,hh}`, and `src/session_trace.{cc,hh}`. `lnav_commands.cc` now keeps the forensic view/report rendering and delegates timestamp formatting, gap detection, SSH scan aggregation, session matching, session grouping, and session summary data to these helpers.
- 2026-05-14: Updated autotools and CMake source lists for the new helper modules.

## Phase 4: Unify Duplicate Behavior

- [x] Make `:log-gaps` use the shared log gap detector.
- [x] Make `log_gaps()` use the same shared detector.
- [x] Ensure command output and SQL output agree on gap duration and suspicious/normal classification.
- [x] Add regression tests proving UI command and SQL behavior stay aligned.

Notes:

- 2026-05-14: Phase 3 extraction also completed Phase 4 for log gaps: both `:log-gaps` and `log_gaps()` now call `lnav::forensics::detect_log_gaps()`, and the existing Phase 2 command/SQL snapshots cover the shared fixture corpus.

## Phase 5: Fix Cache Invalidation

- [x] Replace SSH stats cache key based only on visible line count.
- [x] Track a cache generation or hash that changes when log content changes.
- [x] Include filter/visibility state in cache invalidation.
- [x] Include IOC set changes in cache invalidation.
- [x] Add a regression test for same-line-count content changes.

Notes:

- 2026-05-14: `:ssh-stats` now caches by a fingerprint covering visible line
  count, log index generation, active file generation, file identity/version
  metadata, filter/visibility state, and the loaded IOC set instead of line
  count alone. Added a regression that switches a SQL filter from one matching
  line to another matching line with the same visible count, proving stale
  SSH stats are not reused.

## Phase 6: Improve Parser Correctness

- [x] Tighten IPv4 validation so invalid addresses like `999.999.999.999` do not count as IOCs.
- [x] Add IPv6 IOC support or explicitly document IPv4-only support.
- [x] Harden SSH username extraction for `invalid user`, quoted users, and PAM variants.
- [x] Harden SSH source IP extraction for OpenSSH preauth, disconnect, and IPv6 patterns.
- [x] Add fixtures for BSD syslog and ISO syslog SSH logs.
- [x] Add fixtures for Accepted password/publickey/GSSAPI/keyboard-interactive events.
- [x] Add fixtures for SSSD, Duo/MFA, LDAP, Kerberos, RADIUS, and smartcard/PIV PAM lines.

Notes:

- 2026-05-14: Fixture coverage now includes BSD syslog, ISO syslog, accepted password, accepted publickey, failed publickey, invalid-user failures, preauth disconnects, IPv6 source addresses, quoted IPv4 source addresses, SSSD PAM, Duo PAM, and RADIUS PAM.
- 2026-05-14: `--ioc` IPv4 loading now rejects out-of-range dotted quads before adding them to the IOC set or highlight pattern. Valid IOC integration and invalid/boundary-only IOC behavior are covered by `test/test_forensics.sh`.
- 2026-05-14: `--ioc` now accepts validated IPv4 and IPv6 tokens, stores them in canonical form, and highlights/matches them case-insensitively. SSH stats IP extraction now canonicalizes source IPs, handles bracketed IPv6, `rhost=...`, quoted values, OpenSSH preauth/disconnect patterns, and quoted invalid usernames. The forensic fixtures now cover GSSAPI, keyboard-interactive/PAM, LDAP, Kerberos, SSSD, RADIUS, Duo/MFA, and smartcard/PIV cases.

## Phase 7: CI And Release Polish

- [x] Add GitHub Actions workflow for Linux build.
- [x] Run targeted shell tests in CI.
- [x] Add formatting or lint checks if they are already practical for the codebase.
- [x] Document distro-specific dependencies.
- [x] Add a release checklist for version bumps, generated docs, and smoke tests.
- [x] Consider publishing release artifacts once CI is reliable.

Notes:

- 2026-05-14: Added `.github/workflows/ci.yml` with an Ubuntu autotools build,
  whitespace check that skips generated help/SQL docs, pinned `cxxbridge-cmd`
  install, and targeted `test_forensics.sh` regression run.
- 2026-05-14: Documented the CI-tested Ubuntu/Debian dependency install path in
  `README.md`, including the required `~/.cargo/bin` PATH update for
  `cxxbridge`.
- 2026-05-14: Added `RELEASE_CHECKLIST.md` for version bumps, generated-doc
  review, smoke tests, GitHub token handling from `/home/dev/.env`, and the
  rule that old GitHub releases must stay in place.

## Phase 8: Release Automation And Artifacts

- [x] Let the new CI workflow pass on GitHub at least once.
- [x] Decide which artifacts should be published, such as source archives,
      checksums, or Linux binaries.
- [x] Add artifact packaging only after the build is repeatable in CI.
- [x] Add a release workflow that creates a new versioned release without
      deleting or rewriting older releases.

Notes:

- 2026-05-14: Release artifacts are defined as a source archive, Linux binary
  archive, and SHA256 checksum file.
- 2026-05-14: Added `tools/package-release.sh` to create
  `release-artifacts/flnav-X.Y.Z-source.tar.gz`,
  `release-artifacts/flnav-X.Y.Z-linux-<arch>.tar.gz`, and
  `release-artifacts/flnav-X.Y.Z-SHA256SUMS.txt`.
- 2026-05-14: Added `.github/workflows/release.yml` as a manual release
  workflow. It validates the version against `configure.ac` and
  `CMakeLists.txt`, fails if the tag or release already exists, runs the build
  and forensic regression test, packages artifacts, and creates a new GitHub
  release without deleting older releases.
- 2026-05-14: GitHub Actions CI passed for the Phase 8 release automation
  branch before it was prepared for `main`.

## Phase 9: Forensic Defaults

- [x] Keep forensic features enabled by default.
- [x] Add a small smoke test proving forensic commands are available without a
      special config or profile.
- [x] Document that forensic triage commands are built-in defaults.

Notes:

- 2026-05-14: Forensic triage commands remain built in and available by
  default. Added a `:ssh-stats` smoke test without `--ioc` or a special profile,
  and documented the default behavior in `README.md`.

## Phase 10: IOC CIDR Matching

- [x] Extend `--ioc` parsing to accept CIDR ranges.
- [x] Support IPv4 CIDR ranges first.
- [x] Support IPv6 CIDR ranges if the parser design can cover it cleanly.
- [x] Preserve exact IP matching for plain IP entries.
- [x] Add regression coverage for valid CIDR matches, non-matches, and invalid
      CIDR entries.
- [x] Document IOC file syntax with exact IP and CIDR examples.

Notes:

- 2026-05-14: Added a shared IOC matcher that accepts exact IPv4/IPv6 entries
  and IPv4/IPv6 CIDR ranges. Exact IP entries still power log-view highlights,
  while both exact and CIDR entries are used by SSH stats and structured
  exports. Added CIDR fixtures covering valid matches, non-matches, and invalid
  ranges.

## Phase 11: Structured SSH Stats Export

- [x] Add SQL access to SSH stats data.
- [x] Add JSON export for SSH stats data.
- [x] Keep the current TUI `:ssh-stats` report working.
- [x] Add tests proving SQL, JSON, and TUI outputs stay aligned.
- [x] Document the SQL and JSON export workflows.

Notes:

- 2026-05-14: Added `ssh_stats`, `ssh_stats_ip_counts`, and
  `ssh_stats_summary` SQL table-valued functions plus the `ssh_stats_json()`
  scalar JSON export. The TUI command, SQL rows, and JSON export now share the
  same SSH stats scanner, and regression tests compare the structured outputs
  against the command behavior.

## Phase 12: Configurable Session Trace Timeout

- [x] Keep the default session inactivity timeout at 30 minutes.
- [x] Add `:session-trace --timeout <duration>` support with `s`, `m`, and `h`
      suffixes.
- [x] Add regression coverage showing a shorter timeout splits sessions.
- [x] Document the timeout option.

Notes:

- 2026-05-14: `:session-trace` now accepts `--timeout 10m`,
  `--timeout=10m`, and `-t 10m`. The default remains 30 minutes because it is a
  practical forensic balance: it avoids splitting normal admin pauses too
  aggressively while still separating distinct activity windows.
- 2026-05-14: Tightened session-trace user extraction so lines like
  `session opened for user alice(uid=1001)` report `alice` when a shorter
  timeout starts a new session on that line.

## Decisions

- [x] Forensic features should stay enabled by default.
- [x] `--ioc` should support CIDR ranges for now.
- [x] SSH stats should include structured export through both SQL and JSON.
- [x] Session-trace timeout should be configurable, with 30 minutes as the
      default.

## Open Questions

- [ ] Should CMake remain supported, or should the project officially recommend autotools only?

## Fresh Chat Handoff

When continuing in a new chat, use this prompt:

```text
Read /home/dev/project/flnav/IMPROVEMENT_PLAN.md and continue from the highest-priority unchecked item. Before editing, inspect the related files and keep the checklist updated as work is completed.
```
