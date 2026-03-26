#! /bin/bash

export TZ=UTC
export YES_COLOR=1

# Plain seconds — no millis in input, no millis in output
run_cap_test ./drive_sql "select normalize_ts('2024-03-25 10:30:00')"

# With milliseconds — millis preserved in output
run_cap_test ./drive_sql "select normalize_ts('2024-03-25 10:30:00.123')"

# ISO8601 with negative UTC offset (-05:00) — converts to UTC (+5h)
run_cap_test ./drive_sql "select normalize_ts('2024-03-25T10:30:00-05:00')"

# ISO8601 with positive UTC offset (+08:00) — converts to UTC (-8h), crosses midnight
run_cap_test ./drive_sql "select normalize_ts('2024-03-25T00:05:22+08:00')"

# ISO8601 Z suffix (already UTC) — millis preserved
run_cap_test ./drive_sql "select normalize_ts('2024-03-25T18:05:33.456Z')"

# Millisecond boundary: .000 — millis still present in output
run_cap_test ./drive_sql "select normalize_ts('2024-03-25 14:00:00.000')"

# High-precision millis at end of day
run_cap_test ./drive_sql "select normalize_ts('2024-03-25T23:59:59.999Z')"

# Syslog-style timestamp (no year, no TZ)
run_cap_test ./drive_sql "select normalize_ts('Mar 25 08:22:10')"

# ISO8601 with -05:00 and millis — both TZ conversion and millis preserved
run_cap_test ./drive_sql "select normalize_ts('2024-03-25T10:15:00.500-05:00')"

# NULL input — should return NULL
run_cap_test ./drive_sql "select normalize_ts(NULL)"

# Invalid input — should report an error
run_cap_test ./drive_sql "select normalize_ts('not a timestamp')"
