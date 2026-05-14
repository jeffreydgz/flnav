#! /bin/bash

export TZ=UTC
export YES_COLOR=1
export DUMP_CRASH=1

run_cap_test ${lnav_test} --ioc ${test_dir}/ioc_forensic_ipv4.txt -n \
    -c ":ssh-stats" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} --ioc ${test_dir}/ioc_forensic_invalid_ipv4.txt -n \
    -c ":ssh-stats" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} --ioc ${test_dir}/ioc_forensic_cidr.txt -n \
    -c ":ssh-stats" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} -n \
    -c ":ssh-stats" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} --ioc ${test_dir}/ioc_forensic_cidr.txt -n \
    -c ";SELECT source_ip, destination, outcome, top_user, event_count, ioc_match FROM ssh_stats WHERE source_ip IN ('198.51.100.23', '198.51.100.44', '2001:db8::77', '203.0.113.99') ORDER BY source_ip, destination, outcome, top_user" \
    -c ":write-table-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} --ioc ${test_dir}/ioc_forensic_cidr.txt -n \
    -c ";SELECT address, scope, event_count, ioc_match FROM ssh_stats_ip_counts WHERE ioc_match = 1 ORDER BY address" \
    -c ":write-table-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} --ioc ${test_dir}/ioc_forensic_cidr.txt -n \
    -c ";WITH doc AS (SELECT ssh_stats_json() AS json) SELECT (SELECT value FROM ssh_stats_summary WHERE metric = 'total_ssh_events') AS sql_total, json_extract(json, '$.summary.total_ssh_events') AS json_total, (SELECT count(*) FROM ssh_stats) AS sql_flows, json_array_length(json_extract(json, '$.flows')) AS json_flows, json_extract(json, '$.ioc.entries_loaded') AS ioc_entries FROM doc" \
    -c ":write-table-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} -n \
    -c ":session-trace alice bob" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} -n \
    -c ":session-trace --timeout 10m alice bob" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} -n \
    -c ":log-gaps 15m" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_gaps_a.0 \
    ${test_dir}/logfile_forensic_gaps_b.0

run_cap_test ${lnav_test} -n \
    -c ";SELECT log_file, gap_start, gap_end, gap_duration_seconds AS seconds, other_files_active AS xref, severity FROM log_gaps(900)" \
    -c ":write-table-to -" \
    ${test_dir}/logfile_forensic_gaps_a.0 \
    ${test_dir}/logfile_forensic_gaps_b.0

run_cap_test ${lnav_test} -n \
    -c ":filter-in-and alice" \
    -c ":filter-in-and 198\\.51\\.100\\.23" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} -n \
    -c ":filter-out-and alice" \
    -c ":filter-out-and 198\\.51\\.100\\.23" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} -n \
    -c ":filter-expr :log_body LIKE '%admin%'" \
    -c ":ssh-stats" \
    -c ":ssh-stats" \
    -c ":filter-expr :log_body LIKE '%root%'" \
    -c ":ssh-stats" \
    -c ":write-view-to -" \
    ${test_dir}/logfile_forensic_auth_bsd.0 \
    ${test_dir}/logfile_forensic_auth_iso.0

run_cap_test ${lnav_test} -nN \
    -c ";WITH cases(label, input) AS (VALUES ('offset','2024-03-25T10:30:00-05:00'), ('millis','2024-03-25 10:30:00.123'), ('micros','2024-03-25 10:30:00.123456'), ('nanos','2024-03-25 10:30:00.123456789'), ('null',NULL)) SELECT label, input, normalize_ts(input) AS normalized FROM cases" \
    -c ":write-table-to -"

run_cap_test ${lnav_test} -nN \
    -c ";SELECT normalize_ts('not a timestamp')"
