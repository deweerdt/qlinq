#!/bin/sh
set -eu

app_bin=${QLINQ_APP_BIN:-./qlinq-app}
tmp_dir=$(mktemp -d /tmp/qlinq-app-test.XXXXXX)
server_pid=
client_pid=
client2_pid=

cleanup()
{
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
    if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; fi
    if [ -n "$client2_pid" ]; then kill "$client2_pid" 2>/dev/null || true; fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

timeout 8 "$app_bin" \
    --listen 10093 --bind 127.0.0.1 \
    --idle-timeout-ms 60000 \
    --auth-token app-test --insecure-no-verify \
    --input README.md --message-size 512 --count 1 \
    --wait-subscribers 1 --one-shot --drain-ms 500 --mode rateless \
    --node-id direct-source --stats-file "$tmp_dir/server.tsv" \
    2>"$tmp_dir/server.log" &
server_pid=$!

timeout 4 "$app_bin" \
    --peer 127.0.0.1:10093 \
    --idle-timeout-ms 60000 \
    --auth-token app-test --insecure-no-verify \
    --output "$tmp_dir/output.bin" --mode rateless \
    --receive-count 1 --drain-ms 200 \
    --node-id direct-rx --stats-file "$tmp_dir/client.tsv" \
    2>"$tmp_dir/client.log" &
client_pid=$!

if ! wait "$server_pid"; then
    server_pid=
    sed -n '1,80p' "$tmp_dir/server.log" >&2
    sed -n '1,80p' "$tmp_dir/client.log" >&2
    exit 1
fi
server_pid=
if ! wait "$client_pid"; then
    client_pid=
    sed -n '1,80p' "$tmp_dir/server.log" >&2
    sed -n '1,80p' "$tmp_dir/client.log" >&2
    exit 1
fi
client_pid=

test "$(wc -c < "$tmp_dir/output.bin")" -eq 512
cmp -n 512 README.md "$tmp_dir/output.bin"
awk -F '\t' 'NR == 1 { exit !($1 == "elapsed_ms" && $2 == "node" &&
                                  $3 == "tx_records" && $4 == "rx_records") }' \
    "$tmp_dir/client.tsv"
awk -F '\t' '$2 == "direct-rx" && $3 == 0 && $4 == 1 && $5 == 512 { ok=1 }
              END { exit !ok }' "$tmp_dir/client.tsv"
awk -F '\t' '$2 == "direct-source" && $6 >= 1 { ok=1 } END { exit !ok }' \
    "$tmp_dir/server.tsv"
awk -F '\t' '$2 == "direct-rx" && $7 >= 1 { ok=1 } END { exit !ok }' \
    "$tmp_dir/client.tsv"

# Two clients exercise per-connection subscription targeting and distinct
# server-issued connection IDs.
timeout 8 "$app_bin" \
    --listen 10094 --bind 127.0.0.1 \
    --auth-token fanout-test --insecure-no-verify \
    --input README.md --message-size 256 --count 1 \
    --wait-subscribers 2 --one-shot --drain-ms 500 --mode reliable \
    2>"$tmp_dir/fanout-server.log" &
server_pid=$!

timeout 4 "$app_bin" \
    --peer 127.0.0.1:10094 \
    --auth-token fanout-test --insecure-no-verify \
    --output "$tmp_dir/fanout-a.bin" --mode reliable \
    --receive-count 1 --drain-ms 100 \
    2>"$tmp_dir/fanout-a.log" &
client_pid=$!

timeout 4 "$app_bin" \
    --peer 127.0.0.1:10094 \
    --auth-token fanout-test --insecure-no-verify \
    --output "$tmp_dir/fanout-b.bin" --mode reliable \
    --receive-count 1 --drain-ms 100 \
    2>"$tmp_dir/fanout-b.log" &
client2_pid=$!

fanout_failed=0
wait "$server_pid" || fanout_failed=1
server_pid=
wait "$client_pid" || fanout_failed=1
client_pid=
wait "$client2_pid" || fanout_failed=1
client2_pid=
if [ "$fanout_failed" -ne 0 ]; then
    sed -n '1,80p' "$tmp_dir/fanout-server.log" >&2
    sed -n '1,80p' "$tmp_dir/fanout-a.log" >&2
    sed -n '1,80p' "$tmp_dir/fanout-b.log" >&2
    exit 1
fi
cmp -n 256 README.md "$tmp_dir/fanout-a.bin"
cmp -n 256 README.md "$tmp_dir/fanout-b.bin"

printf '%s\n' '===QLINQ APP DIRECT API OK==='
