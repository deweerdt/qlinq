#!/bin/sh

set -eu

tmp_dir=$(mktemp -d /tmp/qlinq-signals-test.XXXXXX)
app_pid=
daemon_pid=

cleanup()
{
    if [ -n "$app_pid" ]; then kill "$app_pid" 2>/dev/null || true; fi
    if [ -n "$daemon_pid" ]; then kill "$daemon_pid" 2>/dev/null || true; fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

wait_for_log()
{
    pattern=$1
    file=$2
    attempts=50
    while [ "$attempts" -gt 0 ]; do
        if grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        attempts=$((attempts - 1))
        sleep 0.02
    done
    return 1
}

./qlinq-app \
    --listen 10105 --bind 127.0.0.1 \
    --cert t/assets/server.crt --key t/assets/server.key \
    --auth-token signal-test --insecure-no-verify --drain-ms 100 \
    --output /dev/null \
    >"$tmp_dir/app.out" 2>"$tmp_dir/app.log" &
app_pid=$!
sleep 0.1
kill -HUP "$app_pid"
wait_for_log "qlinq-app: TLS credentials reloaded" "$tmp_dir/app.log"
kill -TERM "$app_pid"
wait "$app_pid"
app_pid=

./qlinqd \
    --listen 10106 --bind 127.0.0.1 \
    --cert t/assets/server.crt --key t/assets/server.key \
    --auth-token signal-test --insecure-no-verify \
    --stats-ms 20 \
    --socket "qlinq-signals-$$" \
    >"$tmp_dir/daemon.out" 2>"$tmp_dir/daemon.log" &
daemon_pid=$!
wait_for_log "daemon is running" "$tmp_dir/daemon.out"
wait_for_log "daemon: stats transport=0 role=server" "$tmp_dir/daemon.log"
kill -HUP "$daemon_pid"
wait_for_log "daemon: TLS credential reload complete" "$tmp_dir/daemon.log"
kill -TERM "$daemon_pid"
wait "$daemon_pid"
daemon_pid=

printf '%s\n' '===SIGNALS OK==='
