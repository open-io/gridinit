#!/usr/bin/env bash
set -e
MAX=$1
shift

[[ -n "$MAX" ]]

cat > /tmp/gridinit.conf <<EOF
[Default]
listen=/tmp/gridinit.sock
pidfile=/tmp/gridinit.pid
working_dir=/tmp
inherit_env=1
limit.core_size=0
limit.max_files=256
limit.stack_size=32
EOF

for i in $(seq ${MAX}) ; do
	cat >> /tmp/gridinit.conf <<EOF

[service.TEST-$i]
group=test
on_die=respawn
enabled=true
start_at_boot=true
command=/bin/sleep $((i+15))
EOF
done

