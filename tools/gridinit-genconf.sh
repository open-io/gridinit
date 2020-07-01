#!/usr/bin/env bash
set -e
set -x

MAX=$1 ; shift
[[ -n "$MAX" ]]

[[ -d "$TMPDIR" ]]
BASEDIR="${TMPDIR}/gridinit"
mkdir -p "$BASEDIR"

cat > "$BASEDIR/gridinit.conf" <<EOF
[Default]
listen=$BASEDIR/gridinit.sock
pidfile=$BASEDIR/gridinit.pid
working_dir=$BASEDIR
inherit_env=1
limit.core_size=0
limit.max_files=256
limit.stack_size=32
include=$BASEDIR/{*,*/*}.conf

EOF

for i in 0 1 2 ; do
	if ! [[ -e "$BASEDIR/$i" ]] ; then
		mkdir "$BASEDIR/$i"
	fi
done

for i in $(seq ${MAX}) ; do
	sub=$((i%3))
	cat >> $BASEDIR/$sub/service-${i}.conf <<EOF
[service.TEST-$i]
group=test-$((i%2))
on_die=respawn
enabled=true
start_at_boot=true
command=/bin/sleep "$((i+30))"
EOF
done

