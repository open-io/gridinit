#!/usr/bin/env bash
set -e
set -x

CMD="gridinit_cmd -S /tmp/gridinit/gridinit.sock"

$CMD status

for G in @test-0 @test-1 '' '@test-0 @test-1' ; do
	$CMD status $G
	$CMD stop $G
	$CMD start $G
	$CMD status $G
done

$CMD status

