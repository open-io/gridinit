#!/usr/bin/env bash
set -ex

for DISTRO in trusty xenial bionic focal ; do
    docker build --build-arg DISTRO=${DISTRO} --tag gridinit-test-${DISTRO} -f docker/Dockerfile .
    docker run gridinit-test-${DISTRO}
done

# Unsupported: ubuntu:{yakkety,zesty,artful,cosmic,disco,eoan,groovy}
