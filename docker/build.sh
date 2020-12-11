#!/usr/bin/env bash
set -ex

COMPILERS=$@
if [[ -z "${COMPILERS}" ]] ; then
    COMPILERS="gcc clang"
fi

NPROCS=$(nproc --ignore=2)

for BUILD in Debug Release RelWithDebInfo MinSizeRel ; do
    for COMPILER in $COMPILERS ; do 
        TAG="${BUILD}-${COMPILER}"
        D=/tmp/build-${TAG}
        mkdir ${D}
        cd ${D}
        export CC=${COMPILER}
        cmake -DCMAKE_INSTALL_PREFIX=/tmp/install-${TAG} -DCMAKE_BUILD_TYPE=${BUILD} /tmp/src
        make -j $NPROCS
        make install
    done
done

