ARG DISTRO
FROM ubuntu:${DISTRO} as gridinit-base

LABEL maintainer "Jean-Francois SMIGIELSKI <jf.smigielski@gmail.com>"

ARG DEBIAN_FRONTEND=noninteractive
ARG DEBCONF_NONINTERACTIVE_SEEN=true

RUN set -ex && \
    echo "tzdata tzdata/Areas select Europe" > /tmp/preseed.txt; \
    echo "tzdata tzdata/Zones/Europe select Brussels" >> /tmp/preseed.txt; \
    debconf-set-selections /tmp/preseed.txt && \
    apt-get update -q && \
    apt-get install -y --no-install-recommends tzdata pkg-config software-properties-common


#------------------------------------------------------------------------------#
# Build and Install the exotic dependencies of gridinit

FROM gridinit-base as gridinit-build-deps

RUN set -ex && \
    # Deps
    apt-get update -q && \
    apt-get install -y --no-install-recommends git autoconf automake autotools-dev build-essential m4 libtool && \
    # Checkout
    cd /tmp && \
    git clone https://github.com/open-io/libdill.git && \
    cd /tmp/libdill && \
    git checkout e738f9661a5f63c219ea3a7e8627237b5fa0d9c0 && \
    # Build
    cd /tmp/libdill && \
    ./autogen.sh && \
    ./configure --prefix=/usr --enable-static --enable-shared && \
    make -j $(nproc --ignore=2) && \
    make install && \
    # Cleanup
    apt-get remove -y --purge git autoconf automake autotools-dev build-essential m4 libtool && \
    apt-get autoremove -y --purge && \
    rm -rf /tmp/libdill

ENTRYPOINT ["/bin/bash"]


#------------------------------------------------------------------------------#
# Install the sources and the minimal tooling to build gridinit

FROM gridinit-build-deps

RUN set -ex && \
    apt-get update -q && \
    apt-get install -y --no-install-recommends cmake clang gcc jq libglib2.0-dev make pkg-config

RUN set -ex && \
    mkdir /tmp/src

COPY main /tmp/src/main/
COPY CMakeLists.txt /tmp/src/
COPY docker/build.sh /tmp/

CMD ["/tmp/build.sh"]

