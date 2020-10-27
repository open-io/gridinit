# Gridinit

Gridinit is a tool used to manage non-daemon processes.

## Dependencies

* A toolchain made of [cmake](https://cmake.org),
  [make](https://www.gnu.org/software/make/),
  [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/),
  [gcc](https://www.gnu.org/software/gcc/) or [clang](https://clang.llvm.org/)
* The [GNome Library](https://developer.gnome.org/glib/stable/)
* [Martin Sustrik's libdill](https://github.com/open-io/libdill)

## Build

Building ``gridinit`` is configured by ``cmake``, done by ``make`` and requires
that ``libdill`` is installed ans its installation paths are configured with
``pkg-config``.

```shell script
cmake -D GRIDINIT_SOCK_PATH=/tmp/gridinit.sock .
make
```

But ``libdill`` is rarely available in mainstream Linux distributions, so here
are the build instructions to build it from the ``git submodule``:

```shell script
git submodule update --init --recursive
cd vendor/libdill
./autogen.sh
./configure --prefix=/usr --enable-shared --disable-static --enable-tls --enable-threads
make
sudo make install
```

## Compile-time Configuration

| Macro | Default | Description |
| ----- | ------- | ----------- |
| GRIDINIT_SOCK_PATH | /var/run/gridinit.sock | Path used for the socket on both server and client side, when no path is specified in the configuration. |

## Try it

```
./gridinit -d ./gridinit.conf
./gridinit_cmd status
./gridinit_cmd status2
./gridinit_cmd status3
./gridinit_cmd status @NS0
./gridinit_cmd status @NS1
./gridinit_cmd status @local
./gridinit_cmd status @local @NS1 @NS0
./gridinit_cmd stop
./gridinit_cmd start
```

