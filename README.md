# Gridinit

Gridinit is a tool used to manage non-daemon processes.

## Build

```
cmake -D GRIDINIT_SOCK_PATH=/tmp/gridinit.sock .
make
```

### Dependencies

* cmake, make, gcc
* glib, glib-devel
* libdill (currently embedded)

### Compile-time configuration

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

