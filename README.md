# Gridinit

Gridinit is a tool used to manage non-daemon processes.

## Build

### Dependencies

* cmake, make, gcc
* glib, glib-devel
* libdill (currently embedded)

### Compile-time configuration

| Macro | Default | Description |
| ----- | ------- | ----------- |
| GRIDINIT_SOCK_PATH | /var/run/gridinit.sock | Path used for the socket on both server and client side, when no path is specified in the configuration. |

