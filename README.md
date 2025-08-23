# ipr-daemon
`iprd` is a ASIC listening daemon that sniffs IP Report packets from the local network.

Goals:
 - target pfsense/freebsd
 - UDP packet sniffing for various miner types
 - TCP Broadcasting
 - small CLI interface

## Building

#### FreeBSD Static binary
```bash
make build-freebsd
```


## Subscribing to TCP
By default, the TCP Broadcaster listens on port 7788.

To start listening for messages, send the message:
`{"command": "iprd_subscribe"}` after connecting to the broadcaster.
