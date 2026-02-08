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

#### Debian Static binary
```bash
make build-debian
```


## Subscribing to TCP broadcast
By default, the TCP Broadcaster listens on port 7788.

To start listening for messages, send the message:
`{"command": "iprd_subscribe"}` after connecting to the broadcaster.

One can subscribe to the broadcast by running `cmd/example/tcp_listener.go` or using netcat as follows:
```bash
echo '{"command": "iprd_subscribe"}' | nc localhost 7788
```
May replace `localhost` with host IP address.
