## ipr-daemon
IPR Daemon (later referred to as iprd) is an ASIC miner listener, sniffing IP report messages live on the wire from a LAN.

## Overview
iprd serves as a LAN-wide listening solution for ASIC miner listening by sniffing IP report packets sent by the miners. It captures the received IP & MAC addresses along with the miner type over an TCP stream for easy reading and integration with front-ends/applications like its sister project [bitcap-ipr](https://github.com/bitcap-co/bitcap-ipr).

## How it works
iprd is designed to run on a local server/PC with direct access to the LAN. Instead of running UDP listeners on specific ports, it looks at ALL local UDP packets in real-time and processes each one to see if it is an IP Report packet.

Effectively, works exactly like [WireShark](https://www.wireshark.org/) but specificly for IP Report packets.

As it receives IP Report messages, it will send the data over a TCP broadcast/stream that is accessible over an configurable port (default: port 7788).

## Building
Currently, it supports UNIX-based distros (FreeBSD, Ubuntu, MacOS) and Windows!

Ubuntu pre-built binaries are available in Releases!

### Build dependencies
  - Go (>=1.24.5)
  - make (Optional)

To build locally, simply run
```bash
go build -o iprd cmd/main.go
```

### Static binaries
  - FreeBSD
```bash
make build-freebsd
```
 - Debian-based Linux
```bash
sudo apt install libpcap-dev libcap-dev librdmacm-dev libibverbs-dev
make build-debian
```

## Usage
> [!WARNING]
> This program does require root permissions to run. 

Once built (and marked at executable!), simply run:
```bash
sudo ./iprd -i "eth0"
```
where, `-i` is the system interface name that you want to listen on.
> [!NOTE]
> On Windows, supply the network device name (i.e. "Ethernet Instance 0"). Run `ipconfig` in cmd/pwsh to see all interface names.

To configure the TCP port, use `-p` to supply:
```
sudo ./iprd -i "eth0" -p <SOME_PORT>
```

## Subscribing to TCP broadcast
By default, the TCP broadcast listens on port 7788.

To start listening for messages, send the message `{"command": "iprd_subscribe"}` after initial connection to the broadcast.

See `cmd/example/tcp_listener.go` for an example golang implementation or can use netcat `nc`:
```bash
echo '{"command": "iprd_subscribe"}' | nc localhost 7788
```
Replacing `localhost` with host IP address if required.
