## ipr-daemon
IPR Daemon (later referred to as iprd) is an ASIC miner listener, sniffing IP report messages live on the wire from a LAN.

## Overview
iprd serves as a LAN-wide listening backend for ASIC miners by sniffing IP report packets sent by the miners. It captures the received IP & MAC addresses along with the miner type over an TCP stream for easy reading and integration with front-ends/applications like its sister project [bitcap-ipr](https://github.com/bitcap-co/bitcap-ipr).

## How it works
iprd is designed to run on a local server/PC with direct access to the LAN. Instead of running UDP listeners on specific ports, it looks at ALL local UDP packets in real-time and processes each one to determine if its a valid IP report packet.

Effectively, works exactly like [WireShark](https://www.wireshark.org/) but specificly for IP Report packets.

As it receives IP Report messages, it will send the data over a TCP broadcast/stream that is accessible over an configurable port (default: port 7788).

## Highlights of iprd
 - IP Report listening/sniffing across LAN (even miners within VLANS!)
 - TCP Broadcasting for easy front-end/app integration
 - Duplicate packet handling
 - Wide OS support

## Building
Currently, it supports UNIX-based distros (FreeBSD/pfSense/OPNsense, Ubuntu, MacOS) and Windows!
Pre-built binaries are available in Releases!

### Build dependencies
  - Go (>=1.24.0)
  - make (Optional)

To build locally, simply run
```bash
go build -o iprd cmd/main.go
# or
make
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

See `iprd -h` for all available options.

## Subscribing to TCP broadcast
By default, the TCP broadcast listens on port 7788.

To start listening for messages, send the message `{"command": "iprd_subscribe"}` after initial connection to the broadcast.

See `cmd/example/tcp_listener.go` for an example golang implementation or can use netcat `nc`:
```bash
echo '{"command": "iprd_subscribe"}' | nc localhost 7788
```
Replacing `localhost` with host IP address if required.

## Miner Support
In theory, it should receive any ASIC miner IP Report message since it isn't bound to any specific UDP ports.

The only thing that iprd looks at is the destination port of the packet for a known ASIC miner "hint" (not all miner types have unique port destinations) and the data payload for if it contains its own source IP address.

This is designed to be as open-ended as possible to accept any IP Report message/output from ASIC miners. One caveat is the possibility of false positives from other devices on the network.

### Current list of known miner ports:
```go
minerPorts  = map[int]MinerTypeHint{
		14235: Antminer, // Assume antminer but could be a multitude of miner types (i.e. Volcminer, Hammer)
		11503: Iceriver,
		8888:  Whatsminer,
		1314:  Goldshell,
		18650: Sealminer,
		9999:  Elphapex,
		12345: Auradine,
}
```
