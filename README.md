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

## Getting started
The pre-built binaries in Release are statically built whereever possible. meaning that all the needed libraries/dependencies are already included with the binary. However, on some operating systems, static binaries are not supported which means that some dependencies may be required to be installed manually

If using Windows or MacOS/darwin binaries, `libpcap` is required on the system to run succussfully.

### Windows setup
It recommended to install [Npcap for Windows](https://npcap.com/#download)

### MacOS/darwin setup
Install `libpcap` via Brew:
```bash
brew install libpcap
```

### FreeBSD/pfSense setup
The FreeBSD binary is statically built (no `libpcap` needed on the target) and can
be installed as an rc service two ways.

**Packaged install (recommended).** Build a native `.pkg` from the Vagrant VM:
```bash
make freebsd-package        # produces dist/iprd-<version>.pkg
```
then copy it to the target and install:
```bash
scp dist/iprd-<version>.pkg target:
ssh target
pkg add ./iprd-<version>.pkg
```
This installs `/usr/local/sbin/iprd`, registers the rc service at
`/usr/local/etc/rc.d/iprd`, and enables + starts it. Remove with `pkg delete iprd`.

> [!NOTE]
> `pkg add` refuses on an ABI mismatch (e.g. a different FreeBSD major, or some
> pfSense builds). Use `pkg add -f ./iprd-<version>.pkg` to force the install.

**Manual install.** Copy the binary and the installer script to the target and run
it as root:
```bash
scp dist/iprd-<version>-freebsd-amd64 target:iprd
scp resources/freebsd/install-freebsd.sh target:
ssh target
su -
./install-freebsd.sh
```
This lands the binary in `/usr/local/sbin/`, writes the rc service, enables it via
`sysrc iprd_enable=YES`, and starts it.

Once installed, the service is controlled with `service iprd {start|stop|status}`.
Extra arguments can be passed via `iprd_flags="..."` in `/etc/rc.conf`.

## Usage

### Finding network interfaces to listen on
To see all available network interfaces that the daemon can listen on, run with the `-list` argument:
```
./iprd -list

# example output
3: eth0 (eth0) Desc:""
   Hardware:aa:bb:cc:dd:ee:ff
   IPv4:192.168.1.xx
```
Using the interface index (3) or the name ("eth0"), can specifiy which interface to listen on with the `-i` option
```bash
sudo ./iprd -i "eth0"
```
where, `-i` is specifying the system interface name or index to listen on.

It also worth noting that `iprd` requires running under the `root` user to run.

To configure the TCP stream port, use `-p` to supply:
```bash
sudo ./iprd -i "eth0" -p <SOME_PORT>
```
Also see `iprd -h` for a list of all available options.

> [!NOTE]
> MacOS: if you get a message along the lines of "this application is damaged" or similar, run the following as root to exclude the binary path from the anti-virus:
> ```bash
> sudo xattr -dr com.apple.quarantine </path/to/iprd/binary>
> ```

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

## iprd (package)
The core tooling/functionality of IPR Daemon can be found in `pkg/iprd`.
See [README](./pkg/iprd/README.md) for more details on how to use within your own programs!

For documentation, see:
```bash
go doc -http ./pkg/iprd
```

To include into a local project:
```
go get github.com/bitcap-co/ipr-daemon
```
then to import the `iprd` package, simply import:
```go
import "github.com/bitcap-co/ipr-daemon/pkg/iprd"
```
