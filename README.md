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

### Linux/Debian setup
The Linux binary is statically built (no `libpcap` needed on the target) and can be
installed as a systemd service via a `.deb` package.

Build the package (compiles the static Linux/amd64 binary in Docker first):
```bash
make deb-package            # produces dist/iprd_<version>_amd64.deb
```
then copy it to the target and install:
```bash
scp dist/iprd_<version>_amd64.deb target:
ssh target
sudo dpkg -i ./iprd_<version>_amd64.deb
```
This installs `/usr/bin/iprd`, the systemd unit `/etc/systemd/system/iprd.service`,
and the config `/etc/iprd.conf`, then enables + starts the service. Remove with
`sudo dpkg -r iprd`.

Once installed, the service is controlled with `sudo systemctl {start|stop|status} iprd`.
Arguments are passed via the `ARGS=` line in `/etc/iprd.conf` (defaults to `-a`); run
`sudo systemctl restart iprd` after editing. Your edits to `/etc/iprd.conf` are
preserved across package upgrades.

### FreeBSD/pfSense/OPNsense setup
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

### Docker
A pre-built image is published to Docker Hub at
[`mattwert/ipr-daemon`](https://hub.docker.com/r/mattwert/ipr-daemon).

Because iprd sniffs packets across the LAN, the container must run on the **host
network**. The simplest run uses auto interface detection (`-a`):
```bash
docker run -d --name ipr-daemon --network host -e ARGS="-a" mattwert/ipr-daemon:latest
```
`ARGS` accepts any iprd flags (e.g. `-e ARGS="-i eth0 -p 7788"`); see `iprd -h`.

To configure via a TOML file instead, mount your own config and point iprd at it
(the image ships a sample at `/home/iprd.toml`):
```bash
docker run -d --name ipr-daemon --network host \
  -v ./default.toml:/home/iprd.toml \
  mattwert/ipr-daemon:latest /usr/local/bin/iprd -c /home/iprd.toml
```

Or with Docker Compose (see `compose.yaml`):
```bash
# optionally set CONFIG_PATH to your own TOML config (defaults to ./default.toml)
CONFIG_PATH=./default.toml docker compose up -d
```

> [!NOTE]
> Host networking is required so the daemon can see LAN traffic. If packet capture
> fails, the container may also need the `NET_ADMIN` capability
> (`--cap-add=NET_ADMIN`) to put the interface into promiscuous mode.

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

By default the TCP stream binds all interfaces. On a multi-homed host you can restrict
it to a single local IP with `-b`:
```bash
sudo ./iprd -i "eth0" -b 192.168.1.10
```
To retain capture history, enable capture rotation together with a capture path:
```bash
sudo ./iprd -i "eth0" -capture-file /var/log/iprd/capture.pcap -rotate-capture
```
Each capture is limited to 4 MiB. Rotation keeps four files total: the active
`capture.pcap`, then `capture.1.pcap` through `capture.3.pcap` from newest to
oldest. Without `-rotate-capture`, the active capture is flushed at 4 MiB
as before. TOML configurations can enable the same behavior with
`rotate_capture_files = true`.

To make the TCP endpoint discoverable by applications on the same LAN, enable
mDNS/DNS-SD advertisement:
```bash
sudo ./iprd -i "eth0" -mdns
```
This publishes `_iprd._tcp.local.` with the daemon's hostname, configured TCP
port, and subscription metadata. TOML configurations can use `mdns = true`.
Discovery can be verified with Avahi on Linux or `dns-sd` on macOS:
```bash
avahi-browse -rt _iprd._tcp
# or
dns-sd -B _iprd._tcp local.
```
mDNS is link-local multicast, so discovery normally stays within the same
LAN/VLAN unless the network has an mDNS reflector. No secrets are included in
the advertised TXT records.

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
