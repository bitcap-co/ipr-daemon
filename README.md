## ipr-daemon
IPR Daemon (later referred to as IPRD) is an ASIC miner listener, sniffing IP report messages live on the wire from a LAN.

## Overview
iprd serves as a LAN-wide listening backend for ASIC miners by sniffing IP report packets sent by the miners. It captures the received IP & MAC addresses along with the miner type over an TCP stream for easy reading and integration with front-ends/applications like its sister project [bitcap-ipr](https://github.com/bitcap-co/bitcap-ipr).

## How it works
IPRD is designed to run on a local server/container with direct access to the LAN. Instead of running UDP listeners on specific ports, it looks at ALL local UDP packets in real-time and processes each one to determine if its a valid IP report packet.

Effectively, works exactly like [WireShark](https://www.wireshark.org/) but specificly for IP Report packets.

As it receives IP Report messages, it will send the data over a TCP broadcast/stream that is accessible over an configurable port (default: port 7788).

## Highlights of IPRD
 - IP Report listening/sniffing across LAN (even miners within VLANS!)
 - TCP Broadcasting for easy front-end/app integration
 - Duplicate packet handling
 - Wide OS support

## Building
Currently, IPRD is available for UNIX-based distros (FreeBSD/pfSense/OPNsense, Ubuntu, MacOS) and Windows!
Pre-built binaries and packages are available in [Releases](https://github.com/bitcap-co/ipr-daemon/releases)!

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
Binaries are built statically wherever possible, meaning that all the needed libraries/dependencies (e.g. `libpcap`) are already included in the binary itself. However, particularly Windows and MacOS/darwin, dependencies may need to be installed manually.

Below shows necessary steps for each operating system:

### Windows Prerequisites
For best support for Windows, install [Npcap for Windows](https://npcap.com/#download)

### MacOS/darwin Prerequisites
For best support for MacOS, install `libpcap` via Brew:
```bash
brew install libpcap
```

### Linux (Debian/RedHat) Setup
Linux binaries are statically built (no `libpcap` needed on the target) and can be
installed as a systemd service via a `.deb`/`.rpm` package.

Build the package (compiles the static Linux amd64/arm64 binary in Docker first):
```bash
make deb-package            # produces dist/iprd_<version>_amd64.deb
make rpm-package            # produces dist/iprd-<version>-1.x86_64.rpm
make deb-package-arm64      # produces dist/iprd_<version>_arm64.deb
make rpm-package-arm64      # produces dist/iprd-<version>-1.arm64.rpm
```
then install:
```bash
sudo dpkg -i ./iprd_<version>_<arch>.deb
# or
sudo rpm -i ./iprd-<version>-<arch>.rpm
```
This installs `/usr/bin/iprd`, the systemd unit `/etc/systemd/system/iprd.service`,
and the config `/etc/iprd.conf`, then enables + starts the service. Remove with
`sudo dpkg -r iprd` or `sudo rpm -e iprd`.

Once installed, the service is controlled with `sudo systemctl {start|stop|status} iprd`.
Arguments are passed via the `ARGS=` line in `/etc/iprd.conf` (defaults to `-a`); run
`sudo systemctl restart iprd` after editing. Your edits to `/etc/iprd.conf` are
preserved across package upgrades.

### FreeBSD/pfSense/OPNsense setup
The FreeBSD binary is statically built (no `libpcap` needed on the target) and can
be installed as an rc service.

Build a native `.pkg` from the Vagrant VM:
```bash
make freebsd-package        # produces both amd64/arm64 packages in dist/iprd-<version>-<arch>.pkg
```
then install:
```bash
pkg add ./iprd-<version>-<arch>.pkg
```
This installs `/usr/local/sbin/iprd`, registers the rc service at
`/usr/local/etc/rc.d/iprd`, and enables + starts it. Remove with `pkg delete iprd`.

> [!NOTE]
> `pkg add` refuses on an ABI mismatch (e.g. a different FreeBSD major, or some
> pfSense builds). Use `pkg add -f ./iprd-<version>.pkg` to force the install.

### Docker container
Prebuilt Linux amd64/arm64 images are published to Docker Hub at
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

## IPR Daemon CLI

### Finding interfaces
To see all available network interfaces that the daemon can listen on, run with the `-list` argument:
```
./iprd -list

# example output
3: eth0 (eth0) Desc:""
   Hardware:aa:bb:cc:dd:ee:ff
   IPv4:192.168.1.xx
```
Using an interface index or name, specify one or more interfaces with `-i`.
The flag supports chaining and comma-separated values:
```bash
sudo ./iprd -i "eth0" -i "eth1"
sudo ./iprd -i "eth0,eth1"
```
Each interface has an independent capture and reconnect loop. Packets are
processed through one duplicate record, capture file, and TCP broadcast stream.

It also worth noting that `iprd` requires running under the `root` user to run.

### Modifying BPF filters
IPRD CLI allows direct modification of BPF filters for interfaces to add/exclude networks and ignoring specific devices on the network.

Available global BPF interface (applies to all interfaces):
 - `-add-network <NETWORK>` - Append a IPv4 network number to BPF filter. (i.e. -add-network 172.16,192.168.1,10). Can be used multple times or comma-separated values.
 - `-no-root-network` - By default, the "root" network of interface is included in the BPF filter. Use this flag to exclude it. `add-network` must follow this flag if supplied.
 - `-exclude <NETWORK>` - Exclude a IPv4 network number from BPF filter. Can be used multple times or comma-separated values.
 - `-ignore <MAC_ADDR>` - Ignore a specific network device (MAC Address) from BPF filter. Can be used multple times or comma-separated values.

 For configuring interface-specific BPF filters, options similar to the global flags can be used like so:
```bash
sudo ./iprd -i eth0:no-root-network,add-network=172.16 \ # exclude root network and add 172.16 for eth0
    -i eth1:add-network=10,exclude=192.168.1 \ # exclude 192.168.1 for eth1
    -ignore "aa:bb:cc:dd:ee:ff" # global flags can also be used in conjuntction! ignore MAC address aa:bb:cc:dd:ee:ff for both interfaces.
```

### Configuring TCP Stream/Broadcast
To configure the TCP stream port, use `-p` to supply:
```bash
sudo ./iprd -i "eth0" -p <SOME_PORT>
```

By default the TCP stream binds all interfaces. On a multi-homed host you can restrict
it to a single local IP with `-b`:
```bash
sudo ./iprd -i "eth0" -b 192.168.1.10
```

### Enabling MDNS Advertisement
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

### Capturing
To retain capture history, enable capture rotation together with a capture path:
```bash
sudo ./iprd -i "eth0" -capture-file /var/log/iprd/capture.pcapng -rotate-capture
```
Captures are written in PCAP-NG format so packets retain their source interface.
A supplied extension such as `.pcap` is normalized to `.pcapng`. Each capture is
limited to 4 MiB. Rotation keeps four files total: the active `capture.pcapng`,
then `capture.1.pcapng` through `capture.3.pcapng` from newest to oldest. Without
`-rotate-capture`, the active capture is flushed at 4 MiB. TOML configurations
can enable the same behavior with `rotate_capture_files = true`. Existing classic
PCAP captures remain readable with `iprd-offline`.

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
	54321: IPollo,
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
