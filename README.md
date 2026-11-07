## ipr-daemon
IPR Daemon is an ASIC miner listening backend targetting the IP report packets sent by miners within a LAN.

## Overview
IPR Daemon serves as a LAN-wide listening backend for ASIC miners by sniffing IP report packets sent via IP report button. It processes UDP packets live on the wire and sends back the identifying information (i.e. IP, MAC and miner type) over a TCP JSON broadcast for easy reading/integration with front-ends/applications. 
Check out it's sister project [bitcap-ipr](https://github.com/bitcap-co/bitcap-ipr) as an example.

## How it works
IPR Daemon is designed to run on a local node with direct access to the LAN. It listens on one or more interfaces for local UDP packets and processes each one in real-time for valid IP report packets. 

When a valid IP report packet is received, It will send over the relevant data over a TCP-JSON broadcast that is accessible over a configurable port (default: port 7788).

## Features/Support
 - IP report listening/sniffing across LAN (even miners within VLANs)
 - Duplicate packet handling
 - Listen on one or more interfaces with configurable BPF filters
 - TCP-JSON broadcasting/forwarding over configurable address/port
 - Capture live packets to .pcagng files
 - Opt-in MDNS advertising for service discovery
 - Wide device support 
    - FreeBSD (amd64/arm64) - pfSense/OPNsense
    - Linux (amd64/arm64/armv5/armv6/armv7)
    - MacOS (amd64/arm64)
    - Windows (amd64)
    - Docker (amd64/arm64) - Linux container image

## Getting started
Currently, IPR Daemon is available for UNIX-based distros (FreeBSD/pfSense/OPNsense, Ubuntu, MacOS) and Windows! Pre-built binaries and packages are available in [Releases](https://github.com/bitcap-co/ipr-daemon/releases)!

Prebuilt Linux amd64/arm64 container images are published to Docker Hub at [`mattwert/ipr-daemon`](https://hub.docker.com/r/mattwert/ipr-daemon).

Binaries are built statically wherever possible, meaning that all the needed libraries/dependencies (e.g. `libpcap`) are already included in the binary itself. Windows requires Npcap to be installed separately; macOS uses its native system libpcap.

Below shows necessary steps for each operating system:

### Windows Prerequisites
For best support for Windows, install [Npcap for Windows](https://npcap.com/#download)

## Building/Installation
### Build prerequisites
  - Go (>=1.25.0)
  - libpcap (provided by macOS/npcap for Windows; install the development package on other platforms)
  - make

To build locally, simply run
```bash
go build -o iprd ./cmd
# or
make
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
This installs `/usr/bin/iprd`, the systemd unit, and `/etc/iprd.conf`, then
enables the service. If `/etc/iprd/config.toml` exists, the service is also
started; otherwise run `sudo iprd -setup` followed by `sudo systemctl start iprd`.
Remove with `sudo dpkg -r iprd` or `sudo rpm -e iprd`.

Once installed, the service is controlled with `sudo systemctl {start|stop|status} iprd`.
The `IPRD_CONFIG=` value in `/etc/iprd.conf` can override the default configuration
path. The service cleanly remains inactive when that file is absent. Edits to
`/etc/iprd.conf` are preserved across package upgrades. Service output is stored
in the systemd journal and can be read with `journalctl -u iprd`;
`/var/log/iprd` is created for packet captures.

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
`/usr/local/etc/rc.d/iprd`, and enables it. If
`/usr/local/etc/iprd/config.toml` exists, the service is also started; otherwise
run `iprd -setup` followed by `service iprd start`. Set `iprd_config` in
`/etc/rc.conf` to override the configuration path. Service output is written to
`/var/log/iprd/iprd.log`, alongside the default capture location. Remove with
`pkg delete iprd`.

### Docker container
Prebuilt Linux amd64/arm64 images are published to Docker Hub at
[`mattwert/ipr-daemon`](https://hub.docker.com/r/mattwert/ipr-daemon).

Because IPR Daemon sniffs packets across the LAN, the container must run on the **host
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

## Known Issues & Workarounds
 - MacOS binary is damaged/unknown source
  > For MacOS, if you get a message along the lines of "this application is damaged" or similar, run the following as root to exclude the binary path from the anti-virus:
  > ```bash
  > sudo xattr -dr com.apple.quarantine </path/to/iprd/binary>
  > ```

## IPR Daemon CLI Usage/Configuration
See [`cmd/README.md`](cmd/README.md) for more details on initial configuration and CLI usage.

## Subscribing to TCP broadcast
By default, the TCP broadcast listens on port 7788.

To start listening for messages, send the message `{"command": "iprd_subscribe"}` after initial connection to the broadcast.

See `cmd/example/tcp_listener.go` for an example golang implementation or can use netcat `nc`:
```bash
echo '{"command": "iprd_subscribe"}' | nc localhost 7788
```
Replacing `localhost` with host IP address if required.

## Querying daemon status

The same TCP endpoint supports a one-shot status request. Send `iprd_status`
on a new connection to receive the current listener state and cumulative diagnostics:

```bash
echo '{"command": "iprd_status"}' | nc localhost 7788
```

The `iprd` binary can query and format this response directly:

```bash
iprd -status
iprd -status-json
```

Use `-b` and `-p`, or `-c` with the daemon's TOML configuration, to select a
non-default endpoint. Status requests are separate from subscriptions and the
server closes the request connection after sending one response.

The TCP endpoint is unauthenticated. Both report subscriptions and status
requests should only be exposed to a trusted LAN. Bind to localhost with
`-b 127.0.0.1` or restrict the port with a firewall when remote access is not
required; status responses include interface names and recent listener errors.

## Miner Support
The daemon isn't bound to any specific UDP ports by default, so it can receive any IP report message from ANY source. Any packet containing its own source IP address in the payload is deemed as a valid IP report packet to be forwarded. While this approach allows the daemon to be miner-agnostic, it may result in false positives being forwarded from other devices on the network.

However, this can be refined as needed with further configuration via the CLI (see [Modifying BPF filters](./cmd/README.md#modifying-bpf-filters) or available filtering options in `iprd -h`).

Instead of explicitly handling each miner's specific packet format, the daemon uses a lookup table to map destination ports to miner types. This allows the daemon to forward valid IP report packets from any source, while still providing a type hint for the miner if known.

### Known Miners:
```go
minerPorts = map[int]MinerTypeHint{
	14235: Antminer, // Known common port for other miner types as well (blackminer/hammer)
	11503: Iceriver,
	8888:  Whatsminer,
	1314:  Goldshell,
	18650: Sealminer,
	9999:  Elphapex,
	12345: Auradine,
	54321: IPollo,
	42069: HiveGPU, // Custom port for HiveOS
	6667:  IBeLink,
}
```

## Getting Started with iprd (package)
All the core functionality of IPR Daemon can be found in `pkg/iprd`.
See [README](./pkg/iprd/README.md) to get familiar with the package and learn how to use it within your own programs!

For the latest documentation, run in the `ipr-daemon` project:
```bash
go doc -http ./pkg/iprd
```
or can browse online at [pkg.go.dev](https://pkg.go.dev/github.com/bitcap-co/ipr-daemon/pkg/iprd)

### Importing
To include into a local project, download this repository:
```bash
go get github.com/bitcap-co/ipr-daemon
```
then import the `iprd` package:
```go
import "github.com/bitcap-co/ipr-daemon/pkg/iprd"
```

iprd's configuration library is separate pcap-free sub-package of `iprd` at `iprd/config`.

To use the config library, import it as follows:
```go
import (
	iprdconfig "github.com/bitcap-co/ipr-daemon/pkg/iprd/config"
)
```
