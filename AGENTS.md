## AGENTS Guidance for IPR Daemon

### Project Overview
ipr-daemon serves as a LAN-wide listening daemon for ASIC miners by sniffing IP Report packets sent by miners. It broadcasts IP & MAC addresses over TCP stream/broadcast for easy integration with front-ends/monitoring tools.

### Technical Details
ipr-daemon uses the following technologies:
 - Go (>= 1.24.0)
 - libpcap (github.com/gopacket/gopacket/pcap) for packet sniffing
 - gopacket (github.com/gopacket/gopacket) for packet parsing
 - TOML (github.com/BurntSushi/toml) for configuration
 - nfpm (github.com/goreleaser/nfpm) for packaging (.deb, .rpm, etc.)
 - docker/vagrant needed for building/running in a containerized environment

 ### Project Structure
 - `cmd/` - entrypoints (ipr-daemon, iprd-offline)
 - `pkg/iprd/` -  core library for IPR daemon
 - `resources/` - services, configuration files for packaging
 - `scripts/` - included scripts for packages
 - `tests/` - unit tests for the ipr-daemon

### Build & Run
```bash
make  # builds the ipr-daemon binary
make offline # builds iprd-offline binary (validates IPR packets from pcap files)
make clean  # removes build artifacts
make clean-build  # cleans up vagrant/docker images/containers

make help  # shows available make targets
```

### Testing
```bash
make unittest
```

### Lint & formatting
```bash
make lint  # runs golangci-lint
make fmt   # runs gofmt
```

### Release
 - Bump version in Makefile - `PROJECT_VERSION`
 - ipr-daemon release workflow automatically triggers on tag push
