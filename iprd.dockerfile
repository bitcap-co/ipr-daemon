FROM golang:1.25-alpine AS builder

ARG VERSION

RUN apk add --update git build-base libpcap libpcap-dev && \
    mkdir ipr-daemon
COPY . ipr-daemon/

RUN cd ipr-daemon && \
    DOCKER_VERSION=${VERSION} make .docker && \
    mkdir -p /usr/local/bin && \
    cp dist/iprd /usr/local/bin/iprd

FROM alpine
RUN apk add --update libpcap && \
    mkdir -p /usr/local/bin
COPY --from=builder /usr/local/bin/iprd /usr/local/bin/
RUN cat <<EOF > /home/iprd.toml
# debug is a switch to enable packet debugging output.
debug = false
# auto is a switch to find and use the defined LAN interface for listening (OPNSense/pfSense).
# overrides listen_interfaces.
auto = false
# listen_interfaces contains the names or indexes of interfaces for listen/capture.
# At least one interface must be configured before starting the daemon.
listen_interfaces = []
# forward_bind is the local IP address to bind the TCP broadcast stream to.
# empty binds all interfaces (default).
forward_bind = ""
# forward_port is the TCP stream/broadcast port for forwarding IP report packet data.
forward_port = 7788
# forward_known is a switch to only forward IP reports from known miner types/ports over forward_port.
forward_known = false
# mdns advertises the TCP forwarding endpoint as _iprd._tcp.local. for LAN discovery.
mdns = false
# no_root_network is a switch to remove the interface network from BPF filter.
# must add additional network inclusions via network_inclusions.
no_root_network = false
# filter_known_ports is a switch to only allow packets from known miner ports.
# This is similar to forward_known but applies at the BPF filter level instead.
# Packets outside of these ports are dropped and not logged or captured.
filter_known_ports = false
# ignored_devices is a list of source MAC addresses to exclude in BPF filter.
ignored_devices = [""]
# network_inclusions is a list of networks to append in BPF filter.
# networks are IPv4 network numbers that can be written as
# dotted quad (192.168.1.0), triple (192.168.1), pair (192.168) or a single number (10).
network_inclusions = [""]
# network_exclusions is a list of networks to additionally exclude in BPF filter.
# these get appended after network_inclusions.
network_exclusions = [""]
# capture_file is a path to write received packets to in PCAP-NG format for replay/debugging.
capture_file = ""
# rotate_capture_files keeps the active capture plus three numbered history files instead of flushing it.
rotate_capture_files = false

# Per-interface BPF options overlay the global options above. The selector
# should also appear in listen_interfaces. Repeat [[interfaces]] for each interface.
# [[interfaces]]
# selector = "eth0"
# no_root_network = true
# filter_known_ports = false
# ignored_devices = ["aa:bb:cc:dd:ee:ff"]
# network_inclusions = ["192.168.1"]
# network_exclusions = ["10"]
EOF

ENV ARGS=""
CMD /usr/local/bin/iprd ${ARGS}
