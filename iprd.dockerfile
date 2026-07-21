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
# auto is a switch to find and use the defined LAN interface (description matching 'lan/LAN') for listening.
# overrides listen_inteface.
auto = false
# listen_inteface is the name or index of interface for listen/capture.
listen_interface = "eth0"
# forward_port is the TCP stream/broadcast port for forwarding IP report packet data.
forward_port = 7788
# forward_known is a switch to only forward IP reports from known miner types/ports over forward_port.
forward_known = false
# mdns advertises the TCP forwarding endpoint as _iprd._tcp.local. for LAN discovery.
mdns = false
# no_root_network is a switch to not include the interface network in BPF filter.
no_root_network = false
# ignored_devices is a list of source MAC addresses to exclude in BPF filter.
ignored_devices = [""]
# network_inclusions is a list of networks to append in BPF filter.
# networks are IPv4 network numbers that can be written as
# dotted quad (192.168.1.0), triple (192.168.1), pair (192.168) or a single number (10).
network_inclusions = [""]
# network_exclusions is a list of networks to additionally exclude in BPF filter.
# these get appended after network_inclusions.
network_exclusions = [""]
# capture_file is a path to write received packets to in PCAP format for replay/debugging.
capture_file = ""
# rotate_capture_files keeps the active capture plus three numbered history files instead of flushing it.
rotate_capture_files = false
EOF

ENV ARGS=""
CMD /usr/local/bin/iprd ${ARGS}
