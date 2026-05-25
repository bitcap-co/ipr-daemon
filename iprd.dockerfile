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
# auto is a switch to use the defined LAN interface (matching description of 'lan' or 'LAN') for listening
auto = false
# filter is a switch to only broadcast known ports/miner types over forward port. Excludes 'unknown' type.
filter = false
# no_root_network is a switch to remove the root network on listen_interface from BPF filter, only using networks from network_prefixes.
no_root_network = false
# listen_interface is the name of the the desired interface to listen/capture on
listen_interface = "eth0"
# forward_port is the TCP stream/broadcast port to forward packet data over
forward_port = 7788
# ignored_addrs is a list of MAC addresses to be blacklisted (useful for ignoring packets from specific network devices)
ignore_addrs = [""]
# network_prefixes is a list of network prefixes to append to BPF filter.
network_prefixes = [""]
# capture_file is the file descriptor to write received packets to in PCAP format
capture_file = ""
EOF

ENV ARGS=""
CMD /usr/local/bin/iprd ${ARGS}
