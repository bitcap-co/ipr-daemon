FROM ubuntu:24.04 AS base
ENV DEBIAN_FRONTEND=noninteractive
ENV PROJECT=ipr-daemon
ENV LIBPCAP_VERSION=1.10.3

RUN apt-get update && \
    apt-get install -y wget flex bison make git gcc golang-1.24-go && \
    apt-get clean
RUN mkdir -p /build

FROM base
WORKDIR /build
COPY . /build/$PROJECT/

# setup libpcap
RUN wget -qO - https://tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz | tar zvxf -
WORKDIR /build/libpcap-$LIBPCAP_VERSION
RUN ./configure --disable-dbus
RUN make && make install

WORKDIR /build/$PROJECT
ENV GOROOT=/usr/lib/go-1.24
ENV PATH=/build/bin:${GOROOT}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ENTRYPOINT [ "make", ".linux-amd64" ]
