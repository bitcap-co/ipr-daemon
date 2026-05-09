FROM ubuntu:24.04 AS base
ENV DEBIAN_FRONTEND=noninteractive
ENV PROJECT=ipr-daemon
ENV LIBPCAP_VERSION=1.10.3
ENV AARCH64_SYSROOT=/build/sysroot/aarch64
ENV ARMV5_SYSROOT=/build/sysroot/armv5
ENV ARMV6_SYSROOT=/build/sysroot/armv6
ENV ARMV7_SYSROOT=/build/sysroot/armv7

RUN apt-get update && \
    apt-get install -y wget flex bison make git gcc \
        gcc-aarch64-linux-gnu \
        gcc-arm-linux-gnueabi \
        golang-1.24-go file && \
    apt-get clean
RUN mkdir -p /build $AARCH64_SYSROOT $ARMV5_SYSROOT $ARMV6_SYSROOT $ARMV7_SYSROOT

FROM base
WORKDIR /build
COPY . /build/$PROJECT/

RUN wget -qO - https://tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz | tar zvxf -
WORKDIR /build/libpcap-$LIBPCAP_VERSION

# aarch64
RUN ./configure --host=aarch64-linux-gnu --with-pcap=linux --disable-dbus \
        --prefix=$AARCH64_SYSROOT && \
    make && make install && make distclean

# armv5 (soft-float ABI)
RUN ./configure --host=arm-linux-gnueabi --with-pcap=linux --disable-dbus \
        --prefix=$ARMV5_SYSROOT CFLAGS="-march=armv5te" && \
    make && make install && make distclean

# armv6 (soft-float ABI -- Ubuntu's gnueabihf has no armv6 multilib)
RUN ./configure --host=arm-linux-gnueabi --with-pcap=linux --disable-dbus \
        --prefix=$ARMV6_SYSROOT CFLAGS="-march=armv6" && \
    make && make install && make distclean

# armv7 (soft-float ABI)
RUN ./configure --host=arm-linux-gnueabi --with-pcap=linux --disable-dbus \
        --prefix=$ARMV7_SYSROOT CFLAGS="-march=armv7-a" && \
    make && make install && make distclean

WORKDIR /build/$PROJECT
ENV GOROOT=/usr/lib/go-1.24
ENV PATH=/build/bin:${GOROOT}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ENTRYPOINT ["make"]
CMD [".linux-arm64"]
