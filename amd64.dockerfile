FROM ubuntu:24.04 AS base
ENV DEBIAN_FRONTEND=noninteractive
ENV PROJECT=ipr-daemon

RUN apt-get update && \
    apt-get install -y libpcap-dev libcap-dev librdmacm-dev libibverbs-dev libsystemd-dev make git gcc golang-1.24-go && \
    apt-get clean
RUN mkdir -p /build

FROM base
WORKDIR /build
COPY . /build/$PROJECT/

WORKDIR /build/$PROJECT
ENV GOROOT=/usr/lib/go-1.24
ENV PATH=/build/bin:${GOROOT}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ENTRYPOINT [ "make", ".linux-amd64" ]
