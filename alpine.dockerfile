FROM golang:1.25-alpine
ENV PROJECT=ipr-daemon

# build-base gives the musl gcc toolchain; libpcap-dev provides headers + static lib.
RUN apk add --update --no-cache git build-base make pkgconfig libpcap libpcap-dev && \
    mkdir -p /build
WORKDIR /build
COPY . /build/$PROJECT/
WORKDIR /build/$PROJECT

# builds a fully static musl binary into dist/ (mounted from the host); the target
# (.linux-musl-amd64 / .linux-musl-arm64) is passed as the run argument.
ENTRYPOINT ["make"]
CMD [".linux-musl-amd64"]
