SHELL=/bin/bash -o pipefail

BUILDVARS = CGO_ENABLED=1

.PHONY: build-freebsd
build-freebsd:
	$(BUILDVARS) go build -tags netgo -ldflags "-linkmode 'external' -extldflags '-static -libverbs -lpcap'" -o iprd cmd/main.go

.PHONY: build-debian
build-debian:
	go build -tags netgo -ldflags "-linkmode 'external' -extldflags '-static -ldbus-1 -lsystemd -lpcap -lcap -libverbs -lnl-route-3 -lnl-3'" -o iprd cmd/main.go
