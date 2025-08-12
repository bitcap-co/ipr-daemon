SHELL=/bin/bash -o pipefail

BUILDVARS = CGO_ENABLED=1

.PHONY: build-freebsd
build-freebsd:
	$(BUILDVARS) go build -tags netgo -ldflags "-linkmode 'external' -extldflags '-static -libverbs -lpcap'" -o iprd cmd/main.go
