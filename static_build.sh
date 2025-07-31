#!/bin/sh
##
## build static binary for freebsd

CGO_ENABLED=1 sudo go124 build -tags netgo -ldflags "-linkmode 'external' -extldflags '-static -libverbs -lpcap'" -o iprd cmd/main.go
