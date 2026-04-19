DIST_DIR ?= dist/
GOOS ?= $(shell uname -s | tr "[:upper:]" "[:lower:]")
GOARCH ?= $(shell uname -m | sed -E 's/x86_64/amd64/')
BUILDINFOSDET ?=

# Project metadata
PROJECT_VERSION    := 0.1.0
REPO_ORG           := bitcap-co
PROJECT_NAME       := ipr-daemon
PROJECT_TAG        := $(shell git describe --tags 2>/dev/null $(git rev-list --tags --max-count=1))
ifeq ($(PROJECT_TAG),)
PROJECT_TAG        := NO-TAG
endif
PROJECT_COMMIT     := $(shell git rev-parse HEAD)
ifeq ($(PROJECT_COMMIT),)
PROJECT_COMMIT     := NO-CommitID
endif
PROJECT_DELTA      := $(shell DELTA_LINES=$$(git diff | wc -l); if [ $${DELTA_LINES} -ne 0 ]; then echo $${DELTA_LINES} ; else echo "''" ; fi)
VERSION_PKG        := $(shell echo $(PROJECT_VERSION) | sed 's/^v//g')
LICENSE            := MIT
URL                := https://github.com/$(REPO_ORG)/$(PROJECT_NAME)
DESCRIPTION        := ASIC Miner IP Report listener

# Build variables
BUILDINFOS         := $(shell date +%FT%T%z)$(BUILDINFOSDET)
HOSTNAME           := $(shell hostname)
LDFLAGS            := $(LDFLAGS) -X "main.VERSION=$(PROJECT_VERSION)" -X "main.DELTA=$(PROJECT_DELTA)"
LDFLAGS            += -X "main.BUILDINFO=$(BUILDINFOS)" -X "main.TAG=$(PROJECT_TAG)"
LDFLAGS            += -X "main.COMMIT=$(PROJECT_COMMIT)" -s -w
OUTPUT_BINARY      := iprd
OUTPUT_NAME        := $(DIST_DIR)$(OUTPUT_BINARY)-$(GOOS)-$(GOARCH)
DOCKER_VERSION     := v$(PROJECT_VERSION)
FREEBSD_VERSION    := 14.3

ALL: $(OUTPUT_NAME)

.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: unittest
unittest:
	go test ./...

.PHONY: test-race
test-race:
	@echo checking code for races...
	go test -race ./...

.PHONY: vet
vet:
	@echo checking code is vetted...
	go vet $(shell go list ./...)

test: vet unittest

.PHONY: fmt
fmt:
	@go fmt ./cmd/...

.PHONY: test-fmt
test-fmt: fmt
	@if test `git diff ./cmd | wc -l` -gt 0; then \
	    echo "Code changes detected when running 'go fmt':" ; \
	    git diff -Xfiles ; \
	    exit -1 ; \
	fi

.PHONY: test-tidy
test-tidy:
	@go mod tidy
	@if test `git diff go.mod | wc -l` -gt 0; then \
	    echo "Need to run 'go mod tidy' to clean up go.mod" ; \
	    exit -1 ; \
	fi

lint:
	golangci-lint run

precheck: test test-fmt test-tidy lint

clean:
	rm -f dist/*

clean-go:
	go clean -i -r -cache -modcache

.prepare: $(DIST_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

$(OUTPUT_NAME): ./cmd/main.go .prepare
	go build -ldflags='$(LDFLAGS)' -o ${OUTPUT_NAME} ./cmd/main.go


# Linux (amd64)
LINUX_AMD64_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-amd64
AMD64_IMAGE 	   := $(REPO_ORG)/$(PROJECT_NAME)-builder-amd64:$(DOCKER_VERSION)

.PHONY: linux-amd64
linux-amd64:
	docker build -t $(AMD64_IMAGE) -f Dockerfile.amd64 .
	docker run --rm \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(AMD64_IMAGE)

.PHONY: linux-amd64-shell
linux-amd64-shell:
	docker run -it --rm  --entrypoint /bin/bash \
	    --volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
	    $(AMD64_IMAGE)

.linux-amd64: $(LINUX_AMD64_S_NAME)
$(LINUX_AMD64_S_NAME): .prepare
	CGO_LDFLAGS=$$(pkg-config --libs dbus-1 libsystemd libpcap libcap libibverbs libnl-route-3.0) CGO_ENABLED=1 \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(LINUX_AMD64_S_NAME) ./cmd/main.go

# FreeBSD
.PHONY: .vagrant-check
.vagrant-check:
	@which vagrant >/dev/null || "Please install Vagrant: https://www.vagrantup.com"
	@which VBoxManage >/dev/null || "Please install VirtualBox: https://www.virtualbox.org"

freebsd: .vagrant-check
	vagrant provision && vagrant up && vagrant ssh-config >.vagrant-ssh && \
		scp -F .vagrant-ssh default:$(PROJECT_NAME)/dist/*freebsd* dist/

freebsd-shell:
	vagrant ssh

freebsd-clean:
	vagrant destroy -f || true
	rm -f .vagrant-ssh

ifeq ($(GOOS),freebsd)
FREEBSD_AMD64_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-freebsd-amd64

freebsd-binaries: freebsd-amd64
freebsd-amd64: $(FREEBSD_AMD64_S_NAME)

$(FREEBSD_AMD64_S_NAME):
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=1 \
	CGO_LDFLAGS='-libverbs' \
	go build -ldflags '$(LDFLAGS) -linkmode external -extldflags -static' \
		-o $(FREEBSD_AMD64_S_NAME) ./cmd/main.go
	@echo "Created: $(FREEBSD_AMD64_S_NAME)"
endif
