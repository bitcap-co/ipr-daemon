DIST_DIR ?= dist/
GOOS ?= $(shell uname -s | tr "[:upper:]" "[:lower:]")
GOARCH ?= $(shell uname -m | sed -E 's/x86_64/amd64/')
BUILDINFOSDET ?=

# Project metadata
PROJECT_VERSION    := 0.4.5
REPO_ORG           := bitcap-co
DOCKER_REPO        := mattwert
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
DESCRIPTION        := LAN-wide miner IP Report listener

# Build variables
BUILDINFOS         := $(shell date +%FT%T%z)$(BUILDINFOSDET)
HOSTNAME           := $(shell hostname)
LDFLAGS            := $(LDFLAGS) -X "main.VERSION=$(PROJECT_VERSION)" -X "main.DELTA=$(PROJECT_DELTA)"
LDFLAGS            += -X "main.BUILDINFO=$(BUILDINFOS)" -X "main.TAG=$(PROJECT_TAG)"
LDFLAGS            += -X "main.COMMIT=$(PROJECT_COMMIT)" -s -w
OUTPUT_BINARY      := iprd
OUTPUT_OFFLINE     := iprd-offline
OUTPUT_NAME        := $(DIST_DIR)$(OUTPUT_BINARY)-$(GOOS)-$(GOARCH)
DOCKER_VERSION     := v$(PROJECT_VERSION)
FREEBSD_VERSION    := 14.3

ALL: $(OUTPUT_NAME)

## help : prints this output
.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## unittest : run go unit tests
.PHONY: unittest
unittest:
	go test ./...

## test-race : run `go test -race`
.PHONY: test-race
test-race:
	@echo checking code for races...
	go test -race ./...

## vet : run `go vet`
.PHONY: vet
vet:
	@echo checking code is vetted...
	go vet $(shell go list ./...)

## test : run all tests
test: vet unittest

## fmt : format code with `go fmt`
.PHONY: fmt
fmt:
	@go fmt ./cmd/...

## test-fmt : test to make sure code is formatted correctly
.PHONY: test-fmt
test-fmt: fmt
	@if test `git diff ./cmd | wc -l` -gt 0; then \
	    echo "Code changes detected when running 'go fmt':" ; \
	    git diff -Xfiles ; \
	    exit -1 ; \
	fi

## test-tidy : test to make sure go.mod is tidy
.PHONY: test-tidy
test-tidy:
	@go mod tidy
	@if test `git diff go.mod | wc -l` -gt 0; then \
	    echo "Need to run 'go mod tidy' to clean up go.mod" ; \
	    exit -1 ; \
	fi

## lint : run `golangci-list`
lint:
	golangci-lint run

## precheck : run all checks
precheck: test test-fmt test-tidy lint

## clean : clear dist/
clean:
	rm -f dist/*

## clean-go : clear go cache
clean-go:
	go clean -i -r -cache -modcache

## clean-build : clear build environment
clean-build: vagrant-clean docker-clean clean

.prepare: $(DIST_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

$(OUTPUT_NAME): ./cmd/main.go .prepare
	go build -ldflags='$(LDFLAGS)' -o ${OUTPUT_NAME} ./cmd/main.go

.PHONY: offline
offline: ./cmd/offline/main.go
	go build -o ${OUTPUT_OFFLINE} ./cmd/offline/main.go


# Linux (amd64)
LINUX_AMD64_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-amd64
AMD64_IMAGE 	   := $(REPO_ORG)/$(PROJECT_NAME)-builder-amd64:$(DOCKER_VERSION)

## linux-amd64 : build static Linux/amd64 binary using Docker
.PHONY: linux-amd64
linux-amd64:
	docker build -t $(AMD64_IMAGE) -f linux-amd64.dockerfile .
	docker run --rm \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(AMD64_IMAGE)

## linux-amd64-shell : get a shell in Linux/amd64 Docker container
.PHONY: linux-amd64-shell
linux-amd64-shell:
	docker run -it --rm  --entrypoint /bin/bash \
	    --volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
	    $(AMD64_IMAGE)

.linux-amd64: $(LINUX_AMD64_S_NAME)
$(LINUX_AMD64_S_NAME): .prepare
	CGO_LDFLAGS="$$(pkg-config --libs libpcap)" CGO_ENABLED=1 \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(LINUX_AMD64_S_NAME) ./cmd/main.go
	@echo "Created: $(LINUX_AMD64_S_NAME)"

# Linux musl (static, for Alpine/apk). One Alpine builder does a native build; the
# --platform selects the target arch (native on matching CI hardware, qemu elsewhere).
MUSL_AMD64_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-musl-amd64
MUSL_ARM64_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-musl-arm64
ALPINE_IMAGE      := $(REPO_ORG)/$(PROJECT_NAME)-builder-alpine:$(DOCKER_VERSION)

## linux-musl-amd64 : build static musl Linux/amd64 binary using Docker (for apk)
.PHONY: linux-musl-amd64
linux-musl-amd64:
	docker build --platform linux/amd64 -t $(ALPINE_IMAGE)-amd64 -f alpine.dockerfile .
	docker run --rm --platform linux/amd64 \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(ALPINE_IMAGE)-amd64 .linux-musl-amd64

## linux-musl-arm64 : build static musl Linux/arm64 binary using Docker (for apk)
.PHONY: linux-musl-arm64
linux-musl-arm64:
	docker build --platform linux/arm64 -t $(ALPINE_IMAGE)-arm64 -f alpine.dockerfile .
	docker run --rm --platform linux/arm64 \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(ALPINE_IMAGE)-arm64 .linux-musl-arm64

.linux-musl-amd64: $(MUSL_AMD64_S_NAME)
$(MUSL_AMD64_S_NAME): .prepare
	CGO_LDFLAGS="$$(pkg-config --libs --static libpcap)" CGO_ENABLED=1 \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(MUSL_AMD64_S_NAME) ./cmd/main.go
	@echo "Created: $(MUSL_AMD64_S_NAME)"

.linux-musl-arm64: $(MUSL_ARM64_S_NAME)
$(MUSL_ARM64_S_NAME): .prepare
	CGO_LDFLAGS="$$(pkg-config --libs --static libpcap)" CGO_ENABLED=1 \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(MUSL_ARM64_S_NAME) ./cmd/main.go
	@echo "Created: $(MUSL_ARM64_S_NAME)"

# Linux ARM (aarch64 / armv5 / armv6 / armv7)
LINUX_ARM64_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-arm64
LINUX_ARMV5_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-armv5
LINUX_ARMV6_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-armv6
LINUX_ARMV7_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-linux-armv7
ARM_IMAGE          := $(REPO_ORG)/$(PROJECT_NAME)-builder-arm:$(DOCKER_VERSION)
AARCH64_SYSROOT    := /build/sysroot/aarch64
ARMV5_SYSROOT      := /build/sysroot/armv5
ARMV6_SYSROOT      := /build/sysroot/armv6
ARMV7_SYSROOT      := /build/sysroot/armv7

## linux-arm64 : build static Linux/arm64 binary using Docker
.PHONY: linux-arm64
linux-arm64:
	docker build -t $(ARM_IMAGE) -f linux-arm.dockerfile .
	docker run --rm \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(ARM_IMAGE) .linux-arm64

## linux-armv5 : build static Linux/armv5 binary using Docker
.PHONY: linux-armv5
linux-armv5:
	docker build -t $(ARM_IMAGE) -f linux-arm.dockerfile .
	docker run --rm \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(ARM_IMAGE) .linux-armv5

## linux-armv6 : build static Linux/armv6 binary using Docker
.PHONY: linux-armv6
linux-armv6:
	docker build -t $(ARM_IMAGE) -f linux-arm.dockerfile .
	docker run --rm \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(ARM_IMAGE) .linux-armv6

## linux-armv7 : build static Linux/armv7 binary using Docker
.PHONY: linux-armv7
linux-armv7:
	docker build -t $(ARM_IMAGE) -f linux-arm.dockerfile .
	docker run --rm \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(ARM_IMAGE) .linux-armv7

## linux-arm32 : build all Linux/arm32 variants (armv5/v6/v7) using Docker
.PHONY: linux-arm32
linux-arm32:
	docker build -t $(ARM_IMAGE) -f linux-arm.dockerfile .
	docker run --rm \
		--volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
		$(ARM_IMAGE) .linux-arm32

## linux-arm-shell : get a shell in Linux/arm Docker container
.PHONY: linux-arm-shell
linux-arm-shell:
	docker run -it --rm  --entrypoint /bin/bash \
	    --volume $(shell pwd)/dist:/build/$(PROJECT_NAME)/dist \
	    $(ARM_IMAGE)

.linux-arm64: $(LINUX_ARM64_S_NAME)
$(LINUX_ARM64_S_NAME): .prepare
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc \
	    CGO_CFLAGS="-I$(AARCH64_SYSROOT)/include" \
	    CGO_LDFLAGS="-L$(AARCH64_SYSROOT)/lib -lpcap" \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(LINUX_ARM64_S_NAME) ./cmd/main.go
	@echo "Created: $(LINUX_ARM64_S_NAME)"
	@file $(LINUX_ARM64_S_NAME)
	@aarch64-linux-gnu-readelf -d $(LINUX_ARM64_S_NAME)

.PHONY: .linux-arm32
.linux-arm32: .linux-armv5 .linux-armv6 .linux-armv7

.linux-armv5: $(LINUX_ARMV5_S_NAME)
$(LINUX_ARMV5_S_NAME): .prepare
	GOOS=linux GOARCH=arm GOARM=5 CGO_ENABLED=1 CC=arm-linux-gnueabi-gcc \
	    CGO_CFLAGS="-I$(ARMV5_SYSROOT)/include" \
	    CGO_LDFLAGS="-L$(ARMV5_SYSROOT)/lib -lpcap" \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(LINUX_ARMV5_S_NAME) ./cmd/main.go
	@echo "Created: $(LINUX_ARMV5_S_NAME)"
	@file $(LINUX_ARMV5_S_NAME)
	@arm-linux-gnueabi-readelf -d $(LINUX_ARMV5_S_NAME)

.linux-armv6: $(LINUX_ARMV6_S_NAME)
$(LINUX_ARMV6_S_NAME): .prepare
	GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=1 CC=arm-linux-gnueabi-gcc \
	    CGO_CFLAGS="-I$(ARMV6_SYSROOT)/include" \
	    CGO_LDFLAGS="-L$(ARMV6_SYSROOT)/lib -lpcap" \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(LINUX_ARMV6_S_NAME) ./cmd/main.go
	@echo "Created: $(LINUX_ARMV6_S_NAME)"
	@file $(LINUX_ARMV6_S_NAME)
	@arm-linux-gnueabi-readelf -d $(LINUX_ARMV6_S_NAME)

.linux-armv7: $(LINUX_ARMV7_S_NAME)
$(LINUX_ARMV7_S_NAME): .prepare
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=1 CC=arm-linux-gnueabi-gcc \
	    CGO_CFLAGS="-I$(ARMV7_SYSROOT)/include" \
	    CGO_LDFLAGS="-L$(ARMV7_SYSROOT)/lib -lpcap" \
	    go build -ldflags "$(LDFLAGS) -linkmode 'external' -extldflags '-static'" \
	        -o $(LINUX_ARMV7_S_NAME) ./cmd/main.go
	@echo "Created: $(LINUX_ARMV7_S_NAME)"
	@file $(LINUX_ARMV7_S_NAME)
	@arm-linux-gnueabi-readelf -d $(LINUX_ARMV7_S_NAME)

# FreeBSD
.PHONY: .vagrant-check
.vagrant-check:
	@which vagrant >/dev/null || "Please install Vagrant: https://www.vagrantup.com"
	@which VBoxManage >/dev/null || "Please install VirtualBox: https://www.virtualbox.org"

## freebsd : build static FreeBSD/amd64 binary with Vagrant VM
freebsd: .vagrant-check
	vagrant provision && vagrant up && vagrant ssh-config >.vagrant-ssh && \
		scp -F .vagrant-ssh default:$(PROJECT_NAME)/dist/*freebsd* dist/

## freebsd-package : build FreeBSD/amd64 .pkg package with Vagrant VM
.PHONY: freebsd-package
freebsd-package: .vagrant-check
	vagrant provision && vagrant up && vagrant ssh-config >.vagrant-ssh && \
		ssh -F .vagrant-ssh default 'sh -c "PATH=/usr/local/bin:$$PATH; cd $(PROJECT_NAME) && gmake .freebsd-package"' && \
		scp -F .vagrant-ssh default:$(PROJECT_NAME)/dist/*.pkg dist/

## freebsd-shell : get shell in FreeBSD Vagrant VM
freebsd-shell:
	vagrant ssh

## vagrant-clean : destroy Vagrant VM
vagrant-clean:
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

# FreeBSD .pkg packaging (must run on FreeBSD — needs the pkg(8) tool).
# Invoked inside the Vagrant VM by the host-side `freebsd-package` target.
FREEBSD_MAJOR      := $(shell echo $(FREEBSD_VERSION) | cut -d. -f1)
FREEBSD_PKG_STAGE  := $(DIST_DIR)iprd-pkg-stage

## .freebsd-package : (run on FreeBSD) stage tree and build .pkg with pkg create
.PHONY: .freebsd-package
.freebsd-package: $(FREEBSD_AMD64_S_NAME)
	@rm -rf $(FREEBSD_PKG_STAGE)
	@mkdir -p $(FREEBSD_PKG_STAGE)/usr/local/sbin $(FREEBSD_PKG_STAGE)/usr/local/etc/rc.d
	@install -m 0755 $(FREEBSD_AMD64_S_NAME)      $(FREEBSD_PKG_STAGE)/usr/local/sbin/iprd
	@install -m 0555 resources/freebsd/rc.d/iprd  $(FREEBSD_PKG_STAGE)/usr/local/etc/rc.d/iprd
	@sed -e 's/%%VERSION%%/$(VERSION_PKG)/' \
	     -e 's/%%ARCH%%/FreeBSD:$(FREEBSD_MAJOR):amd64/' \
	     resources/freebsd/+MANIFEST.in > $(DIST_DIR)+MANIFEST
	pkg create -M $(DIST_DIR)+MANIFEST -p resources/freebsd/pkg-plist -r $(FREEBSD_PKG_STAGE) -o $(DIST_DIR)
	@rm -rf $(FREEBSD_PKG_STAGE) $(DIST_DIR)+MANIFEST
	@echo "Created: $(DIST_DIR)iprd-$(VERSION_PKG).pkg"
endif

# macOS/darwin
ifeq ($(GOOS),darwin)
DARWIN_S_NAME := $(DIST_DIR)$(OUTPUT_BINARY)-$(PROJECT_VERSION)-darwin-$(GOARCH)
## darwin : build MacOS/amd64 binary
darwin: $(DARWIN_S_NAME)

PCAP_CFLAGS := $(shell pkg-config --cflags libpcap)
PCAP_LDFLAGS := $(shell pkg-config --libs --static libpcap)

HOMEBREW_PREFIX := $(or $(shell test -d /opt/homebrew && echo /opt/homebrew),$(shell test -d /usr/local && echo /usr/local))
ifeq ($(PCAP_CFLAGS),)
PCAP_CFLAGS := -I$(HOMEBREW_PREFIX)/include
PCAP_LDFLAGS := -L$(HOMEBREW_PREFIX)/lib -lpcap
endif

CGO_LDFLAGS := -Wl,-rpath,$(HOMEBREW_PREFIX)/lib
$(DARWIN_S_NAME): ./cmd/main.go .prepare
	@echo "CFLAGS: $(PCAP_CFLAGS)"
	CGO_ENABLED=1 CGO_CFLAGS="$(PCAP_CFLAGS)" \
	CGO_LDFLAGS="$(CGO_LDFLAGS) $(PCAP_LDFLAGS)" \
	go build -ldflags='$(LDFLAGS)' \
		-o $(DARWIN_S_NAME) ./cmd/main.go
	@echo "Created: $(DARWIN_S_NAME)"
endif

# ── Native packages via nfpm (deb + rpm + apk) ───────────────────────────────
# nfpm reads nfpm.yaml; the packaged binary/arch/version are passed via env.
# deb/rpm use the glibc-static binary; apk uses the musl-static binary.
NFPM ?= nfpm

## deb-package : build static linux-amd64 binary (Docker) and package as .deb
.PHONY: deb-package
deb-package: linux-amd64
	$(MAKE) .deb-package

## .deb-package : package the existing dist/ linux-amd64 binary as .deb (nfpm)
.PHONY: .deb-package
.deb-package:
	@test -f $(LINUX_AMD64_S_NAME) || { echo "ERROR: $(LINUX_AMD64_S_NAME) not found — build it first (make linux-amd64 or make .linux-amd64)" >&2; exit 1; }
	@cp $(LINUX_AMD64_S_NAME) $(DIST_DIR).nfpm-bin
	IPRD_ARCH=amd64 IPRD_VERSION=$(VERSION_PKG) $(NFPM) package -f nfpm.yaml -p deb -t $(DIST_DIR)
	@rm -f $(DIST_DIR).nfpm-bin

## deb-package-arm64 : build static linux-arm64 binary (Docker) and package as arm64 .deb
.PHONY: deb-package-arm64
deb-package-arm64: linux-arm64
	$(MAKE) .deb-package-arm64

## .deb-package-arm64 : package the existing dist/ linux-arm64 binary as arm64 .deb (nfpm)
.PHONY: .deb-package-arm64
.deb-package-arm64:
	@test -f $(LINUX_ARM64_S_NAME) || { echo "ERROR: $(LINUX_ARM64_S_NAME) not found — build it first (make linux-arm64 or make .linux-arm64)" >&2; exit 1; }
	@cp $(LINUX_ARM64_S_NAME) $(DIST_DIR).nfpm-bin
	IPRD_ARCH=arm64 IPRD_VERSION=$(VERSION_PKG) $(NFPM) package -f nfpm.yaml -p deb -t $(DIST_DIR)
	@rm -f $(DIST_DIR).nfpm-bin

## rpm-package : build static linux-amd64 binary (Docker) and package as .rpm
.PHONY: rpm-package
rpm-package: linux-amd64
	$(MAKE) .rpm-package

## .rpm-package : package the existing dist/ linux-amd64 binary as .rpm (nfpm)
.PHONY: .rpm-package
.rpm-package:
	@test -f $(LINUX_AMD64_S_NAME) || { echo "ERROR: $(LINUX_AMD64_S_NAME) not found — build it first (make linux-amd64 or make .linux-amd64)" >&2; exit 1; }
	@cp $(LINUX_AMD64_S_NAME) $(DIST_DIR).nfpm-bin
	IPRD_ARCH=amd64 IPRD_VERSION=$(VERSION_PKG) $(NFPM) package -f nfpm.yaml -p rpm -t $(DIST_DIR)
	@rm -f $(DIST_DIR).nfpm-bin

## rpm-package-arm64 : build static linux-arm64 binary (Docker) and package as arm64 .rpm
.PHONY: rpm-package-arm64
rpm-package-arm64: linux-arm64
	$(MAKE) .rpm-package-arm64

## .rpm-package-arm64 : package the existing dist/ linux-arm64 binary as aarch64 .rpm (nfpm)
.PHONY: .rpm-package-arm64
.rpm-package-arm64:
	@test -f $(LINUX_ARM64_S_NAME) || { echo "ERROR: $(LINUX_ARM64_S_NAME) not found — build it first (make linux-arm64 or make .linux-arm64)" >&2; exit 1; }
	@cp $(LINUX_ARM64_S_NAME) $(DIST_DIR).nfpm-bin
	IPRD_ARCH=arm64 IPRD_VERSION=$(VERSION_PKG) $(NFPM) package -f nfpm.yaml -p rpm -t $(DIST_DIR)
	@rm -f $(DIST_DIR).nfpm-bin

## apk-package : build static musl binary (Docker) and package as .apk
.PHONY: apk-package
apk-package: linux-musl-amd64
	$(MAKE) .apk-package

## .apk-package : package the existing dist/ musl binary as .apk (nfpm)
.PHONY: .apk-package
.apk-package:
	@test -f $(MUSL_AMD64_S_NAME) || { echo "ERROR: $(MUSL_AMD64_S_NAME) not found — build it first (make linux-musl-amd64)" >&2; exit 1; }
	@cp $(MUSL_AMD64_S_NAME) $(DIST_DIR).nfpm-bin
	IPRD_ARCH=amd64 IPRD_VERSION=$(VERSION_PKG) $(NFPM) package -f nfpm.yaml -p apk -t $(DIST_DIR)
	@rm -f $(DIST_DIR).nfpm-bin

## apk-package-arm64 : build static musl arm64 binary (Docker) and package as arm64 .apk
.PHONY: apk-package-arm64
apk-package-arm64: linux-musl-arm64
	$(MAKE) .apk-package-arm64

## .apk-package-arm64 : package the existing dist/ musl arm64 binary as aarch64 .apk (nfpm)
.PHONY: .apk-package-arm64
.apk-package-arm64:
	@test -f $(MUSL_ARM64_S_NAME) || { echo "ERROR: $(MUSL_ARM64_S_NAME) not found — build it first (make linux-musl-arm64)" >&2; exit 1; }
	@cp $(MUSL_ARM64_S_NAME) $(DIST_DIR).nfpm-bin
	IPRD_ARCH=arm64 IPRD_VERSION=$(VERSION_PKG) $(NFPM) package -f nfpm.yaml -p apk -t $(DIST_DIR)
	@rm -f $(DIST_DIR).nfpm-bin

DOCKER_IMAGE := $(DOCKER_REPO)/$(PROJECT_NAME):$(DOCKER_VERSION)

.PHONY: docker docker_clean .docker
docker:
	docker build \
		-t $(DOCKER_IMAGE) \
		--build-arg VERSION=$(DOCKER_VERSION) \
		-f iprd.dockerfile .

.docker:
	CGO_ENABLED=1 \
	go build -ldflags '$(LDFLAGS)' -o dist/iprd ./cmd/main.go

docker-shell:
	docker run --rm -it --network=host \
	$(DOCKER_IMAGE) \
	/bin/sh

BUILDX_BUILDER := iprd-builder

## docker-buildx : ensure a multi-platform buildx builder exists
.PHONY: docker-buildx
docker-buildx:
	@docker buildx inspect $(BUILDX_BUILDER) >/dev/null 2>&1 || \
		docker buildx create --name $(BUILDX_BUILDER) --driver docker-container --bootstrap >/dev/null
	@echo "using buildx builder: $(BUILDX_BUILDER)"

## docker-release : build+push the multi-arch (amd64+arm64) image to Docker Hub
# Requires QEMU/binfmt for cross-arch emulation (Docker Desktop bundles it; otherwise:
#   docker run --privileged --rm tonistiigi/binfmt --install arm64,amd64).
docker-release: docker-buildx
	docker buildx build \
	--builder $(BUILDX_BUILDER) \
	-t $(DOCKER_IMAGE) \
	-t $(DOCKER_REPO)/$(PROJECT_NAME):latest \
	--build-arg VERSION=$(DOCKER_VERSION) \
	--platform linux/amd64,linux/arm64 \
	--push -f iprd.dockerfile .

## docker-clean : remove Docker containers
docker-clean:
	docker image rm ${AMD64_IMAGE} ${ARM_IMAGE} || true
