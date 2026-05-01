#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY=""
ARCH=""
VERSION=""

OPTIND=1
while getopts "abV:" opt; do
    case "$opt" in
       "a") ARCH="$OPTARG" ;;
       "b") BINARY="$OPTARG" ;;
       "V") VERSION="$OPTARG" ;;
       \? ) echo "$0: ERROR (Invalid flag)" >&2; exit 1 ;;
        : ) echo  "$0: ERROR ($OPTARG requires an argument)" >&2; exit 1 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ -z "$VERSION" ]] && echo "ERROR (Supply version string)" && exit 1

# ── locate binary ─────────────────────────────────────────────────────────────
if [[ -z "$BINARY" ]]; then
    BINARY="$(ls "$REPO_ROOT"/dist/iprd-*-linux-* 2>/dev/null | head -1 || true)"
    if [[ -z "$BINARY" ]]; then
        echo "ERROR (No linux binary found in dist/ — build one first or pass as first argument" >&2
        exit 1
    fi
fi

if [[ ! -f "$BINARY" ]]; then
    echo "ERROR (Binary not found: $BINARY)" >&2
    exit 1
fi

if [[ -z "$ARCH" ]]; then
    ARCH="$(basename "$BINARY" | sed -E 's/^iprd-*-linux-(.+)$/\1/')"
    if [[ -z "$ARCH" ]]; then
        ARCH="$(uname -m | sed -E 's/x86_64/amd64/')"
        echo "No ARCH supplied, using machine architecture: $ARCH" >&2
    fi
fi

PKG_NAME="iprd_${VERSION}_${ARCH}"
STAGING="$REPO_ROOT/dist/${PKG_NAME}"
DEB_OUT="$REPO_ROOT/dist/iprd_${VERSION}_${ARCH}.deb"

echo "Packaging iprd ${VERSION} for Linux/${ARCH}..."

# ── build staging tree ────────────────────────────────────────────────────────
rm -rf "$STAGING"
mkdir -p "$STAGING/DEBIAN"
mkdir -p "$STAGING/usr/bin"
mkdir -p "$STAGING/etc/systemd/system"

install -m 0755 "$BINARY"                                               "$STAGING/usr/bin/iprd"
install -m 0644 "$REPO_ROOT/resources/systemd/iprd.service"            "$STAGING/etc/systemd/system/iprd.service"
install -m 0644 "$REPO_ROOT/resources/systemd/iprd.conf"               "$STAGING/etc/iprd.conf"

# ── DEBIAN/control ────────────────────────────────────────────────────────────
cat > "$STAGING/DEBIAN/control" <<EOF
Package: iprd
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: MatthewWertman <matt@bitcap.co>
Section: net
Priority: optional
Description: ASIC Miner IP Report listener
 iprd listens for IP Report packets broadcast by ASIC miners on the local
 network and forwards them over TCP.
EOF

# ── DEBIAN/conffiles — preserves user edits to iprd.conf on upgrade ───────────
cat > "$STAGING/DEBIAN/conffiles" <<EOF
/etc/iprd.conf
EOF

# ── DEBIAN/postinst ───────────────────────────────────────────────────────────
cat > "$STAGING/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload
systemctl enable iprd.service
systemctl start iprd.service
EOF
chmod 0755 "$STAGING/DEBIAN/postinst"

# ── DEBIAN/prerm ──────────────────────────────────────────────────────────────
cat > "$STAGING/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if systemctl is-active --quiet iprd.service; then
    systemctl stop iprd.service
fi
systemctl disable iprd.service || true
EOF
chmod 0755 "$STAGING/DEBIAN/prerm"

# ── DEBIAN/postrm ─────────────────────────────────────────────────────────────
cat > "$STAGING/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl daemon-reload
fi
EOF
chmod 0755 "$STAGING/DEBIAN/postrm"

# ── build .deb ────────────────────────────────────────────────────────────────
dpkg-deb --root-owner-group --build "$STAGING" "$DEB_OUT"
rm -rf "$STAGING"

echo "Created: $DEB_OUT"
