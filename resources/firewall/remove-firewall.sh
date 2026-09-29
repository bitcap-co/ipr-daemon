#!/bin/sh

set -u

IPRD_DIR=/conf/iprd
LOCK_DIR=/var/run/iprd-bootstrap.lock
RUNTIME_DIR=/usr/local/libexec/iprd-private
PURGE=0

fail()
{
    echo "error: $*" >&2
    exit 1
}

unregister_pfsense_boot_command()
{
    /usr/local/bin/php <<'PHP'
<?php
require_once("/etc/inc/config.inc");

$command = "/conf/iprd/bootstrap.sh start";
$changed = false;

if (isset($config["system"]["shellcmd"])) {
    $commands = is_array($config["system"]["shellcmd"])
        ? $config["system"]["shellcmd"]
        : [$config["system"]["shellcmd"]];
    $filtered = array_values(array_filter(
        $commands,
        static function ($entry) use ($command) {
            return $entry !== $command;
        }
    ));
    if ($filtered !== $commands) {
        $config["system"]["shellcmd"] = $filtered;
        $changed = true;
    }
}

if (isset($config["installedpackages"]["shellcmdsettings"]["config"]) &&
    is_array($config["installedpackages"]["shellcmdsettings"]["config"])) {
    $entries = $config["installedpackages"]["shellcmdsettings"]["config"];
    $filtered = array_values(array_filter(
        $entries,
        static function ($entry) use ($command) {
            return ($entry["cmd"] ?? "") !== $command;
        }
    ));
    if ($filtered !== $entries) {
        $config["installedpackages"]["shellcmdsettings"]["config"] = $filtered;
        $changed = true;
    }
}

if ($changed) {
    $result = write_config("Removed persistent IPR Daemon boot command");
    if ($result === false || $result === -1) {
        fwrite(STDERR, "Failed to write pfSense configuration\n");
        exit(1);
    }
}
PHP
}

case "${1:-}" in
    "")
        ;;
    --purge)
        PURGE=1
        ;;
    *)
        echo "usage: $0 [--purge]" >&2
        exit 64
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    fail "this remover must run as root"
fi

if [ -f /usr/local/opnsense/version/core ]; then
    platform=opnsense
elif [ -f /etc/inc/config.inc ] && [ -x /usr/local/sbin/pfSsh.php ]; then
    platform=pfsense
else
    fail "this remover only supports pfSense and OPNsense"
fi

if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    fail "another iprd bootstrap or installation operation is already running"
fi
trap 'rmdir "${LOCK_DIR}" 2>/dev/null' 0 HUP INT TERM

if [ -x "${IPRD_DIR}/bootstrap.sh" ]; then
    IPRD_LOCK_HELD=1 "${IPRD_DIR}/bootstrap.sh" stop ||
        fail "could not stop iprd"
fi

case "${platform}" in
    pfsense)
        unregister_pfsense_boot_command || fail "could not unregister the pfSense shellcmd"
        ;;
    opnsense)
        rm -f /usr/local/etc/rc.syshook.d/start/50-iprd \
            /usr/local/etc/rc.syshook.d/stop/50-iprd
        ;;
esac

rm -rf "${RUNTIME_DIR}"
rm -f /var/run/iprd.pid

if [ "${PURGE}" -eq 1 ]; then
    rm -rf "${IPRD_DIR}"
    echo "Removed IPR Daemon and its persistent configuration from ${platform}."
else
    rm -f "${IPRD_DIR}/iprd" \
        "${IPRD_DIR}/iprd.sha256" \
        "${IPRD_DIR}/bootstrap.sh" \
        "${IPRD_DIR}/installing" \
        "${IPRD_DIR}/iprd.previous" \
        "${IPRD_DIR}/iprd.sha256.previous" \
        "${IPRD_DIR}/bootstrap.sh.previous" \
        "${IPRD_DIR}/iprd.new" \
        "${IPRD_DIR}/iprd.sha256.new" \
        "${IPRD_DIR}/bootstrap.sh.new" \
        "${IPRD_DIR}/start-hook.new" \
        "${IPRD_DIR}/stop-hook.new"
    echo "Removed IPR Daemon from ${platform}; preserved ${IPRD_DIR}/iprd.toml."
fi
