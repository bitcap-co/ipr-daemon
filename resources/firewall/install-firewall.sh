#!/bin/sh

set -u

IPRD_DIR=/conf/iprd
LOCK_DIR=/var/run/iprd-bootstrap.lock
SCRIPT_DIR=$(dirname "$0")
SOURCE_BINARY=${1:-./iprd}
CONFIG_SOURCE=${2:-}

fail()
{
    echo "error: $*" >&2
    exit 1
}

has_forward_bind()
{
    awk '
        /^[[:space:]]*forward_bind[[:space:]]*=[[:space:]]*"[^"]+"[[:space:]]*(#.*)?$/ {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

register_pfsense_boot_command()
{
    /usr/local/bin/php <<'PHP'
<?php
require_once("config.inc");

$command = "/conf/iprd/bootstrap.sh start";
if (!isset($config["system"]["shellcmd"])) {
    $config["system"]["shellcmd"] = [];
} elseif (!is_array($config["system"]["shellcmd"])) {
    $config["system"]["shellcmd"] = [$config["system"]["shellcmd"]];
}
if (!in_array($command, $config["system"]["shellcmd"], true)) {
    $config["system"]["shellcmd"][] = $command;
}

if (isset($config["installedpackages"]["shellcmdsettings"])) {
    if (!isset($config["installedpackages"]["shellcmdsettings"]["config"]) ||
        !is_array($config["installedpackages"]["shellcmdsettings"]["config"])) {
        $config["installedpackages"]["shellcmdsettings"]["config"] = [];
    }
    $found = false;
    foreach ($config["installedpackages"]["shellcmdsettings"]["config"] as $entry) {
        if (($entry["cmd"] ?? "") === $command) {
            $found = true;
            break;
        }
    }
    if (!$found) {
        $config["installedpackages"]["shellcmdsettings"]["config"][] = [
            "cmd" => $command,
            "cmdtype" => "shellcmd",
            "description" => "Start IPR Daemon",
        ];
    }
}

$result = write_config("Registered persistent IPR Daemon boot command");
if ($result === false || $result === -1) {
    fwrite(STDERR, "Failed to write pfSense configuration\n");
    exit(1);
}
PHP
}

register_opnsense_hooks()
{
    install -d -m 0755 /usr/local/etc/rc.syshook.d/start \
        /usr/local/etc/rc.syshook.d/stop || return 1

    cat > "${IPRD_DIR}/start-hook.new" <<'EOF' || return 1
#!/bin/sh
exec /conf/iprd/bootstrap.sh start
EOF
    cat > "${IPRD_DIR}/stop-hook.new" <<'EOF' || return 1
#!/bin/sh
exec /conf/iprd/bootstrap.sh stop
EOF
    install -m 0755 "${IPRD_DIR}/start-hook.new" \
        /usr/local/etc/rc.syshook.d/start/50-iprd || return 1
    install -m 0755 "${IPRD_DIR}/stop-hook.new" \
        /usr/local/etc/rc.syshook.d/stop/50-iprd || return 1
    rm -f "${IPRD_DIR}/start-hook.new" "${IPRD_DIR}/stop-hook.new"
}

restore_previous_payload()
{
    if [ -f "${IPRD_DIR}/iprd.previous" ] &&
        [ -f "${IPRD_DIR}/iprd.sha256.previous" ] &&
        [ -f "${IPRD_DIR}/bootstrap.sh.previous" ]; then
        cp -p "${IPRD_DIR}/iprd.previous" "${IPRD_DIR}/iprd"
        cp -p "${IPRD_DIR}/iprd.sha256.previous" "${IPRD_DIR}/iprd.sha256"
        cp -p "${IPRD_DIR}/bootstrap.sh.previous" "${IPRD_DIR}/bootstrap.sh"
        rm -f "${IPRD_DIR}/installing"
        IPRD_LOCK_HELD=1 IPRD_INSTALLING=1 \
            "${IPRD_DIR}/bootstrap.sh" start >/dev/null 2>&1 || true
    else
        rm -f "${IPRD_DIR}/installing"
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    fail "this installer must run as root"
fi
if [ ! -x "${SOURCE_BINARY}" ]; then
    fail "IPR Daemon binary not found or not executable: ${SOURCE_BINARY}"
fi
if [ ! -r "${SCRIPT_DIR}/bootstrap.sh" ]; then
    fail "bootstrap.sh must be next to this installer"
fi
if ! "${SOURCE_BINARY}" -version >/dev/null 2>&1; then
    fail "the supplied binary cannot execute on this firewall"
fi

if [ -f /usr/local/opnsense/version/core ]; then
    platform=opnsense
elif [ -f /etc/inc/config.inc ] && [ -x /usr/local/sbin/pfSsh.php ]; then
    platform=pfsense
else
    fail "this installer only supports pfSense and OPNsense"
fi

if [ ! -e "${IPRD_DIR}/iprd.toml" ]; then
    if [ -z "${CONFIG_SOURCE}" ] || [ ! -r "${CONFIG_SOURCE}" ]; then
        fail "initial installation requires a readable TOML configuration: $0 [iprd-binary] <config.toml>"
    fi
    if ! has_forward_bind "${CONFIG_SOURCE}"; then
        fail "configuration must contain a non-empty quoted forward_bind"
    fi
fi

echo "Detected ${platform}"
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
    fail "another iprd bootstrap or installation operation is already running"
fi
trap 'rmdir "${LOCK_DIR}" 2>/dev/null' 0 HUP INT TERM

install -d -m 0700 "${IPRD_DIR}" || fail "could not create ${IPRD_DIR}"
if [ -f "${IPRD_DIR}/installing" ] && [ -x "${IPRD_DIR}/bootstrap.sh" ]; then
    IPRD_LOCK_HELD=1 "${IPRD_DIR}/bootstrap.sh" recover ||
        fail "could not recover the previous interrupted installation"
fi

install -m 0755 "${SOURCE_BINARY}" "${IPRD_DIR}/iprd.new" ||
    fail "could not stage the persistent binary"
sha256 -q "${IPRD_DIR}/iprd.new" > "${IPRD_DIR}/iprd.sha256.new" ||
    fail "could not checksum the persistent binary"
chmod 0600 "${IPRD_DIR}/iprd.sha256.new" || fail "could not protect the checksum"
install -m 0755 "${SCRIPT_DIR}/bootstrap.sh" "${IPRD_DIR}/bootstrap.sh.new" ||
    fail "could not stage the bootstrap"

if [ ! -e "${IPRD_DIR}/iprd.toml" ]; then
    install -m 0600 "${CONFIG_SOURCE}" "${IPRD_DIR}/iprd.toml.new" ||
        fail "could not stage the configuration"
    mv -f "${IPRD_DIR}/iprd.toml.new" "${IPRD_DIR}/iprd.toml" ||
        fail "could not install the configuration"
else
    echo "Preserving existing ${IPRD_DIR}/iprd.toml"
fi

rm -f "${IPRD_DIR}/iprd.previous" "${IPRD_DIR}/iprd.sha256.previous" \
    "${IPRD_DIR}/bootstrap.sh.previous"
if [ -f "${IPRD_DIR}/iprd" ] && [ -f "${IPRD_DIR}/iprd.sha256" ] &&
    [ -f "${IPRD_DIR}/bootstrap.sh" ]; then
    cp -p "${IPRD_DIR}/iprd" "${IPRD_DIR}/iprd.previous" || fail "could not back up iprd"
    cp -p "${IPRD_DIR}/iprd.sha256" "${IPRD_DIR}/iprd.sha256.previous" ||
        fail "could not back up the checksum"
    cp -p "${IPRD_DIR}/bootstrap.sh" "${IPRD_DIR}/bootstrap.sh.previous" ||
        fail "could not back up the bootstrap"
fi

touch "${IPRD_DIR}/installing" || fail "could not begin the payload transaction"
mv -f "${IPRD_DIR}/iprd.new" "${IPRD_DIR}/iprd" || fail "could not install iprd"
mv -f "${IPRD_DIR}/iprd.sha256.new" "${IPRD_DIR}/iprd.sha256" ||
    fail "could not install the checksum"
mv -f "${IPRD_DIR}/bootstrap.sh.new" "${IPRD_DIR}/bootstrap.sh" ||
    fail "could not install the bootstrap"

if ! IPRD_LOCK_HELD=1 IPRD_INSTALLING=1 "${IPRD_DIR}/bootstrap.sh" restart; then
    restore_previous_payload
    fail "iprd failed to start; the previous payload was restored when available"
fi
rm -f "${IPRD_DIR}/installing" || fail "could not complete the payload transaction"
rm -f "${IPRD_DIR}/iprd.previous" "${IPRD_DIR}/iprd.sha256.previous" \
    "${IPRD_DIR}/bootstrap.sh.previous"

case "${platform}" in
    pfsense)
        register_pfsense_boot_command || fail "could not register the pfSense shellcmd"
        ;;
    opnsense)
        register_opnsense_hooks || fail "could not register the OPNsense syshooks"
        ;;
esac

echo "Installed IPR Daemon for ${platform}."
echo "Configuration: ${IPRD_DIR}/iprd.toml"
echo "Control: ${IPRD_DIR}/bootstrap.sh {start|stop|restart|status}"
