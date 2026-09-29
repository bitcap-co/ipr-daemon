#!/bin/sh

set -u

IPRD_DIR=/conf/iprd
SOURCE_BINARY="${IPRD_DIR}/iprd"
CHECKSUM_FILE="${IPRD_DIR}/iprd.sha256"
CONFIG_FILE="${IPRD_DIR}/iprd.toml"
RUNTIME_DIR=/usr/local/libexec/iprd-private
INSTALLED_BINARY="${RUNTIME_DIR}/iprd"
PID_FILE=/var/run/iprd.pid
LOCK_DIR=/var/run/iprd-bootstrap.lock
TRANSACTION_FILE="${IPRD_DIR}/installing"

log()
{
    logger -t iprd "$*"
    echo "$*"
}

is_running()
{
    [ -f "${PID_FILE}" ] || return 1
    pid=$(cat "${PID_FILE}" 2>/dev/null) || return 1
    [ -n "${pid}" ] || return 1
    kill -0 "${pid}" 2>/dev/null || return 1
    process=$(ps -p "${pid}" -o comm= 2>/dev/null | awk 'NR == 1 { print $1 }')
    [ "${process##*/}" = iprd ]
}

acquire_lock()
{
    if mkdir "${LOCK_DIR}" 2>/dev/null; then
        trap 'rmdir "${LOCK_DIR}" 2>/dev/null' 0 HUP INT TERM
        return 0
    fi
    log "another iprd bootstrap operation is already running"
    return 1
}

recover_interrupted_install()
{
    [ -f "${TRANSACTION_FILE}" ] || return 0

    if [ -f "${IPRD_DIR}/iprd.previous" ] &&
        [ -f "${IPRD_DIR}/iprd.sha256.previous" ] &&
        [ -f "${IPRD_DIR}/bootstrap.sh.previous" ]; then
        cp -p "${IPRD_DIR}/iprd.previous" "${SOURCE_BINARY}" || return 1
        cp -p "${IPRD_DIR}/iprd.sha256.previous" "${CHECKSUM_FILE}" || return 1
        cp -p "${IPRD_DIR}/bootstrap.sh.previous" "${IPRD_DIR}/bootstrap.sh" || return 1
        rm -f "${TRANSACTION_FILE}"
        log "restored the previous payload after an interrupted installation"
        return 0
    fi

    if [ -x "${SOURCE_BINARY}" ] && [ -r "${CHECKSUM_FILE}" ] &&
        [ -x "${IPRD_DIR}/bootstrap.sh" ]; then
        expected=$(cat "${CHECKSUM_FILE}") || return 1
        actual=$(sha256 -q "${SOURCE_BINARY}") || return 1
        if [ "${actual}" = "${expected}" ]; then
            rm -f "${TRANSACTION_FILE}"
            log "completed recovery of the initial payload installation"
            return 0
        fi
    fi

    log "an interrupted installation was detected without a recoverable payload"
    return 1
}

verify_payload()
{
    if [ ! -x "${SOURCE_BINARY}" ]; then
        log "persistent binary is missing or not executable: ${SOURCE_BINARY}"
        return 1
    fi
    if [ ! -r "${CHECKSUM_FILE}" ]; then
        log "checksum file is missing: ${CHECKSUM_FILE}"
        return 1
    fi
    expected=$(cat "${CHECKSUM_FILE}") || return 1
    actual=$(sha256 -q "${SOURCE_BINARY}") || return 1
    if [ "${actual}" != "${expected}" ]; then
        log "checksum verification failed for ${SOURCE_BINARY}"
        return 1
    fi
    if [ ! -r "${CONFIG_FILE}" ]; then
        log "configuration file is missing: ${CONFIG_FILE}"
        return 1
    fi
}

install_binary()
{
    install -d -m 0755 "${RUNTIME_DIR}" || return 1
    if [ ! -x "${INSTALLED_BINARY}" ] || ! cmp -s "${SOURCE_BINARY}" "${INSTALLED_BINARY}"; then
        install -m 0755 "${SOURCE_BINARY}" "${INSTALLED_BINARY}.new" || return 1
        mv -f "${INSTALLED_BINARY}.new" "${INSTALLED_BINARY}" || return 1
        log "installed private runtime binary ${INSTALLED_BINARY}"
    fi
}

start_iprd()
{
    if is_running; then
        log "iprd is already running"
        return 0
    fi

    rm -f "${PID_FILE}"
    verify_payload || return 1
    install_binary || return 1

    /usr/sbin/daemon -f -S -T iprd -p "${PID_FILE}" \
        "${INSTALLED_BINARY}" -c "${CONFIG_FILE}" || return 1

    attempts=0
    while [ "${attempts}" -lt 10 ]; do
        if is_running; then
            log "started iprd"
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done

    log "iprd did not create a running PID within 10 seconds"
    return 1
}

stop_iprd()
{
    if ! is_running; then
        rm -f "${PID_FILE}"
        log "iprd is not running"
        return 0
    fi

    pid=$(cat "${PID_FILE}")
    kill "${pid}" || return 1
    attempts=0
    while [ "${attempts}" -lt 10 ]; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            rm -f "${PID_FILE}"
            log "stopped iprd"
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done

    log "iprd did not stop within 10 seconds"
    return 1
}

operation=${1:-start}
if [ "${IPRD_LOCK_HELD:-0}" != 1 ]; then
    acquire_lock || exit 1
fi
if [ "${IPRD_INSTALLING:-0}" != 1 ]; then
    recover_interrupted_install || exit 1
fi

case "${operation}" in
    recover)
        :
        ;;
    start)
        start_iprd
        ;;
    stop)
        stop_iprd
        ;;
    restart)
        stop_iprd && start_iprd
        ;;
    status)
        if is_running; then
            echo "iprd is running (PID $(cat "${PID_FILE}"))"
        else
            echo "iprd is not running"
            exit 1
        fi
        ;;
    *)
        echo "usage: $0 {start|stop|restart|status}" >&2
        exit 64
        ;;
esac
