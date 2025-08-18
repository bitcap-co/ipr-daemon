#!/bin/sh
#
# simple install script for iprd (freebsd)

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run by root" >&2
    exit 1
fi

echo "Start iprd installer..."
echo "Write iprd service to /etc/rc.d/..."
if [ ! -e /etc/rc.d/iprd ]; then
    cat > /etc/rc.d/iprd << EOF
#!/bin/sh
#
# PROVIDE: iprd
# KEYWORD: shutdown

. /etc/rc.subr

name=iprd
desc="IP Report Daemon"
rcvar=iprd_enable
command="/usr/sbin/\${name}"

start_precmd="\${name}_prestart"

iprd_prestart()
{
    rc_flags="-a \${rc_flags} > /var/log/iprd.log &"
}

load_rc_config \$name
run_rc_command "\$1"
EOF
    chmod +x /etc/rc.d/iprd
fi


if [ ! -e iprd ]; then
    echo "error: binary not found"
    exit 1
fi

cp -v iprd /usr/sbin/

echo "Add iprd_enable to /etc/rc.conf..."
echo "iprd_enable=\"YES\"" >> /etc/rc.conf

echo "Starting iprd service..."
service iprd start
