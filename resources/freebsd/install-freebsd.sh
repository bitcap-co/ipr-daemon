#!/bin/sh
#
# simple install script for iprd (freebsd)
#
# scp this script alongside the iprd binary to the target machine, then run as
# root. For the packaged install instead, use the .pkg built by
# `make freebsd-package` (pkg add ./iprd-<version>.pkg).

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run by root" >&2
    exit 1
fi

if [ ! -e iprd ]; then
    echo "error: binary not found (run from the directory containing iprd)" >&2
    exit 1
fi

echo "Start iprd installer..."

echo "Install iprd binary to /usr/local/sbin/..."
mkdir -p /usr/local/sbin
cp -v iprd /usr/local/sbin/iprd
chmod 0755 /usr/local/sbin/iprd

echo "Write iprd service to /usr/local/etc/rc.d/..."
mkdir -p /usr/local/etc/rc.d
cat > /usr/local/etc/rc.d/iprd << EOF
#!/bin/sh
#
# PROVIDE: iprd
# KEYWORD: shutdown

. /etc/rc.subr

name=iprd
desc="IP Report Daemon"
rcvar=iprd_enable
command="/usr/local/sbin/\${name}"

start_precmd="\${name}_prestart"

iprd_prestart()
{
    rc_flags="-a \${rc_flags} > /var/log/iprd.log &"
}

load_rc_config \$name
run_rc_command "\$1"
EOF
chmod 0555 /usr/local/etc/rc.d/iprd

echo "Enable iprd service in /etc/rc.conf..."
sysrc iprd_enable=YES

echo "Starting iprd service..."
service iprd start

echo "Done!"
exit 0
