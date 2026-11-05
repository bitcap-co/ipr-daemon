## IPR Daemon CLI
### Interactive setup
Run the guided setup to create a new TOML configuration:
```bash
sudo ./iprd -setup
```
The wizard covers capture interfaces or automatic LAN selection, the TCP bind
address and port, mDNS advertisement, packet capture, known-miner filtering, and
optional global BPF filters. It reviews the result before asking where to write
it. The default destination is `/etc/iprd/config.toml` on Linux and
`/usr/local/etc/iprd/config.toml` on FreeBSD; the wizard offers to create the
application directory when needed. In an interactive terminal, press Tab to
complete filesystem paths for capture files and the configuration destination.

To load and modify an existing configuration, combine setup mode with `-c`:
```bash
sudo ./iprd -setup -c /etc/iprd/config.toml
```
The existing path becomes the default write destination. Run a generated
configuration with `iprd -c /etc/iprd/config.toml`. Linux packages use this path
by default; set `IPRD_CONFIG` in `/etc/iprd.conf` or `/etc/conf.d/iprd` to
override it.

### Finding interfaces
To see all available network interfaces that the daemon can listen on, run with the `-list` argument:
```
./iprd -list

# example output
3: eth0 (eth0) Desc:""
   Hardware:aa:bb:cc:dd:ee:ff
   IPv4:192.168.1.xx
```
Using an interface index or name, specify one or more interfaces with `-i`.
The flag supports chaining, comma-separated values, and inclusive interface index ranges:
```bash
sudo ./iprd -i "eth0" -i "eth1"
sudo ./iprd -i "eth0,eth1"
sudo ./iprd -i "8-21,23"
```
Index ranges can also use per-interface BPF options, which are applied to every
index in the range (for example, `-i "8-21:known-ports"`).
Each interface has an independent capture and reconnect loop. Packets are
processed through one duplicate record, capture file, and TCP broadcast stream.

It also worth noting that `iprd` requires running under the `root` user to run.

### Modifying BPF filters
the CLI allows direct modification of BPF filters for interfaces to add/exclude networks and ignoring specific devices on the network.

Available global BPF interface (applies to all interfaces):
 - `-add-network <NETWORK>` - Append a IPv4 network number to BPF filter. (i.e. -add-network 172.16,192.168.1,10). Can be used multple times or comma-separated values.
 - `-no-root-network` - By default, the "root" network of interface is included in the BPF filter. Use this flag to exclude it. `add-network` must follow this flag if supplied.
 - `-exclude <NETWORK>` - Exclude a IPv4 network number from BPF filter. Can be used multple times or comma-separated values.
 - `-ignore <MAC_ADDR>` - Ignore a specific network device (MAC Address) from BPF filter. Can be used multple times or comma-separated values.

 For configuring interface-specific BPF filters, options similar to the global flags can be used like so:
```bash
sudo ./iprd -i eth0:no-root-network,add-network=172.16 \ # exclude root network and add 172.16 for eth0
    -i eth1:add-network=10,exclude=192.168.1 \ # exclude 192.168.1 for eth1
    -ignore "aa:bb:cc:dd:ee:ff" # global flags can also be used in conjuntction! ignore MAC address aa:bb:cc:dd:ee:ff for both interfaces.
```

### Configuring TCP Stream/Broadcast
To configure the TCP stream port, use `-p` to supply:
```bash
sudo ./iprd -i "eth0" -p <SOME_PORT>
```

By default the TCP stream binds all interfaces. On a multi-homed host you can restrict
it to a single local IP with `-b`:
```bash
sudo ./iprd -i "eth0" -b 192.168.1.10
```

### Enabling MDNS Advertisement
To make the TCP endpoint discoverable by applications on the same LAN, enable
mDNS/DNS-SD advertisement:
```bash
sudo ./iprd -i "eth0" -mdns
```
This publishes `_iprd._tcp.local.` with the daemon's hostname, configured TCP
port, and subscription metadata. TOML configurations can use `mdns = true`.
Discovery can be verified with Avahi on Linux or `dns-sd` on macOS:
```bash
avahi-browse -rt _iprd._tcp
# or
dns-sd -B _iprd._tcp local.
```
mDNS is link-local multicast, so discovery normally stays within the same
LAN/VLAN unless the network has an mDNS reflector. No secrets are included in
the advertised TXT records.

### Capturing
To retain capture history, enable capture rotation together with a capture path:
```bash
sudo ./iprd -i "eth0" -capture-file /var/log/iprd/capture.pcapng -rotate-capture
```
Captures are written in PCAP-NG format so packets retain their source interface.
The setup wizard suggests `/var/log/iprd/capture.pcapng` on Linux and FreeBSD,
`/Library/Logs/iprd/capture.pcapng` on macOS, and the `iprd\\logs` directory
under `%ProgramData%` on Windows. It offers to create the suggested directory
when needed. A supplied extension such as `.pcap` is normalized to `.pcapng`.
Each capture is limited to 4 MiB. Rotation keeps four files total: the active `capture.pcapng`,
then `capture.1.pcapng` through `capture.3.pcapng` from newest to oldest. Without
`-rotate-capture`, the active capture is flushed at 4 MiB. TOML configurations
can enable the same behavior with `rotate_capture_files = true`. Existing classic
PCAP captures remain readable with `iprd-offline`.

### Available Options
See `iprd -h` for a list of all available options.
