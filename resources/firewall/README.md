# pfSense and OPNsense private installation

This installer provides a private, persistent installation without requiring an
official pfSense package or OPNsense plugin. The persistent payload lives under
`/conf/iprd`; the boot hook restores the private runtime binary under
`/usr/local/libexec/iprd-private` if an operating-system update removes it.

## Install

Copy these files to the firewall:

- The matching FreeBSD `iprd` binary from the release.
- `install-firewall.sh`.
- `bootstrap.sh`.
- `remove-firewall.sh`.

First generate and review the daemon configuration. For example:

```sh
./iprd -i igb1 -b 192.168.1.1 -p 7788 -w iprd
```

This writes `iprd.toml`. Adjust it for the firewall's actual interface
assignments and desired forwarding address before installation. The installer
intentionally does not infer or generate any daemon settings because pfSense
and OPNsense interface assignments are user-defined.

Then run as root from the directory containing the files:

```sh
chmod +x iprd install-firewall.sh bootstrap.sh remove-firewall.sh
./install-firewall.sh ./iprd ./iprd.toml
```

The initial installation requires a readable TOML file containing an explicit,
non-empty `forward_bind`. `iprd` performs full configuration validation when it
starts. An installed `/conf/iprd/iprd.toml` is preserved during binary
reinstallation, in which case the second argument is optional.

On pfSense, the installer adds a persistent `shellcmd` entry to `config.xml`. If
the Shellcmd package is installed, it also adds the matching package entry so a
later Shellcmd synchronization does not remove it.

On OPNsense, the installer creates native start and stop syshooks under
`/usr/local/etc/rc.syshook.d/`.

## Operation

```sh
/conf/iprd/bootstrap.sh status
/conf/iprd/bootstrap.sh restart
/conf/iprd/bootstrap.sh stop
```

Edit `/conf/iprd/iprd.toml`, then restart the daemon to apply changes. The
bootstrap verifies the persistent binary against `/conf/iprd/iprd.sha256` before
installing or starting it.

The locally generated checksum detects later payload corruption; it does not
establish release authenticity. Obtain the binary from a trusted release source.

The standard firewall configuration backup contains the pfSense boot command,
but not arbitrary files under `/conf/iprd`. OPNsense syshooks are also external
to `config.xml`. Back up `/conf/iprd` separately and recreate the hooks after a
full configuration restore.

## Remove

Remove the daemon, runtime files, and platform boot hook while preserving the
configuration for a later reinstall:

```sh
./remove-firewall.sh
```

To also remove `/conf/iprd/iprd.toml` and the persistent directory:

```sh
./remove-firewall.sh --purge
```

## Build the distribution bundles

From the repository root, build amd64 and arm64 ZIP bundles through the FreeBSD
Vagrant builder:

```sh
make firewall-bundle
```

The archives are written to `dist/` and contain the matching `iprd` binary, all
three helper scripts, and this README.
