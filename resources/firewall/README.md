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

## Update to a new release

Obtain the new release's FreeBSD binary for the firewall's architecture
(`amd64` or `arm64`) and its helper scripts from a trusted source. Extract or
copy them into a separate staging directory on the firewall, not directly into
`/conf/iprd` or `/usr/local/libexec/iprd-private`. In a distribution bundle, the
binary is already named `iprd`; rename a standalone release binary to `iprd`.

Back up `/conf/iprd` separately before updating. Then, as root, run from the
staging directory containing the new binary and scripts:

```sh
chmod +x iprd install-firewall.sh bootstrap.sh remove-firewall.sh
./iprd -version
./install-firewall.sh ./iprd
```

No configuration argument is needed for an existing installation. The installer
preserves `/conf/iprd/iprd.toml`, replaces the persistent binary and checksum,
updates the bootstrap and platform boot hooks, and restarts the daemon. Expect
a brief interruption while it restarts. If the new daemon fails to start, the
installer attempts to restore and start the previous payload when available.

Verify the installed runtime version and daemon status:

```sh
/usr/local/libexec/iprd-private/iprd -version
/conf/iprd/bootstrap.sh status
```

Do not update only the runtime binary: the bootstrap can replace it with the
persistent copy on the next start. Do not overwrite `/conf/iprd/iprd` manually
either, because its stored checksum would no longer match. Use the installer
to keep both copies and the checksum consistent.

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
