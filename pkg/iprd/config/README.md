## iprd/config (package)

`config` provides the configuration models, defaults, validation, TOML helpers, and command-line flag values used by the `iprd` package and daemon.

### Configuration types

The package separates reusable listener settings from daemon-specific forwarding settings:

- `InterfaceConfig` defines BPF filtering options for one network interface, selected by name or index.
- `ListenerConfig` defines packet capture, filtering, report forwarding, and capture-file behavior.
- `ForwardConfig` defines the TCP forwarding endpoint and optional mDNS/DNS-SD advertisement.
- `IPRDConfig` embeds `ListenerConfig` and `ForwardConfig` to provide the complete daemon configuration.

Use `DefaultListenerConfig()`, `DefaultForwardConfig()`, or `DefaultIPRDConfig()` when constructing configuration programmatically. The corresponding `ParseListenerConfig()` and `ParseConfig()` functions apply defaults, normalize interface selectors, and validate the result.

```go
cfg, err := iprdconfig.ParseConfig(&iprdconfig.IPRDConfig{
    ListenerConfig: iprdconfig.ListenerConfig{
        ListenInterfaces: []string{"eth0", "eth1"},
        ForwardKnown:     true,
        Interfaces: []iprdconfig.InterfaceConfig{
            {
                Selector:         "eth1",
                FilterKnownPorts: true,
            },
        },
    },
    ForwardConfig: iprdconfig.ForwardConfig{
        Bind: "0.0.0.0",
        Port: 7788,
        MDNS: true,
    },
})
if err != nil {
    return err
}
```

`ListenInterfaces` accepts interface names or numeric indexes. Comma-separated selectors are normalized into individual, unique values. The legacy `ListenInterface` field remains supported, but new callers should use `ListenInterfaces`.

An empty listener list is valid while parsing partial configuration; `iprd.ListenerManager.Run()` still requires at least one configured interface unless automatic interface selection is enabled with `Auto`.

### Per-interface filtering

Global BPF settings on `ListenerConfig` apply to every listener. Entries in `Interfaces` add settings for a specific selector. Use `InterfaceConfigFor()` to retrieve the combined global and per-interface configuration.

```go
filter := cfg.InterfaceConfigFor("eth1")
fmt.Println(filter.FilterKnownPorts)
```

When `NoRootNetwork` is enabled, at least one `NetworkInclusions` entry must be supplied so the resulting filter still includes a network. Network values use BPF IPv4 network notation, such as `192.168.1.0`, `192.168.1`, `172.16`, or `10`.

### TOML configuration

`NewIPRDConfigFromBytes()` and `NewIPRDConfigFromFile()` decode, normalize, and validate TOML configuration. `WriteIPRDConfigToFile()` performs the same validation before writing a configuration file.

```toml
listen_interfaces = ["eth0", "eth1"]
forward_known = true
capture_file = "/var/log/iprd/capture.pcapng"

forward_bind = "0.0.0.0"
forward_port = 7788
mdns = true
mdns_interfaces = ["eth0"]

[[interfaces]]
selector = "eth1"
filter_known_ports = true
ignored_devices = ["00:11:22:33:44:55"]
network_exclusions = ["10"]
```

```go
cfg, err := iprdconfig.NewIPRDConfigFromFile("iprd.toml")
if err != nil {
    return err
}

if err := iprdconfig.WriteIPRDConfigToFile(cfg, "normalized.toml"); err != nil {
    return err
}
```

All configuration types also provide `Validate()` and `Merge()` methods. `Merge()` applies non-zero values from a target configuration and returns a new value; it is best suited to additive overrides because zero values do not clear existing settings.

### Command-line flag values

`FlagSlice` and `FlagInterface` implement `flag.Value` for applications exposing `iprd` configuration through Go's `flag` package.

- `FlagSlice` accepts repeated or comma-separated values.
- `FlagInterface` accepts interface names, indexes, comma-separated selectors, and numeric index ranges. Per-interface options follow the selector after `:`, for example `eth0:known-ports,exclude=10`.

Use `FlagInterface.Selectors()` and `FlagInterface.Configs()` to obtain deterministic slices after parsing flags.
