## iprd (package)
`iprd` is the core library for the standalone IP Reporter daemon CLI. This package provides live on the wire IP report packet processing from one or more network interfaces on a local network.

### Retrieving Network Interfaces
Available local/private IPv4 network interfaces are described by the `IPRInterface` type. Use `iprd.GetInterfaces()` to retrieve a list of all available IPRInterfaces on the system.

Additionally, `iprd.GetInterfaceByName()` & `iprd.GetInterfaceByIndex()` allow retrieving an interface by its name or index, respectively.

For FreeBSD-based routers (OPNsense, pfSense), `iprd.FindLanInterface()` allows finding the detected LAN interface using the interface's description.

### Listening for IP Reports
IP report listening is facilitated by the `ListenerManager` type. It manages a configured set of `IPRListener`s (one for each `IPRInterface`), capture writing, the processing & forwarding of captured packets to a unified readable channel.

#### Basic usage
```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// Create a new ListenerManager with the given config and logger
manager, err := iprd.NewListenerManager(cfg, logger)
if err != nil {
	// invalid configuration...
}

// Message handler func. Reads reports directly from the
// provided Reports() channel.
go func() {
	for {
		select {
		case report, ok := <-manager.Reports():
			if !ok {
				return
			}
			// further processing...
			fmt.Println(report)
		case <-ctx.Done():
			return
		}
	}
}()

// Start the listener manager; supervises IPRListeners derived from the config
if err := manager.Run(ctx); err != nil {
	// encountered fatal error...
}
```

### Listener health/statistics
`ListenerManager` provides a `Status()` method that returns current listener health/status and statistics for itself and all managed listeners. Returns the `ManagerStatus` struct.

### Broadcasting reports over TCP endpoint
`IPRBroadcast` provides a TCP endpoint for forwarding validated reports to multiple clients. Create one with `iprd.NewBroadcaster()`, start its accept loop with `Listen()`, then serialize each report (i.e., `IPRBroadcastMessage`) and send it to the broadcaster's `Msgs` channel.

```go
// Create a new broadcaster on port 7788, binding to all interfaces or specified bind address
broadcaster, err := iprd.NewBroadcaster(logger, "", 7788)
if err != nil {
	return err
}
// Optionally set status provider to get listener health/status
// via the `iprd_status` command
broadcaster.SetStatusProvider(manager)
// accept incoming connections
go broadcaster.Listen()

report := <-manager.Reports()
message, err := iprd.NewIPRBroadcastMessage(report)
if err != nil {
	return err
}
data, err := message.Marshal()
if err != nil {
	return err
}
broadcaster.Msgs <- data
```

The endpoint uses newline-delimited JSON. A client must first send an `iprd.TCPCommand` with `Command` set to `iprd.TCPCommandSubscribe`; it will then receive an `IPRBroadcastMessage` for each forwarded report. Sending `iprd.TCPCommandStatus` instead performs a one-shot status request and returns a `TCPResponse`. Configure the latter with `SetStatusProvider()` and, optionally, `SetDaemonInfo()`.

See [cmd/example/tcp_listener.go](https://github.com/bitcap-co/ipr-daemon/blob/main/cmd/example/tcp_listener.go) for a complete subscribing client.

### Service advertising over mDNS/DNS-SD
`MDNSAdvertiser` publishes the TCP endpoint as an `_iprd._tcp.local.` DNS-SD service. The advertisement includes TXT records identifying the protocol and the supported subscribe/status commands.

```go
advertiser, err := iprd.NewMDNSAdvertiser(bind, port, version, interfaceSelectors)
if err != nil {
	return err
}
defer advertiser.Close()
```

Interface selectors may be interface names or indexes. With a wildcard bind and no selectors, the service is advertised on every operational multicast interface. With an explicit bind address, the interface owning that address is always included. The advertiser watches for local interface changes and reloads the advertisement automatically; call `Close()` to withdraw it cleanly.

### IP Report Parsing & Validation
`iprd.NewIPReportPacket()` decodes a `gopacket.Packet` into an `IPReportPacket`, requiring Ethernet, IPv4, UDP, and a non-empty UDP payload. A `CapturedPacket` returned by a listener can be converted through its `ToIPRPacket()` helper.

Further validation is handled by `PacketProcessor`:

```go
processor := iprd.NewPacketProcessor(nil)
report, err := captured.ToIPRPacket()
if err == nil {
	err = processor.ParseIPReportPacket(report)
}
```

`ParseIPReportPacket()` identifies the miner type from its destination port, decompresses supported zlib payloads, validates known payload formats, and records accepted reports for duplicate detection. Reports from the same source MAC within ten seconds return `iprd.ErrDuplicatePacket`. A `PacketProcessor` should be shared wherever duplicate detection must also be shared, and calls to it must be serialized.

#### Parsing/Validating Supported IP Report Payloads
Known ports and payload models can be queried with `GetKnownMinerPorts()`, `GetMinerHintFromPort()`, `GetMsgPatternFromHint()`, and `NewIPReportFromHint()`. 

Structured payload parsing is exposed through the `IPReportModel` interface, which provides methods for parsing (`Parse()`) and extracting IP and MAC addresses from a raw report payload. `ParseIPAddress()` and `ParseMACAddress()` are also available for normalizing addresses found in report payloads.

### Offline packet processing
`iprd.ProcessCapture()` replays classic PCAP and PCAP-NG streams through the same decoding, validation, and duplicate-detection pipeline used for live captures. Its handler is called once per captured frame with an `OfflinePacketResult`, including the decoded packet, interface name, optional report, and processing error.

```go
file, err := os.Open("capture.pcapng")
if err != nil {
	return err
}
defer file.Close()

result, err := iprd.ProcessCapture(ctx, file, func(packet iprd.OfflinePacketResult) error {
	if packet.Err != nil {
		return nil // invalid or duplicate packet
	}
	fmt.Println(packet.Report)
	return nil
})
if err != nil {
	return err
}
fmt.Println(result)
```

The returned `OfflineResult` summarizes processed, valid, invalid, and duplicate packets. PCAP-NG input preserves per-packet interface names; classic PCAP packets use `classic` as their interface name.

### Example Usage
See [cmd/example/starter/main.go](https://github.com/bitcap-co/ipr-daemon/blob/main/cmd/example/starter/main.go) for a basic example program.
