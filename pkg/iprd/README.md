## iprd
This package serves as the core lib for the IP Reporter daemon (iprd).

## Stucture
### `interface.go`
This defines the `IPRInterface` type and provides functions to enumerate over the system's network interfaces to find valid interfaces to attach to.
The two main functions that it provides are `GetInterfaceByName` and `FindLANInterface`.

### `packet.go`
This defines the `IPRReportPacket` type and analyzes the incoming packets on the wire for IP Report packets. An IP Report packet is simply defined as a UDP packet that contains its own source IP address within the datagram.

Using `IsValidIPReportPacket` will return an IPRReportPacket if packet is deemed a IP Report packet. 

### `broadcast.go`
This handles the broadcasting logic, allowing clients to subscribe using the JSON formatted command `{"command": "iprd_subscribe"}`.
Once a packet is received, all subscribed clients will be sent the packet data marshalled as `IPRBroadcastMessage`:
```
type IPRBroadcastMessage struct {
	PacketID  string        `json:"id"`
	SrcIP     string        `json:"src_ip"`
	SrcMAC    string        `json:"src_mac"`
	MinerType MinerTypeHint `json:"miner_type"`
}
```
Each packet gets a UUID (`id`).
