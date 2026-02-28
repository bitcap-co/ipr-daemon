## iprd
This package serves as the core library for the IP Reporter daemon (iprd). It provides all the necessary tooling to sniff IP Report packets from ASIC miners on a local network.

#### Documentation
Run `go doc -http` for more information on what is included.

#### Example Usage
```go
func main() {
	// getting a network interface
	iface, err := iprd.GetInterfaceByName("eth0")
	if err != nil {
			log.Fatal(err)
	}
	// initializing and activating a IPRListener on iface
	listener := iprd.NewIPRListener(nil, false, iface)
	if err := listener.Activate(); err != nil {
			log.Fatal(err)
	}
	// start listening
	listener.Listen()
}
```
