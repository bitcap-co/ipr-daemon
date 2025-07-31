package main

import (
	"fmt"
	"log"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func main() {
	iface, err := iprd.FindLANInterface()
	if err != nil {
		log.Panicln(err)
	}
	fmt.Printf("%+v\n", *iface)
	if iface.IsUp() {
		fmt.Println("interface is up!")
	}
	if iface.IsLan() {
		fmt.Println("interface is marked LAN.")
	}
}
