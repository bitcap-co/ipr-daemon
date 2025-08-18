package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var localPort = 7788

func main() {
	conn, err := net.Dial("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		log.Fatalf("error connecting: %s", err)
	}
	defer conn.Close()

	log.Printf("Connected: %s <-> %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	reader := bufio.NewReader(conn)
	var obj iprd.IPRJSONObject
	for {
		data, err := reader.ReadBytes('\n')
		if err != nil {
			log.Println("error reading for server:", err)
			return
		}
		err = json.Unmarshal(data, &obj)
		if err != nil {
			log.Println("error unmarshalling json:", err)
		}
		log.Printf("Receieved: [%s] -- IP:%s,MAC:%s", obj.ID, obj.IPAddr, obj.MACAddr)
	}
}
