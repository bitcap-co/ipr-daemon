package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var (
	flHost = flag.String("h", "127.0.0.1", "Host address of iprd instance. Default: localhost")
	flPort = flag.String("p", "7788", "Configured TCP forward port of iprd. Default: 7788")
)

func main() {
	flag.Parse()
	ipAddress := net.ParseIP(*flHost)
	if ipAddress == nil {
		log.Fatal("invalid IP address")
	}
	socketAddress := net.JoinHostPort(*flHost, *flPort)
	conn, err := net.Dial("tcp", socketAddress)
	if err != nil {
		log.Fatalf("error connecting: %s", err)
	}
	defer conn.Close()

	log.Println("Sending subscribe command...")
	var subCmd = iprd.TCPCommand{
		Command: "iprd_subscribe",
	}
	subscribeMsg, err := json.Marshal(subCmd)
	if err != nil {
		log.Fatalf("error marshalling subscribe message: %v", err)
	}
	_, err = conn.Write(append(subscribeMsg, '\n'))
	if err != nil {
		log.Fatalf("error sending subscribe message: %v", err)
	}

	log.Printf("Connected: %s <-> %s", conn.RemoteAddr().String(), conn.LocalAddr().String())

	reader := bufio.NewReader(conn)
	var obj iprd.IPRBroadcastMessage
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
		log.Printf("Received: [%s] -- TYPE:%s,IP:%s,MAC:%s", obj.PacketID, obj.MinerHint, obj.SrcIP, obj.SrcMAC)
	}
}
