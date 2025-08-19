package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func main() {
	var (
		flHost = flag.String("host", "", "host addr")
		flPort = flag.Int("port", 7788, "tcp port")
	)
	flag.Parse()
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", *flHost, *flPort))
	if err != nil {
		log.Fatalf("error connecting: %s", err)
	}
	defer conn.Close()

	log.Println("Sending subscribe command...")
	var subMsgObj = iprd.IPRSubscribeMessage{
		Command: "iprd_subscribe",
	}
	subscribeMsg, err := json.Marshal(subMsgObj)
	if err != nil {
		log.Fatalf("error marshalling subscribe message: %v", err)
	}
	_, err = conn.Write(append(subscribeMsg, '\n'))
	if err != nil {
		log.Fatalf("error sending subscribe message: %v", err)
	}

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
