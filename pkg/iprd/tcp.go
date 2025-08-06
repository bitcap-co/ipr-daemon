package iprd

import (
	"encoding/json"

	"github.com/google/uuid"
)

type IPRJSONObject struct {
	ID      uuid.UUID `json:"id"`
	IPAddr  string    `json:"ip_addr"`
	MACAddr string    `json:"mac_addr"`
}

func GetMarshalledJSONData(packet IPRReportPacket) ([]byte, error) {
	// Generate packet uuid
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	jsonObj := IPRJSONObject{
		ID:      id,
		IPAddr:  packet.SrcIP,
		MACAddr: packet.SrcMAC,
	}
	data, err := json.Marshal(jsonObj)
	if err != nil {
		return nil, err
	}
	return data, nil
}
