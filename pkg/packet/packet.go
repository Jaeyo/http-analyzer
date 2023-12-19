package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

const (
	MaxPacketSize  = 65536
	PollingTimeout = 5 * time.Second
)

func GetPacketSource(iface string) (*gopacket.PacketSource, func(), error) {
	handle, err := pcap.OpenLive(iface, MaxPacketSize, true, PollingTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open handle for device: %w", err)
	}

	return gopacket.NewPacketSource(handle, handle.LinkType()), func() { handle.Close() }, nil
}
