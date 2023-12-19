package packet

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log/slog"
	"strings"
)

func AnalyzeHttp(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	payload := string(tcp.Payload)
	if payload == "" || !strings.Contains(payload, "HTTP") {
		return
	}

	isRequest := strings.HasPrefix(payload, "HTTP")
	msgPrefix := "HTTP Response"
	if isRequest {
		msgPrefix = "HTTP Request"
	}

	networkFlow := packet.NetworkLayer().NetworkFlow()
	src, dst := networkFlow.Endpoints()

	slog.Info(fmt.Sprintf("%s, src: %v, dst: %v, payload: %s\n", msgPrefix, src, dst, payload))
}
