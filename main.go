package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const MaxPacketSize = 1600

var PcapTimeout = 5 * time.Second

func main() {
	iface, port, err := configure()
	if err != nil {
		slog.Error(fmt.Sprintf("failed to configure: %s", err))
		return
	}

	ctx := listenTermination()

	if err := analyze(ctx, iface, port, analyzeHttpFromPacket); err != nil {
		slog.Error(fmt.Sprintf("failed to analyze: %s", err))
		return
	}
}

func configure() (string, int, error) {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var iface, portStr string
	fs.StringVar(&iface, "iface", "eth0", "interface to listen")
	fs.StringVar(&portStr, "port", "80", "port to listen")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return "", -1, fmt.Errorf("failed to parse arguments: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", -1, fmt.Errorf("invalid port: %s", portStr)
	}

	return iface, port, nil
}

func listenTermination() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)

	go func() {
		<-sigs
		cancel()
	}()

	return ctx
}

func analyze(ctx context.Context, iface string, port int, onPacket func(gopacket.Packet)) error {
	handle, err := pcap.OpenLive(iface, MaxPacketSize, true, PcapTimeout)
	if err != nil {
		return fmt.Errorf("failed to open handle for device: %w", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("tcp and port %d", port)); err != nil {
		return fmt.Errorf("failed to set bpf filter (port: %d): %w", port, err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-ctx.Done():
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			onPacket(packet)
		}
	}

	return nil
}

func analyzeHttpFromPacket(packet gopacket.Packet) {
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
