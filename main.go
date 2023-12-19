package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/jaeyo/http-analyzer/pkg/packet"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	iface, err := configure()
	if err != nil {
		slog.Error(fmt.Sprintf("failed to configure: %s", err))
		return
	}

	ctx := listenTermination()

	packetSource, closeFn, err := packet.GetPacketSource(iface)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to get source: %s", err))
		return
	}
	defer closeFn()

	onPacket := packet.AnalyzeHttp

	for {
		select {
		case <-ctx.Done():
			return
		case pk, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			onPacket(pk)
		}
	}
}

func configure() (string, error) {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	var iface string
	fs.StringVar(&iface, "iface", "eth0", "interface to listen")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return "", fmt.Errorf("failed to parse arguments: %w", err)
	}

	return iface, nil
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
