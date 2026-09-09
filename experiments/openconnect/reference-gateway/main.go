// This optional test driver imports the user's reference checkout at build time.
// No reference implementation is copied into meow-rs or linked into its product.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	fixture "github.com/metacubex/mihomo/internal/testutil/openconnect"
)

type echo struct{}

func (echo) HandlePacket(packet []byte) ([]byte, error) {
	return append([]byte(nil), packet...), nil
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: reference-gateway psk|injected|legacy CA_PATH")
	}
	scenario := fixture.BasicAnyConnectScenario()
	switch os.Args[1] {
	case "psk":
		scenario.ModernDTLS = true
	case "injected":
		scenario.ModernDTLS = true
		scenario.InjectedDTLS = true
	case "legacy":
		scenario.LegacyDTLS = true
	default:
		panic("unknown mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gateway, err := fixture.StartAnyConnectGateway(ctx, scenario, echo{}, nil)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := gateway.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	if err := os.WriteFile(os.Args[2], fixture.AnyConnectRootCAPEM(), 0600); err != nil {
		panic(err)
	}
	fmt.Println(gateway.Address())
	fmt.Println(gateway.ServerName())
	_, _ = io.Copy(io.Discard, os.Stdin)
}
