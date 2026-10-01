// Command link-relay is the Link relay. It is configured by the environment variables of
// spec/protocol.md section 9; with none set it is a self-hosted relay on :8080 with every
// limit off.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/frontierengineer/link/relay/internal/relay"
)

func main() {
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: link-relay (configured by LINK_* environment variables, see spec/protocol.md section 9)")
		os.Exit(2)
	}
	cfg, err := relay.FromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		log.Fatal(err)
	}
	s := relay.New(cfg)
	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()
	log.Printf("link-relay listening on %s", ln.Addr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	select {
	case <-sig:
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
	log.Print("link-relay shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
