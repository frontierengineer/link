// Command vectors writes spec/vectors/relay.json. Run it from relay/:
//
//	go run ./cmd/vectors
package main

import (
	"flag"
	"log"
	"os"

	"github.com/frontierengineer/link/relay/internal/vectors"
)

func main() {
	out := flag.String("o", "../spec/vectors/relay.json", "the file to write")
	flag.Parse()
	b, err := vectors.Generate()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}
