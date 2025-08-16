package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"imapscan/imap"
)

func main() {
	target := flag.String("target", "127.0.0.1", "Target host or IP")
	timeout := flag.Int("timeout", 5, "Timeout in seconds")
	flag.Parse()

	results := imap.RunIMAP(*target, *timeout)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %v\n", err)
		os.Exit(1)
	}
}