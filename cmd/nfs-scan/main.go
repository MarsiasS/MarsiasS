package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"example.com/nfssec/nfs"
)

func main() {
	target := flag.String("target", "", "Target host or IP")
	timeout := flag.Duration("timeout", 3*time.Second, "Timeout per operation")
	jsonOut := flag.Bool("json", false, "Output JSON")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: nfs-scan -target <host> [-timeout 3s] [--json]")
		os.Exit(2)
	}

	res := nfs.ScanNFS(*target, *timeout)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}
	fmt.Println(res.String())
}