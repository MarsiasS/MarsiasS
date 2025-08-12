package main

import (
	"flag"
	"fmt"
	"time"

	"example.com/nfsscan/nfs"
)

func main() {
	target := flag.String("target", "127.0.0.1", "Target host or IP")
	timeout := flag.Duration("timeout", 3*time.Second, "Timeout per check")
	flag.Parse()

	res := nfs.ScanNFS(*target, *timeout)
	fmt.Println(res.String())
}