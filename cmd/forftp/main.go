package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "time"

    "forftp/internal/snmpscan"
)

func main() {
    target := flag.String("t", "", "Target IP or hostname")
    protocol := flag.String("protocol", "snmp", "Protocol to scan (snmp)")
    timeoutMs := flag.Int("timeout", 2000, "Timeout in ms")
    port := flag.Int("p", 161, "SNMP port")
    flag.Parse()

    if *target == "" {
        fmt.Println("Usage: forftp -t <target> --protocol snmp")
        os.Exit(1)
    }

    if *protocol != "snmp" {
        log.Fatalf("unsupported protocol: %s", *protocol)
    }

    res, err := snmpscan.Scan(*target, *port, time.Duration(*timeoutMs)*time.Millisecond)
    if err != nil {
        log.Fatalf("SNMP scan error: %v", err)
    }

    fmt.Println(res.Render())
}

