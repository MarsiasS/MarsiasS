package main

import (
	"flag"
	"fmt"
	"os"
	"time"
	"forftp/common"
	"forftp/vnc"
	"forftp/ntp"
	"forftp/telnet"
	"forftp/ipmi"
)

func main() {
	protocol := flag.String("protocol", "vnc", "Protokol (vnc, ntp, telnet, ipmi)")
	target := flag.String("t", "", "Hedef IP adresi")
	timeout := flag.Int("timeout", 5, "Zaman aşımı süresi (saniye)")
	flag.Parse()

	if *target == "" { fmt.Println("[-] Hedef IP belirtilmeli (-t)"); os.Exit(1) }
	config := common.ScanConfig{Protocol: *protocol, Target: *target, Timeout: time.Duration(*timeout) * time.Second}

	switch config.Protocol {
	case "vnc":
		res := vnc.ScanVNC(config.Target, config.Timeout)
		fmt.Println(res.String())
	case "ntp":
		res := ntp.ScanNTP(config.Target, config.Timeout)
		fmt.Println(res.String())
	case "telnet":
		res := telnet.ScanTelnet(config.Target, config.Timeout)
		fmt.Println(res.String())
	case "ipmi":
		res := ipmi.ScanIPMI(config.Target, config.Timeout)
		fmt.Println(res.String())
	default:
		fmt.Println("[-] Desteklenmeyen protokol!")
		os.Exit(1)
	}
}

