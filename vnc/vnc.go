package vnc

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"forftp/utils"
)

type VNCResult struct {
	Target  string
	Version string
	NoAuth  bool
	Error   string
}

func (r VNCResult) String() string {
	if r.Error != "" {
		return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("VNC Hata:"), utils.Colorize(r.Error, utils.ColorRed))
	}
	var b strings.Builder
	b.WriteString(utils.BoldText(utils.Colorize("VNC", utils.ColorCyan)))
	b.WriteString(" ")
	b.WriteString(utils.Colorize(r.Target, utils.ColorYellow))
	b.WriteString(" ")
	b.WriteString(utils.Colorize(r.Version, utils.ColorGreen))
	if r.NoAuth {
		b.WriteString(" ")
		b.WriteString(utils.Colorize("NoAuth", utils.ColorRed))
	}
	return b.String()
}

// ScanVNC connects to TCP 5900, reads RFB version and checks if NoAuth is offered.
func ScanVNC(target string, timeout time.Duration) VNCResult {
	addr := fmt.Sprintf("%s:%d", target, 5900)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return VNCResult{Target: target, Error: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	// Server sends 12-byte version string, e.g., "RFB 003.008\n"
	verBytes := make([]byte, 12)
	if _, err := reader.Read(verBytes); err != nil {
		return VNCResult{Target: target, Error: fmt.Sprintf("read version: %v", err)}
	}
	serverVer := string(verBytes)
	serverVer = strings.TrimSpace(serverVer)
	if !strings.HasPrefix(serverVer, "RFB ") {
		return VNCResult{Target: target, Error: "not RFB"}
	}

	// Echo back the same version
	if _, err := conn.Write(append([]byte(serverVer), '\n')); err != nil {
		return VNCResult{Target: target, Error: fmt.Sprintf("write version: %v", err)}
	}

	noAuth := false
	verNum := parseRFBVersion(serverVer)
	if verNum <= 3.3 {
		// RFB 3.3: 4-byte security type
		sec := make([]byte, 4)
		if _, err := reader.Read(sec); err == nil {
			// type 1 == None
			if sec[3] == 1 || (sec[0] == 0 && sec[1] == 0 && sec[2] == 0 && sec[3] == 1) {
				noAuth = true
			}
		}
	} else {
		// RFB 3.7 and later: list of security types
		nb, err := reader.ReadByte()
		if err == nil && nb > 0 && nb < 16 {
			types := make([]byte, int(nb))
			if _, err := reader.Read(types); err == nil {
				for _, t := range types {
					if t == 1 { noAuth = true; break }
				}
			}
		}
	}

	return VNCResult{Target: target, Version: serverVer, NoAuth: noAuth}
}

func parseRFBVersion(s string) float64 {
	// s like "RFB 003.008"
	parts := strings.Fields(s)
	if len(parts) < 2 { return 0 }
	v := parts[1]
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "0")
	if v == "" { return 0 }
	// Replace last dot with decimal point, e.g., 003.008 -> 3.8
	nums := strings.Split(v, ".")
	if len(nums) == 2 {
		maj := strings.TrimLeft(nums[0], "0")
		if maj == "" { maj = "0" }
		min := strings.TrimLeft(nums[1], "0")
		if min == "" { min = "0" }
		f, _ := strconv.ParseFloat(maj+"."+min, 64)
		return f
	}
	return 0
}

