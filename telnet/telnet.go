package telnet

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"time"
	"unicode"
	"forftp/utils"
)

type TelnetResult struct {
	Target string
	Banner string
	Error  string
}

func (r TelnetResult) String() string {
	if r.Error != "" { return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("Telnet Hata:"), utils.Colorize(r.Error, utils.ColorRed)) }
	return fmt.Sprintf("%s %s %s", utils.BoldText(utils.Colorize("Telnet", utils.ColorCyan)), utils.Colorize(r.Target, utils.ColorYellow), utils.Colorize(r.Banner, utils.ColorGreen))
}

func ScanTelnet(target string, timeout time.Duration) TelnetResult {
	addr := fmt.Sprintf("%s:%d", target, 23)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil { return TelnetResult{Target: target, Error: err.Error()} }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	buf := make([]byte, 512)
	n, _ := reader.Read(buf)
	clean := stripTelnet(buf[:n])
	return TelnetResult{Target: target, Banner: clean}
}

func stripTelnet(b []byte) string {
	// Remove telnet IAC negotiation and non-printables; keep basic banner text
	out := bytes.NewBuffer(nil)
	for i := 0; i < len(b); i++ {
		if b[i] == 0xff { // IAC
			if i+1 < len(b) {
				cmd := b[i+1]
				if cmd >= 0xf0 && cmd <= 0xff {
					// skip IAC + cmd + optional option byte
					if i+2 < len(b) { i += 2 } else { i++ }
					continue
				}
			}
			continue
		}
		r := rune(b[i])
		if r == '\n' || r == '\r' || unicode.IsPrint(r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}

