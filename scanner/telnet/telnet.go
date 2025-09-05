package telnet

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// TelnetResult represents the outcome of a Telnet scan
type TelnetResult struct {
	Target         string
	Port           int
	Open           bool
	Banner         string
	LoginPrompt    bool
	DetectedDevice string
	Vulnerabilities []string
	ErrorMessage   string
}

// String formats the result for human-friendly output
func (r TelnetResult) String() string {
	status := "[-]"
	if r.Open {
		status = "[+]"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s Telnet scan for %s:%d\n", status, r.Target, r.Port))
	if r.ErrorMessage != "" {
		b.WriteString(fmt.Sprintf("    Error: %s\n", r.ErrorMessage))
	}
	if r.Banner != "" {
		b.WriteString(fmt.Sprintf("    Banner: %s\n", sanitizeNewlines(r.Banner)))
	}
	b.WriteString(fmt.Sprintf("    Login prompt detected: %v\n", r.LoginPrompt))
	if r.DetectedDevice != "" {
		b.WriteString(fmt.Sprintf("    Detected device: %s\n", r.DetectedDevice))
	}
	if len(r.Vulnerabilities) > 0 {
		b.WriteString("    Findings:\n")
		for i, v := range r.Vulnerabilities {
			b.WriteString(fmt.Sprintf("      %d. %s\n", i+1, v))
		}
	}
	return b.String()
}

// ScanTelnet connects to TCP/23, performs minimal option negotiation, reads the banner/prompt,
// and reports basic security findings.
func ScanTelnet(target string, timeout time.Duration) TelnetResult {
	result := TelnetResult{
		Target: target,
		Port:   23,
	}

	addr := fmt.Sprintf("%s:%d", target, result.Port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Open = false
		result.ErrorMessage = err.Error()
		return result
	}
	defer conn.Close()
	result.Open = true

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Nudge the server to show a prompt/banner
	_, _ = conn.Write([]byte("\r\n"))

	var visible bytes.Buffer
	reader := bufio.NewReader(conn)

	readUntil := time.Now().Add(timeout)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		chunk := make([]byte, 1024)
		n, readErr := reader.Read(chunk)
		if n > 0 {
			vis := handleTelnetNegotiation(conn, chunk[:n])
			if len(vis) > 0 {
				visible.Write(vis)
			}
			if hasPromptKeywords(visible.String()) || visible.Len() > 4096 {
				break
			}
		}
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				if time.Now().After(readUntil) {
					break
				}
				continue
			}
			if readErr == io.EOF {
				break
			}
			// Non-timeout error
			result.ErrorMessage = readErr.Error()
			break
		}
	}

	result.Banner = strings.TrimSpace(visible.String())
	lower := strings.ToLower(result.Banner)
	result.LoginPrompt = strings.Contains(lower, "login:") || strings.Contains(lower, "username:") || strings.Contains(lower, "user:") || strings.Contains(lower, "password:")
	result.DetectedDevice = detectDevice(result.Banner)
	result.Vulnerabilities = evaluateFindings(result)

	return result
}

// Telnet protocol bytes
const (
	iac  = 255 // Interpret As Command
	will = 251
	wont = 252
	doCmd = 253
	dont = 254
)

// handleTelnetNegotiation filters out Telnet IAC sequences and responds conservatively
// to avoid option negotiation. Returns only human-visible bytes.
func handleTelnetNegotiation(conn net.Conn, data []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(data); {
		if data[i] == iac {
			// Need at least 3 bytes: IAC <cmd> <opt>
			if i+2 >= len(data) {
				break
			}
			cmd := data[i+1]
			opt := data[i+2]
			// Reply with DONT/WONT for any WILL/DO to keep things simple
			switch cmd {
			case will:
				_, _ = conn.Write([]byte{iac, dont, opt})
			case doCmd:
				_, _ = conn.Write([]byte{iac, wont, opt})
			}
			i += 3
			continue
		}
		out.WriteByte(data[i])
		i++
	}
	return out.Bytes()
}

func hasPromptKeywords(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "login:") || strings.Contains(l, "username:") || strings.Contains(l, "user:") || strings.Contains(l, "password:") || strings.Contains(l, "press any key") || strings.Contains(l, "welcome")
}

func detectDevice(banner string) string {
	l := strings.ToLower(banner)
	switch {
	case strings.Contains(l, "busybox"):
		return "BusyBox/Linux"
	case strings.Contains(l, "mikrotik") || strings.Contains(l, "routeros"):
		return "MikroTik RouterOS"
	case strings.Contains(l, "cisco"):
		return "Cisco"
	case strings.Contains(l, "sonicwall"):
		return "SonicWALL"
	case strings.Contains(l, "hp") && strings.Contains(l, "switch"):
		return "HP Switch"
	case strings.Contains(l, "vxworks"):
		return "VxWorks"
	case strings.Contains(l, "freebsd"):
		return "FreeBSD"
	case strings.Contains(l, "linux"):
		return "Linux"
	case strings.Contains(l, "win"):
		return "Windows"
	default:
		return ""
	}
}

func evaluateFindings(r TelnetResult) []string {
	findings := []string{"Telnet service exposes credentials and data in plaintext (disable or use SSH)"}
	if r.LoginPrompt {
		findings = append(findings, "Interactive login over Telnet detected; enforce SSH and disable Telnet")
	}
	if r.DetectedDevice != "" {
		// High-level notes for common devices
		switch r.DetectedDevice {
		case "MikroTik RouterOS":
			findings = append(findings, "RouterOS historically allowed empty admin password on old versions; ensure strong creds and latest firmware")
		case "BusyBox/Linux":
			findings = append(findings, "Embedded devices often ship with default creds (e.g., root:admin). Verify credentials are changed")
		case "Cisco":
			findings = append(findings, "Verify vty lines require SSH only and local/AAA auth; disable Telnet on vty")
		}
	}
	if strings.Contains(strings.ToLower(r.Banner), "debug") {
		findings = append(findings, "Debug mode strings visible in banner; sanitize banners")
	}
	return findings
}

func sanitizeNewlines(s string) string {
	// Compress newlines and whitespace for single-line banner output
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

