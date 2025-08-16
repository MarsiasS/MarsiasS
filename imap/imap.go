package imap

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// IMAPResult holds scan results for an IMAP endpoint
type IMAPResult struct {
	Target            string
	Port              int
	Banner            string
	InfoLeak          bool
	STARTTLS          bool
	PlaintextAuth     bool
	PlaintextAuthResp string
}

// RunIMAP runs IMAP scan for standard ports 143 (plain with optional STARTTLS) and 993 (implicit TLS)
func RunIMAP(target string, timeoutSec int) []*IMAPResult {
	timeout := time.Duration(timeoutSec) * time.Second
	imapPorts := []int{143, 993}
	var results []*IMAPResult

	for _, port := range imapPorts {
		res := &IMAPResult{Target: target, Port: port}
		banner, starttls, plaintext, plaintextResp, err := scanPort(target, port, timeout)
		if err != nil {
			// Append result even if closed/unreachable to preserve output shape
			results = append(results, res)
			continue
		}

		res.Banner = banner
		res.InfoLeak = hasInfoLeak(banner)
		res.STARTTLS = starttls
		res.PlaintextAuth = plaintext
		res.PlaintextAuthResp = plaintextResp
		results = append(results, res)
	}

	return results
}

func scanPort(target string, port int, timeout time.Duration) (banner string, starttls bool, plaintextAllowed bool, plaintextResp string, err error) {
	if port == 993 {
		return scanIMAPTLS(target, port, timeout)
	}
	return scanIMAPPlain(target, port, timeout)
}

func scanIMAPPlain(target string, port int, timeout time.Duration) (banner string, starttls bool, plaintextAllowed bool, plaintextResp string, err error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		return "", false, false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := textproto.NewWriter(bufio.NewWriter(conn))

	// server greeting (untagged)
	greet, _ := reader.ReadLine()
	banner = strings.TrimSpace(greet)

	capabilities, starttlsSupported, logindisabled := fetchCapabilities(reader, writer, timeout)
	starttls = starttlsSupported

	// Determine if plaintext login is allowed on the current (unencrypted) connection
	// If LOGINDISABLED is present, plaintext login should be disabled until STARTTLS
	if logindisabled {
		plaintextAllowed = false
		return
	}

	// If capabilities advertise LOGIN or AUTH=PLAIN, attempt a safe LOGIN to test policy
	if hasLoginCapability(capabilities) {
		tag := "B001"
		_ = writer.PrintfLine("%s LOGIN test test", tag)
		_ = writer.W.Flush()
		var respLines []string
		for {
			line, rerr := reader.ReadLine()
			if rerr != nil {
				break
			}
			respLines = append(respLines, line)
			if strings.HasPrefix(line, tag+" OK") || strings.HasPrefix(line, tag+" NO") || strings.HasPrefix(line, tag+" BAD") {
				break
			}
		}
		plaintextResp = strings.TrimSpace(strings.Join(respLines, "\n"))

		upperResp := strings.ToUpper(plaintextResp)
		// If server responds BAD and mentions TLS/ENCRYPTION required, then plaintext is not allowed
		if strings.Contains(upperResp, "TLS") || strings.Contains(upperResp, "ENCRYPT") || strings.Contains(upperResp, "STARTTLS") || strings.Contains(upperResp, "LOGINDISABLED") {
			plaintextAllowed = false
		} else {
			// NO or OK both indicate that LOGIN command can be processed on plaintext channel
			plaintextAllowed = true
		}
	} else {
		plaintextAllowed = false
	}

	return
}

func scanIMAPTLS(target string, port int, timeout time.Duration) (banner string, starttls bool, plaintextAllowed bool, plaintextResp string, err error) {
	dialer := &net.Dialer{Timeout: timeout}
	tlsConf := &tls.Config{InsecureSkipVerify: true, ServerName: target}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", target, port), tlsConf)
	if err != nil {
		return "", false, false, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := textproto.NewWriter(bufio.NewWriter(conn))

	greet, _ := reader.ReadLine()
	banner = strings.TrimSpace(greet)

	capabilities, _, _ := fetchCapabilities(reader, writer, timeout)
	_ = capabilities

	// On implicit TLS, plaintext over the wire is already encrypted, so we do not flag it as plaintext vulnerability
	plaintextAllowed = false
	starttls = false
	plaintextResp = ""
	return
}

func fetchCapabilities(reader *textproto.Reader, writer *textproto.Writer, timeout time.Duration) (capabilities []string, hasStartTLS bool, hasLoginDisabled bool) {
	tag := "A001"
	_ = writer.PrintfLine("%s CAPABILITY", tag)
	_ = writer.W.Flush()
	var caps []string
	for i := 0; i < 200; i++ { // reasonable upper bound to avoid infinite loop
		line, err := reader.ReadLine()
		if err != nil {
			break
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(line, "*") && strings.Contains(upper, "CAPABILITY") {
			// Example: * CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN
			// collect tokens after CAPABILITY keyword
			idx := strings.Index(upper, "CAPABILITY")
			if idx >= 0 {
				fields := strings.Fields(line[idx+len("CAPABILITY"):])
				for _, f := range fields {
					caps = append(caps, strings.TrimSpace(f))
				}
			}
			continue
		}
		if strings.HasPrefix(line, tag+" OK") || strings.HasPrefix(line, tag+" BAD") || strings.HasPrefix(line, tag+" NO") {
			break
		}
	}

	upperCaps := make([]string, 0, len(caps))
	for _, c := range caps {
		upperCaps = append(upperCaps, strings.ToUpper(c))
	}
	capabilities = upperCaps
	for _, c := range upperCaps {
		if c == "STARTTLS" {
			hasStartTLS = true
		}
		if c == "LOGINDISABLED" {
			hasLoginDisabled = true
		}
	}
	return
}

func hasLoginCapability(capabilities []string) bool {
	for _, c := range capabilities {
		if c == "LOGIN" || strings.HasPrefix(c, "AUTH=") || strings.Contains(c, "LOGIN") || strings.Contains(c, "PLAIN") {
			return true
		}
	}
	return false
}

func hasInfoLeak(banner string) bool {
	b := strings.ToLower(banner)
	if b == "" {
		return false
	}
	// Common IMAP server products that often leak in greeting/banners
	leakers := []string{"dovecot", "cyrus", "courier", "uw-imap", "imap"}
	for _, k := range leakers {
		if strings.Contains(b, k) {
			return true
		}
	}
	return false
}