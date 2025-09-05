package mysql

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type MySQLResult struct {
	Target          string
	Port            int
	Open            bool
	ProtocolVersion byte
	ServerVersion   string
	ConnectionID    uint32
	Capabilities    uint32
	StatusFlags     uint16
	CharacterSet    byte
	AuthPlugin      string
	SSLSupported    bool
	AuthPluginData  []byte
	Vulnerabilities []string
	ErrorMessage    string
}

func (r MySQLResult) String() string {
	status := "[-]"
	if r.Open { status = "[+]" }
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s MySQL scan for %s:%d\n", status, r.Target, r.Port))
	if r.ErrorMessage != "" {
		b.WriteString(fmt.Sprintf("    Error: %s\n", r.ErrorMessage))
		return b.String()
	}
	b.WriteString(fmt.Sprintf("    Protocol: %d, Server: %s\n", r.ProtocolVersion, r.ServerVersion))
	b.WriteString(fmt.Sprintf("    Caps: 0x%08x, Charset: %d, Status: 0x%04x\n", r.Capabilities, r.CharacterSet, r.StatusFlags))
	b.WriteString(fmt.Sprintf("    Auth plugin: %s, SSL supported: %v\n", r.AuthPlugin, r.SSLSupported))
	if len(r.Vulnerabilities) > 0 {
		b.WriteString("    Findings:\n")
		for i, v := range r.Vulnerabilities { b.WriteString(fmt.Sprintf("      %d. %s\n", i+1, v)) }
	}
	return b.String()
}

type MySQLAuthResult struct {
	Target       string
	Port         int
	Username     string
	Password     string
	Success      bool
	ErrorMessage string
}

func (r MySQLAuthResult) String() string {
	status := "[-]"; if r.Success { status = "[+]" }
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s MySQL auth %s:%d %s:%q -> error: %s", status, r.Target, r.Port, r.Username, r.Password, r.ErrorMessage)
	}
	return fmt.Sprintf("%s MySQL auth %s:%d %s:%q", status, r.Target, r.Port, r.Username, r.Password)
}

// ScanMySQL connects, parses handshake v10, and reports basic capabilities and risks.
func ScanMySQL(target string, timeout time.Duration) MySQLResult {
	res := MySQLResult{ Target: target, Port: 3306 }
	addr := fmt.Sprintf("%s:%d", target, res.Port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil { res.ErrorMessage = err.Error(); return res }
	defer conn.Close(); res.Open = true
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Read initial handshake packet
	pkt, _, err := readPacket(conn)
	if err != nil { res.ErrorMessage = err.Error(); return res }
	if len(pkt) == 0 { res.ErrorMessage = "empty handshake"; return res }
	if pkt[0] < 0x0a { res.ErrorMessage = "unexpected protocol"; return res }
	res.ProtocolVersion = pkt[0]
	pos := 1
	serverVersion, n := readNullTerminated(pkt[pos:])
	res.ServerVersion = serverVersion; pos += n
	if pos+4 > len(pkt) { res.ErrorMessage = "short handshake (conn id)"; return res }
	res.ConnectionID = binary.LittleEndian.Uint32(pkt[pos:pos+4]); pos += 4
	if pos+8 > len(pkt) { res.ErrorMessage = "short handshake (salt part1)"; return res }
	auth1 := pkt[pos:pos+8]; pos += 8
	if pos+1 > len(pkt) { res.ErrorMessage = "short handshake (filler)"; return res }
	pos += 1 // filler
	if pos+2 > len(pkt) { res.ErrorMessage = "short handshake (caps lo)"; return res }
	capsLow := binary.LittleEndian.Uint16(pkt[pos:pos+2]); pos += 2
	var capsHigh uint16
	var charset byte
	var status uint16
	var authDataLen byte
	// the rest may or may not be present
	if pos < len(pkt) {
		if pos+1 > len(pkt) { goto finalize }
		charset = pkt[pos]; pos++
		if pos+2 > len(pkt) { goto finalize }
		status = binary.LittleEndian.Uint16(pkt[pos:pos+2]); pos += 2
		if pos+2 > len(pkt) { goto finalize }
		capsHigh = binary.LittleEndian.Uint16(pkt[pos:pos+2]); pos += 2
		if pos+1 > len(pkt) { goto finalize }
		authDataLen = pkt[pos]; pos++
		if pos+10 > len(pkt) { goto finalize }
		pos += 10 // reserved
		remain := int(authDataLen)
		if remain < 13 { remain = 13 }
		if pos+remain-8 <= len(pkt) { // part2 length may vary; -8 because first part already 8
			auth2 := pkt[pos:pos+remain-8]
			pos += remain - 8
			authData := make([]byte, 0, 20)
			authData = append(authData, auth1...)
			authData = append(authData, auth2...)
			res.AuthPluginData = authData
		}
		// plugin name
		if pos < len(pkt) {
			name, m := readNullTerminated(pkt[pos:])
			res.AuthPlugin = name
			_ = m
		}
	}
finalize:
	res.Capabilities = uint32(capsLow) | (uint32(capsHigh) << 16)
	res.CharacterSet = charset
	res.StatusFlags = status
	res.SSLSupported = (res.Capabilities & 0x00000800) != 0 // CLIENT_SSL
	res.Vulnerabilities = evaluateFindings(&res)
	return res
}

// BruteForceMySQL tries username/password combinations concurrently using mysql_native_password.
func BruteForceMySQL(target string, usernames, passwords []string, timeout time.Duration, concurrency int) []MySQLAuthResult {
	if concurrency <= 0 { concurrency = 5 }
	type combo struct{ u, p string }
	jobs := make(chan combo)
	results := make([]MySQLAuthResult, 0, len(usernames)*len(passwords))
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for c := range jobs {
			ok, err := tryNativePassword(target, c.u, c.p, timeout)
			mu.Lock()
			results = append(results, MySQLAuthResult{
				Target: target, Port: 3306, Username: c.u, Password: c.p, Success: ok, ErrorMessage: errStr(err),
			})
			mu.Unlock()
		}
	}
	for i := 0; i < concurrency; i++ { wg.Add(1); go worker() }
	for _, u := range usernames {
		for _, p := range passwords { jobs <- combo{u: u, p: p} }
	}
	close(jobs); wg.Wait()
	return results
}

// tryNativePassword performs minimal 4.1+ auth against mysql_native_password.
func tryNativePassword(target, username, password string, timeout time.Duration) (bool, error) {
	addr := fmt.Sprintf("%s:%d", target, 3306)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil { return false, err }
	defer conn.Close(); _ = conn.SetDeadline(time.Now().Add(timeout))

	// Read handshake
	handshake, _, err := readPacket(conn)
	if err != nil { return false, err }
	if len(handshake) == 0 { return false, errors.New("empty handshake") }
	if handshake[0] < 0x0a { return false, errors.New("unsupported protocol") }
	pos := 1
	_, n := readNullTerminated(handshake[pos:]); pos += n
	if pos+4 > len(handshake) { return false, errors.New("short handshake") }
	pos += 4 // connection id
	if pos+8 > len(handshake) { return false, errors.New("short handshake") }
	salt1 := handshake[pos:pos+8]; pos += 8
	if pos+1 > len(handshake) { return false, errors.New("short handshake") }
	pos++ // filler
	if pos+2 > len(handshake) { return false, errors.New("short handshake") }
	capsLow := binary.LittleEndian.Uint16(handshake[pos:pos+2]); pos += 2
	var capsHigh uint16
	var authDataLen byte
	var charset byte
	var status uint16
	if pos < len(handshake) {
		if pos+1 > len(handshake) { return false, errors.New("short handshake") }
		charset = handshake[pos]; pos++
		if pos+2 > len(handshake) { return false, errors.New("short handshake") }
		status = binary.LittleEndian.Uint16(handshake[pos:pos+2]); pos += 2
		if pos+2 > len(handshake) { return false, errors.New("short handshake") }
		capsHigh = binary.LittleEndian.Uint16(handshake[pos:pos+2]); pos += 2
		if pos+1 > len(handshake) { return false, errors.New("short handshake") }
		authDataLen = handshake[pos]; pos++
		if pos+10 > len(handshake) { return false, errors.New("short handshake") }
		pos += 10
	}
	_ = status
	capabilities := uint32(capsLow) | (uint32(capsHigh) << 16)
	_ = charset

	var salt2 []byte
	if authDataLen > 0 {
		remain := int(authDataLen)
		if remain < 13 { remain = 13 }
		if pos+remain-8 <= len(handshake) {
			salt2 = handshake[pos:pos+remain-8]
		}
	}
	challenge := make([]byte, 0, 20)
	challenge = append(challenge, salt1...)
	challenge = append(challenge, salt2...)
	if len(challenge) < 20 { // fallback size
		// pad or slice to 20
		for len(challenge) < 20 { challenge = append(challenge, 0) }
		challenge = challenge[:20]
	}

	// Build client response (Handshake Response 41)
	const (
		CLIENT_LONG_PASSWORD   = 0x00000001
		CLIENT_LONG_FLAG       = 0x00000004
		CLIENT_PROTOCOL_41     = 0x00000200
		CLIENT_SECURE_CONNECTION = 0x00008000
		CLIENT_MULTI_RESULTS    = 0x00020000
		CLIENT_PLUGIN_AUTH      = 0x00080000
	)
	clientCaps := uint32(0)
	clientCaps |= CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_MULTI_RESULTS | CLIENT_PLUGIN_AUTH
	clientCaps &= capabilities // intersect with server caps

	authResp := scrambleNativePassword(password, challenge)
	payload := make([]byte, 0, 4+4+1+23+len(username)+1+1+len(authResp)+len("mysql_native_password")+1)
	// capability flags
	buf4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf4, clientCaps)
	payload = append(payload, buf4...)
	// max packet size (use default)
	binary.LittleEndian.PutUint32(buf4, 0)
	payload = append(payload, buf4...)
	// character set
	payload = append(payload, charset)
	// 23 reserved bytes
	payload = append(payload, make([]byte, 23)...)
	// username NUL
	payload = append(payload, []byte(username)...)
	payload = append(payload, 0x00)
	// auth length + data
	payload = append(payload, byte(len(authResp)))
	payload = append(payload, authResp...)
	// plugin name NUL
	payload = append(payload, []byte("mysql_native_password")...)
	payload = append(payload, 0x00)

	if err := writePacket(conn, payload, 1); err != nil { return false, err }
	resp, _, err := readPacket(conn)
	if err != nil { return false, err }
	if len(resp) == 0 { return false, errors.New("empty auth response") }
	// OK_Packet header 0x00, ERR_Packet 0xFF, AuthMore 0x01, EOF (deprecated) 0xFE
	switch resp[0] {
	case 0x00:
		return true, nil
	case 0xFF:
		return false, nil
	case 0xFE, 0x01:
		// Auth switch or more data not handled in this minimal client
		return false, errors.New("auth switch required or more data; unsupported plugin")
	default:
		return false, errors.New("unknown auth response")
	}
}

func scrambleNativePassword(password string, challenge []byte) []byte {
	if password == "" { return []byte{} }
	sha := sha1.New()
	sha.Write([]byte(password))
	stage1 := sha.Sum(nil)
	sha.Reset()
	sha.Write(stage1)
	stage2 := sha.Sum(nil)
	sha.Reset()
	sha.Write(challenge)
	sha.Write(stage2)
	stage3 := sha.Sum(nil)
	out := make([]byte, len(stage3))
	for i := 0; i < len(stage3); i++ { out[i] = stage3[i] ^ stage1[i] }
	return out
}

func readPacket(conn net.Conn) ([]byte, byte, error) {
	head := make([]byte, 4)
	if _, err := readFull(conn, head); err != nil { return nil, 0, err }
	length := int(uint32(head[0]) | uint32(head[1])<<8 | uint32(head[2])<<16)
	seq := head[3]
	if length <= 0 || length > 16*1024*1024 { return nil, 0, errors.New("invalid packet length") }
	buf := make([]byte, length)
	if _, err := readFull(conn, buf); err != nil { return nil, 0, err }
	return buf, seq, nil
}

func writePacket(conn net.Conn, payload []byte, seq byte) error {
	head := []byte{ byte(len(payload) & 0xFF), byte((len(payload)>>8)&0xFF), byte((len(payload)>>16)&0xFF), seq }
	if _, err := conn.Write(head); err != nil { return err }
	_, err := conn.Write(payload)
	return err
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		if n > 0 { read += n }
		if err != nil { return read, err }
	}
	return read, nil
}

func readNullTerminated(b []byte) (string, int) {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 { return string(b[:i]), i+1 }
	}
	return string(b), len(b)
}

func evaluateFindings(r *MySQLResult) []string {
	findings := []string{}
	if !r.SSLSupported {
		findings = append(findings, "Server does not advertise SSL/TLS support (enable TLS)")
	}
	l := strings.ToLower(r.ServerVersion)
	if strings.Contains(l, "5.5") || strings.Contains(l, "5.6") || strings.Contains(l, "5.0") || strings.Contains(l, "4.") {
		findings = append(findings, "Outdated MySQL version detected; upgrade recommended")
	}
	if r.AuthPlugin == "" || strings.Contains(strings.ToLower(r.AuthPlugin), "native") {
		findings = append(findings, "Using mysql_native_password; ensure strong passwords and consider caching_sha2_password for newer servers")
	}
	return findings
}

func errStr(err error) string { if err == nil { return "" }; return err.Error() }

