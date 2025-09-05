package redis

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RedisResult struct {
	Target          string
	Port            int
	Open            bool
	PingOK          bool
	AuthRequired    bool
	Version         string
	Mode            string
	Role            string
	OS              string
	ConfigWritable  bool
	RDBDirWritable  bool
	UnauthCommands  []string
	Vulnerabilities []string
	ErrorMessage    string
}

func (r RedisResult) String() string {
	status := "[-]"; if r.Open { status = "[+]" }
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s Redis scan for %s:%d\n", status, r.Target, r.Port))
	if r.ErrorMessage != "" { b.WriteString(fmt.Sprintf("    Error: %s\n", r.ErrorMessage)); return b.String() }
	b.WriteString(fmt.Sprintf("    Ping: %v, Auth required: %v\n", r.PingOK, r.AuthRequired))
	if r.Version != "" { b.WriteString(fmt.Sprintf("    Version: %s, Mode: %s, Role: %s\n", r.Version, r.Mode, r.Role)) }
	if r.OS != "" { b.WriteString(fmt.Sprintf("    OS: %s\n", r.OS)) }
	if len(r.UnauthCommands) > 0 {
		b.WriteString("    Unauthenticated commands worked: ")
		b.WriteString(strings.Join(r.UnauthCommands, ", "))
		b.WriteString("\n")
	}
	if len(r.Vulnerabilities) > 0 {
		b.WriteString("    Findings:\n")
		for i, v := range r.Vulnerabilities { b.WriteString(fmt.Sprintf("      %d. %s\n", i+1, v)) }
	}
	return b.String()
}

// ScanRedis connects to Redis TCP/6379, runs PING and INFO where possible, and infers risks.
func ScanRedis(target string, timeout time.Duration) RedisResult {
	res := RedisResult{ Target: target, Port: 6379 }
	addr := fmt.Sprintf("%s:%d", target, res.Port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil { res.ErrorMessage = err.Error(); return res }
	defer conn.Close(); res.Open = true
	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	// Try PING
	if err := writeRESP(conn, []string{"PING"}); err == nil {
		line, _ := readLine(reader)
		if strings.HasPrefix(line, "+PONG") { res.PingOK = true }
	}

	// Try INFO (may fail if auth required)
	if err := writeRESP(conn, []string{"INFO"}); err == nil {
		line, _ := readLine(reader)
		if strings.HasPrefix(line, "-") {
			if strings.Contains(strings.ToLower(line), "auth") { res.AuthRequired = true }
		} else {
			info, _ := readBulk(reader, line)
			parseInfo(info, &res)
			res.UnauthCommands = append(res.UnauthCommands, "INFO")
		}
	}

	res.Vulnerabilities = evaluateFindings(&res)
	return res
}

type RedisAuthResult struct {
	Target       string
	Port         int
	Username     string
	Password     string
	Success      bool
	ErrorMessage string
}

func (r RedisAuthResult) String() string {
	status := "[-]"; if r.Success { status = "[+]" }
	if r.Username != "" {
		if r.ErrorMessage != "" {
			return fmt.Sprintf("%s Redis auth %s:%d %s:%q -> error: %s", status, r.Target, r.Port, r.Username, r.Password, r.ErrorMessage)
		}
		return fmt.Sprintf("%s Redis auth %s:%d %s:%q", status, r.Target, r.Port, r.Username, r.Password)
	}
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s Redis auth %s:%d %q -> error: %s", status, r.Target, r.Port, r.Password, r.ErrorMessage)
	}
	return fmt.Sprintf("%s Redis auth %s:%d %q", status, r.Target, r.Port, r.Password)
}

// BruteForceRedis tries AUTH for user:pass (Redis 6+ ACL) and pass-only.
func BruteForceRedis(target string, usernames, passwords []string, timeout time.Duration, concurrency int) []RedisAuthResult {
	if concurrency <= 0 { concurrency = 5 }
	type job struct{ u, p string; mode int } // mode 1: user+pass, 2: pass-only
	jobs := make(chan job)
	results := make([]RedisAuthResult, 0, (len(usernames)*len(passwords))+len(passwords))
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			ok, err := tryAuth(target, j.u, j.p, j.mode, timeout)
			mu.Lock()
			results = append(results, RedisAuthResult{ Target: target, Port: 6379, Username: j.u, Password: j.p, Success: ok, ErrorMessage: errStr(err) })
			mu.Unlock()
		}
	}
	for i := 0; i < concurrency; i++ { wg.Add(1); go worker() }
	// user:pass
	for _, u := range usernames { for _, p := range passwords { jobs <- job{u: u, p: p, mode: 1} } }
	// pass-only
	for _, p := range passwords { jobs <- job{u: "", p: p, mode: 2} }
	close(jobs); wg.Wait()
	return results
}

// tryAuth performs AUTH. mode 1: AUTH username password; mode 2: AUTH password
func tryAuth(target, username, password string, mode int, timeout time.Duration) (bool, error) {
	addr := fmt.Sprintf("%s:%d", target, 6379)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil { return false, err }
	defer conn.Close(); _ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	var cmd []string
	if mode == 1 { cmd = []string{"AUTH", username, password} } else { cmd = []string{"AUTH", password} }
	if err := writeRESP(conn, cmd); err != nil { return false, err }
	line, err := readLine(reader)
	if err != nil { return false, err }
	if strings.HasPrefix(line, "+OK") { return true, nil }
	if strings.HasPrefix(line, "-") { return false, nil }
	return false, errors.New("unexpected reply")
}

// RESP helpers
func writeRESP(conn net.Conn, parts []string) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*%d\r\n", len(parts)))
	for _, p := range parts {
		sb.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(p), p))
	}
	_, err := conn.Write([]byte(sb.String()))
	return err
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil { return "", err }
	return strings.TrimRight(line, "\r\n"), nil
}

func readBulk(r *bufio.Reader, firstLine string) (string, error) {
	if len(firstLine) == 0 || firstLine[0] != '$' { return "", errors.New("not bulk") }
	n, err := strconv.Atoi(firstLine[1:])
	if err != nil { return "", err }
	if n < 0 { return "", nil }
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil { return "", err }
	// consume trailing CRLF
	if _, err := r.ReadByte(); err != nil { return "", err }
	if _, err := r.ReadByte(); err != nil { return "", err }
	return string(buf), nil
}

func parseInfo(info string, res *RedisResult) {
	lines := strings.Split(info, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' { continue }
		kv := strings.SplitN(ln, ":", 2)
		if len(kv) != 2 { continue }
		k := kv[0]; v := kv[1]
		switch k {
		case "redis_version": res.Version = v
		case "redis_mode": res.Mode = v
		case "role": res.Role = v
		case "os": res.OS = v
		}
	}
}

func evaluateFindings(r *RedisResult) []string {
	findings := []string{}
	if !r.AuthRequired {
		findings = append(findings, "Unauthenticated access possible; set requirepass or ACLs")
	}
	if r.PingOK && !r.AuthRequired {
		findings = append(findings, "PING responds without AUTH; exposure risk")
	}
	if r.Role == "master" {
		findings = append(findings, "Node is master; consider restricting access and enabling TLS")
	}
	if r.Version != "" && strings.HasPrefix(r.Version, "2.") {
		findings = append(findings, "Very old Redis version; upgrade urgently")
	}
	return findings
}

func errStr(err error) string { if err == nil { return "" }; return err.Error() }

