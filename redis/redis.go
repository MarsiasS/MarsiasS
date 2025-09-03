package redis

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
	"forftp/utils"
)

type RedisResult struct {
	Target string
	Version string
	Unauthenticated bool
	Error string
}

func (r RedisResult) String() string {
	if r.Error != "" { return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("Redis Hata:"), utils.Colorize(r.Error, utils.ColorRed)) }
	flags := []string{}
	if r.Unauthenticated { flags = append(flags, "noauth") }
	return fmt.Sprintf("%s %s version=%s %s", utils.BoldText(utils.Colorize("Redis", utils.ColorCyan)), utils.Colorize(r.Target, utils.ColorYellow), utils.Colorize(r.Version, utils.ColorGreen), strings.Join(flags, ","))
}

func ScanRedis(target string, timeout time.Duration) RedisResult {
	addr := fmt.Sprintf("%s:%d", target, 6379)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil { return RedisResult{Target: target, Error: err.Error()} }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	// Try INFO server
	if _, err := conn.Write([]byte("INFO server\r\n")); err != nil { return RedisResult{Target: target, Error: err.Error()} }
	line, _ := reader.ReadString('\n')
	if strings.HasPrefix(line, "-NOAUTH") {
		return RedisResult{Target: target, Version: "", Unauthenticated: false}
	}
	buf := line
	// Read rest until blank line or a reasonable size
	for i := 0; i < 20; i++ {
		l, err := reader.ReadString('\n')
		if err != nil { break }
		buf += l
		if strings.TrimSpace(l) == "" { break }
	}
	ver := parseRedisVersion(buf)
	unauth := ver != ""
	return RedisResult{Target: target, Version: ver, Unauthenticated: unauth}
}

func parseRedisVersion(info string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "redis_version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
		}
	}
	return ""
}

