package pop3

import (
	"fmt"
	"time"
)

type POP3ScanResult struct {
	Target string
	Port   int
	Banner string
	TLS    bool
}

func (r POP3ScanResult) String() string {
	return fmt.Sprintf("POP3 %s:%d TLS:%v Banner:%s", r.Target, r.Port, r.TLS, r.Banner)
}

func ScanPOP3(target string, timeout time.Duration) POP3ScanResult {
	return POP3ScanResult{Target: target, Port: 110}
}