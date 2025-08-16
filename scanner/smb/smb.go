package smb

import "time"

type SMBResult struct {
	ErrorMessage   string
	Target         string
	Port           int
	Version        string
	SigningEnabled bool
	SigningRequired bool
	Dialects       []string
	SecurityMode   uint16
}

func ScanSMB(target string, port int, timeout time.Duration) SMBResult {
	return SMBResult{
		Target: target,
		Port: port,
		Version: "",
		SigningEnabled: false,
		SigningRequired: false,
		Dialects: []string{},
		SecurityMode: 0,
	}
}