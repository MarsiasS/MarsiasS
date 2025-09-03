package mssql

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"forftp/utils"
)

type MSSQLResult struct {
	Target string
	Version string
	Error string
}

func (r MSSQLResult) String() string {
	if r.Error != "" { return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("MSSQL Hata:"), utils.Colorize(r.Error, utils.ColorRed)) }
	if r.Version == "" { r.Version = "unknown" }
	return fmt.Sprintf("%s %s version=%s", utils.BoldText(utils.Colorize("MSSQL", utils.ColorCyan)), r.Target, utils.Colorize(r.Version, utils.ColorGreen))
}

// ScanMSSQL performs a minimal TDS PreLogin and parses VERSION token
func ScanMSSQL(target string, timeout time.Duration) MSSQLResult {
	addr := fmt.Sprintf("%s:%d", target, 1433)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil { return MSSQLResult{Target: target, Error: err.Error()} }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Minimal PRELOGIN payload with token table; offsets from start of payload
	// Token IDs: VERSION=0x00, ENCRYPTION=0x01, INSTOPT=0x02, THREADID=0x03, TERMINATOR=0xFF
	// Layout adapted from common scanners; sufficient for server to reply
	payload := []byte{
		0x00, 0x00, 0x20, 0x00, 0x06,
		0x01, 0x00, 0x26, 0x00, 0x01,
		0x02, 0x00, 0x27, 0x00, 0x08,
		0x03, 0x00, 0x2F, 0x00, 0x01,
		0xFF,
		// Data @ 0x20
		0x00, 0x00, 0x0F, 0xA0, 0x00, 0x00, // VERSION (dummy client version 15.4000)
		0x00, // ENCRYPTION: ENCRYPT_OFF
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // INSTOPT
		0x00, // THREADID
	}

	// TDS packet header: Type=0x12 PRELOGIN, Status=0x01 EOM, Length=be16, SPID=0x0000, PacketID=0x00, Window=0x00
	head := make([]byte, 8)
	head[0] = 0x12
	head[1] = 0x01
	length := 8 + len(payload)
	binary.BigEndian.PutUint16(head[2:4], uint16(length))
	// head[4:6]=0, head[6]=0, head[7]=0

	packet := append(head, payload...)
	if _, err := conn.Write(packet); err != nil { return MSSQLResult{Target: target, Error: err.Error()} }

	// Read response header
	respHead := make([]byte, 8)
	if _, err := conn.Read(respHead); err != nil { return MSSQLResult{Target: target, Error: "no response"} }
	respLen := int(binary.BigEndian.Uint16(respHead[2:4]))
	if respLen < 8 { return MSSQLResult{Target: target, Error: "short response"} }
	respPayload := make([]byte, respLen-8)
	if _, err := ioReadFull(conn, respPayload); err != nil { return MSSQLResult{Target: target, Error: "short payload"} }

	ver := parsePreloginVersion(respPayload)
	return MSSQLResult{Target: target, Version: ver}
}

func parsePreloginVersion(payload []byte) string {
	// Parse token table: entries of (token byte, offset be16, length be16), terminated by 0xFF
	i := 0
	var verOff, verLen int
	for i < len(payload) {
		tok := payload[i]
		i++
		if tok == 0xFF { break }
		if i+5 > len(payload) { break }
		off := int(binary.BigEndian.Uint16(payload[i:i+2])); i += 2
		ln := int(binary.BigEndian.Uint16(payload[i:i+2])); i += 2
		if tok == 0x00 { verOff = off; verLen = ln }
	}
	if verLen >= 6 && verOff+verLen <= len(payload) {
		b := payload[verOff:verOff+verLen]
		major := int(b[0])
		minor := int(b[1])
		build := int(binary.BigEndian.Uint16(b[2:4]))
		return fmt.Sprintf("%d.%d.%d", major, minor, build)
	}
	return ""
}

func ioReadFull(r net.Conn, b []byte) (int, error) {
	read := 0
	for read < len(b) {
		n, err := r.Read(b[read:])
		if n > 0 { read += n }
		if err != nil { return read, err }
	}
	return read, nil
}

