package ftp

import (
	"time"
)

func GetVersion(target string, port int, timeout time.Duration) (string, error) {
	return "", nil
}

func SupportsExplicitTLS(target string, port int, timeout time.Duration) (bool, error) {
	return false, nil
}

func FTPLogin(target string, port int, username, password string, timeout time.Duration) (bool, error) {
	return false, nil
}

func SingleLogin(target, username, password string, timeout time.Duration) (bool, error) {
	return FTPLogin(target, 21, username, password, timeout)
}