package imap

type IMAPResult struct {
	Target            string
	Port              int
	Banner            string
	InfoLeak          bool
	STARTTLS          bool
	PlaintextAuth     bool
	PlaintextAuthResp string
}

func RunIMAP(target string, timeoutSeconds int) []IMAPResult {
	return []IMAPResult{{Target: target, Port: 143}}
}