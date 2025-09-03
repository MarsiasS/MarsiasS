package ldapscan

import (
	"fmt"
	"net"
	"time"
	"strings"
	"github.com/go-ldap/ldap/v3"
	"forftp/utils"
)

type LDAPResult struct {
	Target          string
	AnonymousBind   bool
	SupportedSASL   []string
	NamingContexts  []string
	Error           string
}

func (r LDAPResult) String() string {
	if r.Error != "" { return fmt.Sprintf("%s %s %s", utils.Colorize("✗", utils.ColorRed), utils.BoldText("LDAP Hata:"), utils.Colorize(r.Error, utils.ColorRed)) }
	var b strings.Builder
	b.WriteString(utils.BoldText(utils.Colorize("LDAP", utils.ColorCyan)))
	b.WriteString(" ")
	b.WriteString(utils.Colorize(r.Target, utils.ColorYellow))
	b.WriteString(" anon=")
	b.WriteString(utils.Colorize(fmt.Sprintf("%v", r.AnonymousBind), utils.ColorGreen))
	if len(r.NamingContexts) > 0 {
		b.WriteString(" contexts=[")
		b.WriteString(strings.Join(r.NamingContexts, ","))
		b.WriteString("]")
	}
	return b.String()
}

func ScanLDAP(target string, timeout time.Duration) LDAPResult {
	url := fmt.Sprintf("ldap://%s:389", target)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(dialer))
	if err != nil { return LDAPResult{Target: target, Error: err.Error()} }
	defer conn.Close()

	conn.SetTimeout(timeout)

	anonOK := false
	if err := conn.UnauthenticatedBind(""); err == nil { anonOK = true }

	// Query RootDSE
	searchReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, int(timeout/time.Second), false,
		"(objectClass=*)",
		[]string{"namingContexts", "supportedSASLMechanisms"},
		nil,
	)
	res, err := conn.Search(searchReq)
	if err != nil { return LDAPResult{Target: target, AnonymousBind: anonOK} }

	var contexts []string
	var sasl []string
	if len(res.Entries) > 0 {
		entry := res.Entries[0]
		contexts = entry.GetAttributeValues("namingContexts")
		sasl = entry.GetAttributeValues("supportedSASLMechanisms")
	}
	return LDAPResult{Target: target, AnonymousBind: anonOK, NamingContexts: contexts, SupportedSASL: sasl}
}

