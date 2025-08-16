package main

import (
	"FORFTP/scanner/ftp"
	"FORFTP/scanner/imap"
	"FORFTP/scanner/nfs"
	pop3scan "FORFTP/scanner/pop3"
	"FORFTP/scanner/smb"
	"FORFTP/scanner/snmp"
	"FORFTP/utils"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type FTPJob struct {
	Target   string
	Username string
	Password string
}

type FTPResult struct {
	Job     FTPJob
	Success bool
	Err     error
}

type ScanConfig struct {
	Protocol    string
	Targets     []string
	Timeout     time.Duration
	Concurrency int
	Credentials CredentialConfig
}

type CredentialConfig struct {
	Username  string
	Password  string
	UserList  string
	PassList  string
	Anonymous bool
}

func main() {
	protocol := flag.String("protocol", "ftp", "Kullanılacak protokol (ftp, smb, nfs, snmp, pop3, imap)")
	ip := flag.String("t", "", "Hedef IP adresi")
	ipList := flag.String("T", "", "IP adreslerinin bulunduğu dosya")
	timeout := flag.Int("timeout", 5, "Zaman aşımı süresi (saniye)")

	user := flag.String("u", "", "Tek kullanıcı adı")
	pass := flag.String("p", "", "Tek şifre")
	userList := flag.String("U", "", "Kullanıcı adı listesi dosyası")
	passList := flag.String("P", "", "Şifre listesi dosyası")
	anon := flag.Bool("A", false, "Anonim FTP giriş denemesi")
	help := flag.Bool("h", false, "Yardım")
	concurrency := flag.Int("c", 10, "Eşzamanlı çalışma sayısı (goroutine sayısı)")

	flag.Parse()

	if *help {
		printHelp()
		return
	}

	if *ip == "" && *ipList == "" {
		fmt.Println("[-] Hedef IP veya IP listesi dosyası belirtilmeli (-t veya -T)")
		return
	}

	var targets []string
	if *ip != "" {
		targets = append(targets, *ip)
	} else if *ipList != "" {
		lines, err := utils.ReadLines(*ipList)
		if err != nil {
			fmt.Println("[-] IP listesi okunamadı:", err)
			os.Exit(1)
		}
		targets = lines
	}

	config := ScanConfig{
		Protocol:    *protocol,
		Targets:     targets,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		Credentials: CredentialConfig{
			Username:  *user,
			Password:  *pass,
			UserList:  *userList,
			PassList:  *passList,
			Anonymous: *anon,
		},
	}

	switch config.Protocol {
	case "ftp":
		if err := runFTP(&config); err != nil {
			fmt.Println("[-] FTP tarama sırasında hata oluştu:", err)
			for _, target := range config.Targets {
				banner, err := ftp.GetVersion(target, 21, config.Timeout)
				if err != nil {
					fmt.Printf("[-] Banner alınamadı: %s -- %v\n", target, err)
				} else {
					fmt.Printf("[+] FTP Banner (%s): %s\n", target, banner)
				}
				ok, err := ftp.SupportsExplicitTLS(target, 21, config.Timeout)
				if err != nil {
					fmt.Printf("[-] TLS destek kontrolü başarısız: %s -- %v\n", target, err)
				} else if ok {
					fmt.Printf("[+] FTP sunucusu TLS destekliyor: %s\n", target)
				} else {
					fmt.Printf("[-] FTP sunucusu TLS desteklemiyor: %s\n", target)
				}
			}
			os.Exit(1)
		}
	case "smb":
		// Example direct scan usage; in practice, wire to flags similarly
		target := config.Targets[0]
		port := 445
		result := smb.ScanSMB(target, port, config.Timeout)
		if result.ErrorMessage != "" {
			fmt.Printf("Hata oluştu: %s\n", result.ErrorMessage)
			return
		}
		fmt.Printf("SMB Taraması Sonucu:\n")
		fmt.Printf("Sunucu: %s\n", result.Target)
		fmt.Printf("Port: %d\n", result.Port)
		fmt.Printf("Protokol Versiyonu: %s\n", result.Version)
		fmt.Printf("İmzalama Aktif mi?: %v\n", result.SigningEnabled)
		fmt.Printf("İmzalama Zorunlu mu?: %v\n", result.SigningRequired)
		fmt.Printf("Desteklenen Dialectler: %v\n", result.Dialects)
		fmt.Printf("Security Mode (ham): 0x%04x\n", result.SecurityMode)
	case "nfs":
		if err := runNFS(&config); err != nil {
			fmt.Println("[-] NFS tarama sırasında hata oluştu:", err)
			os.Exit(1)
		}
	case "snmp":
		if err := runSNMP(&config); err != nil {
			fmt.Println("[-] SNMP tarama sırasında hata oluştu:", err)
			os.Exit(1)
		}
	case "pop3":
		res := pop3scan.ScanPOP3(config.Targets[0], config.Timeout)
		fmt.Println(res.String())
	case "imap":
		results := imap.RunIMAP(config.Targets[0], int(config.Timeout/time.Second))
		for _, r := range results {
			fmt.Printf("Target: %s:%d\n", r.Target, r.Port)
			fmt.Printf("Banner: %s\n", r.Banner)
			fmt.Printf("InfoLeak: %v\n", r.InfoLeak)
			fmt.Printf("STARTTLS: %v\n", r.STARTTLS)
			fmt.Printf("Plaintext auth allowed: %v (%s)\n", r.PlaintextAuth, r.PlaintextAuthResp)
			fmt.Println("----------------------")
		}
	default:
		fmt.Println("[-] Desteklenmeyen protokol! Sadece ftp, smb, nfs, snmp, pop3 ve imap desteklenmektedir.")
		os.Exit(1)
	}
}

func runFTP(config *ScanConfig) error {
	// 1. anonymous login (if requested)
	if config.Credentials.Anonymous {
		if err := runFTPAnonymous(config); err != nil {
			fmt.Println("[-] Anonim login denemesi sırasında hata:", err)
		}
	}

	// 2. single login
	if config.Credentials.Username != "" && config.Credentials.Password != "" {
		if err := runFTPSingleLogin(config, config.Credentials.Username, config.Credentials.Password); err != nil {
			fmt.Printf("[-] Tek giriş denemesi hatası: %v\n", err)
		}
	} else {
		fmt.Println("[*] Tek kullanıcı/parola giriş denemesi atlandı.")
	}

	// 3. Bruteforce eligibility
	hasUser := config.Credentials.Username != "" || config.Credentials.UserList != ""
	hasPass := config.Credentials.Password != "" || config.Credentials.PassList != ""
	if !hasUser || !hasPass {
		fmt.Println("[*] Kullanıcı adı veya şifre bilgisi sağlanmadığı için brute force atlanıyor.")
		return nil
	}

	// 4. Read lists via shared utils
	users, err := getUsers(config.Credentials)
	if err != nil {
		return fmt.Errorf("kullanıcı adı alınamadı: %v", err)
	}
	passwords, err := getPasswords(config.Credentials)
	if err != nil {
		return fmt.Errorf("şifre alınamadı: %v", err)
	}

	// 5. Bruteforce
	return runFTPBruteforceConcurrent(config, users, passwords)
}

func runFTPAnonymous(config *ScanConfig) error {
	for _, target := range config.Targets {
		ok, err := ftp.FTPLogin(target, 21, "anonymous", "anonymous", config.Timeout)
		if ok {
			fmt.Printf("%s[+] FTP ANONYMOUS LOGIN başarılı: %s%s\n", utils.Green, target, utils.Reset)
		} else {
			if err != nil {
				fmt.Printf("%s[-] FTP ANONYMOUS LOGIN başarısız: %s -- Hata: %s%s\n", utils.Red, target, err.Error(), utils.Reset)
			} else {
				fmt.Printf("%s[-] FTP ANONYMOUS LOGIN başarısız: %s%s\n", utils.Red, target, utils.Reset)
			}
		}
	}
	return nil
}

func runFTPSingleLogin(config *ScanConfig, username, password string) error {
	for _, target := range config.Targets {
		ok, err := ftp.SingleLogin(target, username, password, config.Timeout)
		if ok {
			fmt.Printf("%s[+] TEK GİRİŞ başarılı: %s %s:%s%s\n", utils.Green, target, username, password, utils.Reset)
		} else {
			if err != nil {
				fmt.Printf("%s[-] TEK GİRİŞ başarısız: %s %s:%s -- Hata: %s%s\n", utils.Red, target, username, password, err.Error(), utils.Reset)
			} else {
				fmt.Printf("%s[-] TEK GİRİŞ başarısız: %s %s:%s%s\n", utils.Red, target, username, password, utils.Reset)
			}
		}
	}
	return nil
}

func runFTPBruteforceConcurrent(config *ScanConfig, users, passwords []string) error {
	jobs := make(chan FTPJob)
	results := make(chan FTPResult)

	workerCount := config.Concurrency

	for i := 0; i < workerCount; i++ {
		go func() {
			for job := range jobs {
				ok, err := ftp.FTPLogin(job.Target, 21, job.Username, job.Password, config.Timeout)
				results <- FTPResult{Job: job, Success: ok, Err: err}
			}
		}()
	}

	go func() {
		for _, target := range config.Targets {
			for _, user := range users {
				for _, pass := range passwords {
					jobs <- FTPJob{Target: target, Username: user, Password: pass}
				}
			}
		}
		close(jobs)
	}()

	totalJobs := len(config.Targets) * len(users) * len(passwords)
	for i := 0; i < totalJobs; i++ {
		res := <-results
		if res.Success {
			fmt.Printf("%s[+] FTP GİRİŞ başarılı: %s %s:%s%s\n", utils.Green, res.Job.Target, res.Job.Username, res.Job.Password, utils.Reset)
		} else {
			if res.Err != nil {
				fmt.Printf("%s[-] FTP GİRİŞ başarısız: %s %s:%s -- Hata: %s%s\n", utils.Red, res.Job.Target, res.Job.Username, res.Job.Password, res.Err.Error(), utils.Reset)
			} else {
				fmt.Printf("%s[-] FTP GİRİŞ başarısız: %s %s:%s%s\n", utils.Red, res.Job.Target, res.Job.Username, res.Job.Password, utils.Reset)
			}
		}
	}
	return nil
}

func getUsers(creds CredentialConfig) ([]string, error) {
	if creds.Username != "" {
		return []string{creds.Username}, nil
	}
	if creds.UserList != "" {
		return utils.ReadLines(creds.UserList)
	}
	return []string{}, nil
}

func getPasswords(creds CredentialConfig) ([]string, error) {
	if creds.Password != "" {
		return []string{creds.Password}, nil
	}
	if creds.PassList != "" {
		return utils.ReadLines(creds.PassList)
	}
	return []string{}, nil
}

func printHelp() {
	fmt.Println("Enhanced SMB/FTP Vulnerability Scanner")
	fmt.Println("=====================================")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  forftp.exe -protocol <protocol> [options]")
	fmt.Println()
	fmt.Println("Protocols:")
	fmt.Println("  ftp     - FTP vulnerability scanning")
	fmt.Println("  smb     - SMB vulnerability scanning")
	fmt.Println("  nfs     - NFS vulnerability scanning")
	fmt.Println("  snmp    - SNMP vulnerability scanning")
	fmt.Println()
	fmt.Println("Target Options:")
	fmt.Println("  -t <IP>           - Single target IP address")
	fmt.Println("  -T <file>         - File containing list of IP addresses")
	fmt.Println()
	fmt.Println("Credential Options:")
	fmt.Println("  -u <username>     - Single username")
	fmt.Println("  -p <password>     - Single password")
	fmt.Println("  -U <file>         - File containing usernames")
	fmt.Println("  -P <file>         - File containing passwords")
	fmt.Println("  -A                - Test anonymous login")
	fmt.Println()
	fmt.Println("Scan Options:")
	fmt.Println("  -c <number>       - Number of concurrent workers (default: 10)")
	fmt.Println("  -timeout <sec>    - Connection timeout in seconds (default: 5)")
	fmt.Println("  -h                - Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # SMB scan with anonymous login")
	fmt.Println("  forftp.exe -protocol smb -t 192.168.1.1 -A")
	fmt.Println()
	fmt.Println("  # SMB scan with credentials")
	fmt.Println("  forftp.exe -protocol smb -t 192.168.1.1 -u admin -p password")
	fmt.Println()
	fmt.Println("  # SMB brute force attack")
	fmt.Println("  forftp.exe -protocol smb -t 192.168.1.1 -U users.txt -P passwords.txt")
	fmt.Println()
	fmt.Println("  # FTP scan with anonymous login")
	fmt.Println("  forftp.exe -protocol ftp -t 192.168.1.1 -A")
	fmt.Println()
	fmt.Println("  # NFS scan")
	fmt.Println("  forftp.exe -protocol nfs -t 192.168.1.1")
	fmt.Println()
	fmt.Println("  # SNMP scan")
	fmt.Println("  forftp.exe -protocol snmp -t 192.168.1.1")
	fmt.Println()
	fmt.Println("  # Multiple targets with custom settings")
	fmt.Println("  forftp.exe -protocol smb -T iplist.txt -U users.txt -P passwords.txt -c 20 -timeout 10")
	fmt.Println()
	fmt.Println("Features:")
	fmt.Println("  • SMB Version Enumeration (SMB1, SMB2, SMB3)")
	fmt.Println("  • SMB Signing Status Check")
	fmt.Println("  • Share Enumeration and Access Testing")
	fmt.Println("  • NetBIOS Information Gathering")
	fmt.Println("  • Brute Force Attack with Progress Tracking")
	fmt.Println("  • Read/Write Permission Testing")
	fmt.Println("  • Anonymous Login Testing")
	fmt.Println("  • FTP Banner Grabbing and TLS Support Check")
	fmt.Println("  • NFS Version Enumeration (NFSv2, NFSv3, NFSv4)")
	fmt.Println("  • NFS Export Discovery and Permission Testing")
	fmt.Println("  • NFS Authentication Analysis")
	fmt.Println("  • NFS Vulnerability Detection")
	fmt.Println("  • SNMP Version Enumeration (SNMPv1, SNMPv2c, SNMPv3)")
	fmt.Println("  • SNMP Community String Discovery")
	fmt.Println("  • SNMP Walk and System Information Gathering")
	fmt.Println("  • SNMP Vulnerability Detection")
	fmt.Println()
	fmt.Println("Note: Use responsibly and only on systems you own or have permission to test.")
}

func runNFS(config *ScanConfig) error {
	fmt.Println("[*] NFS taraması başlatıldı.")

	for _, target := range config.Targets {
		fmt.Printf("\n[*] Hedef: %s\n", target)
		fmt.Println("=" + strings.Repeat("=", len(target)+20))

		fmt.Println("\n[1] NFS Versiyon Bilgisi ve Export Listesi")
		fmt.Println("-" + strings.Repeat("-", 45))

		result := nfs.ScanNFS(target, config.Timeout)
		if result.ErrorMessage != "" {
			fmt.Printf("[-] NFS taraması başarısız: %s\n", result.ErrorMessage)
			continue
		}

		if len(result.VersionSummary) > 0 {
			fmt.Printf("[+] NFS Versiyon(lar): %s\n", result.VersionSummary)
		} else {
			fmt.Println("[-] NFS versiyonu tespit edilemedi")
		}

		fmt.Printf("[+] rpcbind aktif: %v\n", result.PortmapperAlive)

		if result.MountdPort > 0 {
			fmt.Printf("[+] mountd port: %d\n", result.MountdPort)
		}

		if len(result.Exports) > 0 {
			fmt.Printf("[+] %d adet export bulundu:\n", len(result.Exports))
			for i, exp := range result.Exports {
				fmt.Printf("    %d. %s (Gruplar: %s)\n", i+1, exp.Path, strings.Join(exp.Groups, ","))
			}
			fmt.Printf("[+] Anonim erişim: %v\n", result.Anonymous)
		} else {
			fmt.Println("[-] Herhangi bir export bulunamadı")
		}

		fmt.Println("\n" + strings.Repeat("=", 50))
	}

	return nil
}

func runSNMP(config *ScanConfig) error {
	fmt.Println("[*] SNMP taraması başlatıldı.")

	for _, target := range config.Targets {
		fmt.Printf("\n[*] Scanning target: %s\n", target)
		fmt.Println("=" + strings.Repeat("=", len(target)+20))

		fmt.Println("\n[1] SNMP Version Enumeration and Community Discovery")
		fmt.Println("-" + strings.Repeat("-", 50))
		result := snmp.ScanSNMPComprehensive(target, 1161, config.Timeout)
		if result.ErrorMessage != "" {
			fmt.Printf("[-] SNMP scan failed: %s\n", result.ErrorMessage)
			continue
		}

		fmt.Printf("[+] SNMP Version: %s\n", result.Version)

		fmt.Println("\n[2] Community String Enumeration")
		fmt.Println("-" + strings.Repeat("-", 30))
		if len(result.Communities) > 0 {
			fmt.Printf("[+] Found %d community strings:\n", len(result.Communities))
			for i, community := range result.Communities {
				fmt.Printf("    %d. %s - Access: %s (RO:%v, RW:%v)\n",
					i+1, community.Name, community.Access, community.ReadOnly, community.ReadWrite)
			}
		} else {
			fmt.Println("[-] No community strings found")
		}

		fmt.Println("\n[3] System Information")
		fmt.Println("-" + strings.Repeat("-", 20))
		if result.SystemInfo.SysDescr != "" {
			fmt.Printf("[+] System Description: %s\n", result.SystemInfo.SysDescr)
		}
		if result.SystemInfo.SysName != "" {
			fmt.Printf("[+] System Name: %s\n", result.SystemInfo.SysName)
		}
		if result.SystemInfo.SysContact != "" {
			fmt.Printf("[+] System Contact: %s\n", result.SystemInfo.SysContact)
		}
		if result.SystemInfo.SysLocation != "" {
			fmt.Printf("[+] System Location: %s\n", result.SystemInfo.SysLocation)
		}
		if result.SystemInfo.SysObjectID != "" {
			fmt.Printf("[+] System Object ID: %s\n", result.SystemInfo.SysObjectID)
		}
		if result.SystemInfo.SysUpTime != "" {
			fmt.Printf("[+] System Up Time: %s\n", result.SystemInfo.SysUpTime)
		}

		fmt.Println("\n[4] SNMP Walk Results")
		fmt.Println("-" + strings.Repeat("-", 20))
		if len(result.OIDs) > 0 {
			fmt.Printf("[+] Found %d OIDs:\n", len(result.OIDs))
			for i, oid := range result.OIDs {
				if i < 10 {
					fmt.Printf("    %d. %s = %s (%s)\n",
						i+1, oid.OID, oid.Value, oid.Description)
				}
			}
			if len(result.OIDs) > 10 {
				fmt.Printf("    ... and %d more OIDs\n", len(result.OIDs)-10)
			}
		} else {
			fmt.Println("[-] No OIDs found during walk")
		}

		fmt.Println("\n[5] Vulnerability Analysis")
		fmt.Println("-" + strings.Repeat("-", 25))
		if len(result.Vulnerabilities) > 0 {
			fmt.Printf("[+] Found %d vulnerabilities:\n", len(result.Vulnerabilities))
			for i, vuln := range result.Vulnerabilities {
				fmt.Printf("    %d. [%s] %s: %s\n",
					i+1, vuln.Severity, vuln.Type, vuln.Description)
				if vuln.Details != "" {
					fmt.Printf("        Details: %s\n", vuln.Details)
				}
			}
		} else {
			fmt.Println("[+] No vulnerabilities detected")
		}

		if len(result.Communities) == 0 {
			fmt.Println("\n[6] Brute Force Community Strings")
			fmt.Println("-" + strings.Repeat("-", 35))
			fmt.Printf("[*] No communities found, attempting brute force...\n")

			communities := []string{
				"public", "private", "community", "admin", "cisco", "hp", "3com",
				"read", "write", "manager", "monitor", "guest", "test", "demo",
				"default", "system", "network", "security", "snmp", "trap",
			}

			bruteResults := snmp.BruteForceSNMP(target, communities, config.Timeout)
			if len(bruteResults) > 0 {
				fmt.Printf("[+] Brute force found %d community strings\n", len(bruteResults))
				for _, comm := range bruteResults {
					fmt.Printf("    - %s (%s)\n", comm.Name, comm.Access)
				}
			} else {
				fmt.Println("[-] Brute force failed to find any community strings")
			}
		}

		fmt.Println("\n[7] Security Recommendations")
		fmt.Println("-" + strings.Repeat("-", 30))
		provideSNMPSecurityRecommendations(result)

		fmt.Println("\n" + strings.Repeat("=", 50))
	}
	return nil
}

func provideSNMPSecurityRecommendations(result *snmp.SNMPResult) {
	recommendations := []string{}

	if strings.Contains(result.Version, "SNMPv1") {
		recommendations = append(recommendations, "• Upgrade to SNMPv3 - SNMPv1 is insecure")
	}

	for _, community := range result.Communities {
		if isDefaultSNMPCommunity(community.Name) {
			recommendations = append(recommendations, fmt.Sprintf("• Change default community string '%s'", community.Name))
		}
		if community.ReadWrite {
			recommendations = append(recommendations, fmt.Sprintf("• Restrict write access for community '%s'", community.Name))
		}
	}

	if result.SystemInfo.SysContact != "" {
		recommendations = append(recommendations, "• Review system contact information exposure")
	}
	if result.SystemInfo.SysLocation != "" {
		recommendations = append(recommendations, "• Review system location information exposure")
	}

	if len(recommendations) == 0 {
		fmt.Println("[+] No immediate security issues detected")
	} else {
		fmt.Println("Security recommendations:")
		for _, rec := range recommendations {
			fmt.Printf("  %s\n", rec)
		}
	}
}

func isDefaultSNMPCommunity(community string) bool {
	defaults := []string{"public", "private", "community", "admin", "cisco", "hp", "3com"}
	for _, def := range defaults {
		if strings.ToLower(community) == def {
			return true
		}
	}
	return false
}