package owasp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Finding struct {
	Category    string
	Severity    string
	Description string
	Evidence    string
}

type Scanner struct {
	target   string
	full     bool
	client   *http.Client
	findings []Finding
}

func New(target string, full bool) *Scanner {
	return &Scanner{
		target: strings.TrimRight(target, "/"),
		full:   full,
		client: &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *Scanner) get(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", s.target+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Lyussfyuring002/1.0 OWASP-Scan")
	return s.client.Do(req)
}

func (s *Scanner) add(cat, sev, desc, evidence string) {
	s.findings = append(s.findings, Finding{cat, sev, desc, evidence})
	var c func(...interface{}) string
	switch sev {
	case "CRITICAL":
		c = color.New(color.FgRed, color.Bold).SprintFunc()
	case "HIGH":
		c = color.New(color.FgRed).SprintFunc()
	case "MEDIUM":
		c = color.New(color.FgYellow).SprintFunc()
	default:
		c = color.New(color.FgCyan).SprintFunc()
	}
	fmt.Printf("  [%s] %-12s %s\n", c(sev), cat, desc)
	if evidence != "" {
		fmt.Printf("         evidence: %s\n", evidence)
	}
}

// A01 - Broken Access Control
func (s *Scanner) checkAccessControl() {
	color.Cyan("\n[A01] Broken Access Control\n")
	paths := []string{
		"/admin", "/admin/", "/wp-admin/", "/.env",
		"/config", "/backup", "/api/v1/users", "/api/admin",
	}
	for _, p := range paths {
		resp, err := s.get(p)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			s.add("A01", "HIGH", fmt.Sprintf("sensitive path accessible: %s", p), fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
	}
}

// A02 - Cryptographic Failures
func (s *Scanner) checkCrypto() {
	color.Cyan("\n[A02] Cryptographic Failures\n")
	resp, err := s.get("/")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		s.add("A02", "MEDIUM", "missing HSTS header", "Strict-Transport-Security not set")
	}

	if !strings.HasPrefix(s.target, "https://") {
		s.add("A02", "HIGH", "plain HTTP endpoint detected", s.target)
	}
}

// A03 - Injection (SQLi probe)
func (s *Scanner) checkInjection() {
	color.Cyan("\n[A03] Injection\n")
	probes := []string{
		"/?id=1'",
		"/?q=1 OR 1=1",
		"/?search=<script>alert(1)</script>",
		"/?page=../../../../etc/passwd",
	}
	for _, p := range probes {
		resp, err := s.get(p)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 500 {
			s.add("A03", "HIGH", "server error on injection probe", p)
		}
	}
}

// A05 - Security Misconfiguration
func (s *Scanner) checkMisconfiguration() {
	color.Cyan("\n[A05] Security Misconfiguration\n")
	resp, err := s.get("/")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	headers := map[string]string{
		"X-Frame-Options":        "MEDIUM",
		"X-Content-Type-Options": "LOW",
		"Content-Security-Policy": "MEDIUM",
		"X-XSS-Protection":       "LOW",
		"Referrer-Policy":        "LOW",
	}

	for header, sev := range headers {
		if resp.Header.Get(header) == "" {
			s.add("A05", sev, fmt.Sprintf("missing header: %s", header), "")
		}
	}

	server := resp.Header.Get("Server")
	if server != "" {
		s.add("A05", "LOW", "server version disclosure", server)
	}
}

// A06 - Vulnerable Components (basic check)
func (s *Scanner) checkComponents() {
	color.Cyan("\n[A06] Vulnerable and Outdated Components\n")
	paths := []string{"/package.json", "/composer.json", "/Gemfile", "/requirements.txt"}
	for _, p := range paths {
		resp, err := s.get(p)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			s.add("A06", "MEDIUM", "dependency manifest exposed", p)
		}
	}
}

func (s *Scanner) Scan() ([]Finding, error) {
	fmt.Println(strings.Repeat("=", 64))
	color.Cyan("[*] OWASP TOP 10 scan started: %s\n", s.target)
	fmt.Println(strings.Repeat("=", 64))

	s.checkAccessControl()
	s.checkCrypto()
	s.checkInjection()
	s.checkMisconfiguration()

	if s.full {
		s.checkComponents()
	}

	fmt.Println(strings.Repeat("=", 64))
	color.Green("[+] scan complete: %d findings\n", len(s.findings))
	return s.findings, nil
}

func Scan(target string, full bool) error {
	sc := New(target, full)
	_, err := sc.Scan()
	return err
}
