package harvester

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/html"
)

type HarvestResult struct {
	Domain     string
	Emails     []string
	Subdomains []string
	IPs        []string
	Hosts      []string
}

var (
	emailRegex     = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	subdomainRegex = regexp.MustCompile(`(?i)([a-z0-9\-]+\.[a-z0-9\-]+\.[a-z]{2,})`)
)

type Harvester struct {
	domain  string
	passive bool
	client  *http.Client
	result  HarvestResult
	seen    map[string]bool
}

func New(domain string, passive bool) *Harvester {
	return &Harvester{
		domain:  domain,
		passive: passive,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		result: HarvestResult{Domain: domain},
		seen:   make(map[string]bool),
	}
}

func (h *Harvester) resolveDomain() {
	color.Cyan("[*] resolving DNS records for %s\n", h.domain)

	ips, err := net.LookupHost(h.domain)
	if err == nil {
		for _, ip := range ips {
			if !h.seen[ip] {
				h.seen[ip] = true
				h.result.IPs = append(h.result.IPs, ip)
				color.Green("[IP]  %s\n", ip)
			}
		}
	}

	mxRecords, err := net.LookupMX(h.domain)
	if err == nil {
		for _, mx := range mxRecords {
			host := strings.TrimRight(mx.Host, ".")
			if !h.seen[host] {
				h.seen[host] = true
				h.result.Hosts = append(h.result.Hosts, host)
				color.Yellow("[MX]  %s\n", host)
			}
		}
	}

	nsRecords, err := net.LookupNS(h.domain)
	if err == nil {
		for _, ns := range nsRecords {
			host := strings.TrimRight(ns.Host, ".")
			color.Yellow("[NS]  %s\n", host)
		}
	}
}

func (h *Harvester) scrapeURL(rawURL string) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Lyussfyuring002/1.0)")

	resp, err := h.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	tokenizer := html.NewTokenizer(resp.Body)
	var textBuf strings.Builder

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.TextToken {
			textBuf.Write(tokenizer.Text())
		}
	}

	body := textBuf.String()

	for _, email := range emailRegex.FindAllString(body, -1) {
		if strings.HasSuffix(email, h.domain) && !h.seen[email] {
			h.seen[email] = true
			h.result.Emails = append(h.result.Emails, email)
			color.Green("[EMAIL] %s\n", email)
		}
	}

	for _, sub := range subdomainRegex.FindAllString(body, -1) {
		sub = strings.ToLower(sub)
		if strings.HasSuffix(sub, h.domain) && !h.seen[sub] {
			h.seen[sub] = true
			h.result.Subdomains = append(h.result.Subdomains, sub)
			color.Magenta("[SUB]  %s\n", sub)
		}
	}
}

func (h *Harvester) certTransparency() {
	color.Cyan("[*] checking certificate transparency logs...\n")
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", h.domain)
	h.scrapeURL(url)
}

func (h *Harvester) Run() (*HarvestResult, error) {
	fmt.Println(strings.Repeat("=", 60))
	color.Cyan("[*] harvesting: %s  [passive=%v]\n", h.domain, h.passive)
	fmt.Println(strings.Repeat("=", 60))

	h.resolveDomain()
	h.certTransparency()

	if !h.passive {
		h.scrapeURL(fmt.Sprintf("http://%s", h.domain))
		h.scrapeURL(fmt.Sprintf("https://%s", h.domain))
	}

	fmt.Println(strings.Repeat("=", 60))
	color.Green("[+] harvest done: %d emails, %d subdomains, %d IPs\n",
		len(h.result.Emails), len(h.result.Subdomains), len(h.result.IPs))

	return &h.result, nil
}

func Run(domain string, passive bool) error {
	h := New(domain, passive)
	_, err := h.Run()
	return err
}
