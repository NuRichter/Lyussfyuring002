package shodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

const shodanBase = "https://api.shodan.io"

type ShodanResult struct {
	Matches []Match `json:"matches"`
	Total   int     `json:"total"`
}

type Match struct {
	IP       string   `json:"ip_str"`
	Port     int      `json:"port"`
	Org      string   `json:"org"`
	ISP      string   `json:"isp"`
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
	OS       string   `json:"os"`
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	Banner   string   `json:"data"`
	Location struct {
		Country string  `json:"country_name"`
		City    string  `json:"city"`
		Lat     float64 `json:"latitude"`
		Lon     float64 `json:"longitude"`
	} `json:"location"`
	Vulns []string `json:"vulns"`
}

type Client struct {
	apiKey string
	http   *http.Client
}

func New(apiKey string) *Client {
	if apiKey == "" {
		apiKey = os.Getenv("SHODAN_API_KEY")
	}
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) doGet(endpoint string) ([]byte, error) {
	u := fmt.Sprintf("%s%s", shodanBase, endpoint)
	resp, err := c.http.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (c *Client) SearchQuery(query string) (*ShodanResult, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("no Shodan API key: set --api-key or SHODAN_API_KEY env")
	}

	endpoint := fmt.Sprintf("/shodan/host/search?key=%s&query=%s",
		c.apiKey, url.QueryEscape(query))

	body, err := c.doGet(endpoint)
	if err != nil {
		return nil, err
	}

	var result ShodanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	return &result, nil
}

func (c *Client) HostInfo(ip string) (*Match, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("no Shodan API key")
	}

	endpoint := fmt.Sprintf("/shodan/host/%s?key=%s", ip, c.apiKey)
	body, err := c.doGet(endpoint)
	if err != nil {
		return nil, err
	}

	var match Match
	if err := json.Unmarshal(body, &match); err != nil {
		return nil, err
	}

	return &match, nil
}

func printMatch(i int, m Match) {
	fmt.Printf("\n  [%d] %s:%d\n", i+1, color.GreenString(m.IP), m.Port)
	if m.Org != "" {
		fmt.Printf("      org     : %s\n", m.Org)
	}
	if m.OS != "" {
		fmt.Printf("      os      : %s\n", m.OS)
	}
	if m.Product != "" {
		fmt.Printf("      product : %s %s\n", m.Product, m.Version)
	}
	if m.Location.Country != "" {
		fmt.Printf("      location: %s, %s\n", m.Location.City, m.Location.Country)
	}
	if len(m.Vulns) > 0 {
		color.Red("      vulns   : %s\n", strings.Join(m.Vulns, ", "))
	}
	if len(m.Hostnames) > 0 {
		fmt.Printf("      hosts   : %s\n", strings.Join(m.Hostnames, ", "))
	}
	if m.Banner != "" && len(m.Banner) > 120 {
		m.Banner = m.Banner[:120] + "..."
	}
	if m.Banner != "" {
		fmt.Printf("      banner  : %s\n", strings.ReplaceAll(m.Banner, "\n", " "))
	}
}

func Search(query, apiKey string) error {
	c := New(apiKey)

	color.Cyan("[*] shodan search: %q\n", query)
	fmt.Println(strings.Repeat("-", 64))

	result, err := c.SearchQuery(query)
	if err != nil {
		return err
	}

	color.Green("[+] total results: %d (showing first %d)\n", result.Total, len(result.Matches))

	for i, m := range result.Matches {
		printMatch(i, m)
	}

	return nil
}
