package fuzzer

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Result struct {
	URL        string
	StatusCode int
	Size       int64
	Duration   time.Duration
}

type Fuzzer struct {
	target   string
	wordlist string
	threads  int
	client   *http.Client
	results  []Result
	mu       sync.Mutex
}

func New(target, wordlist string, threads int) *Fuzzer {
	return &Fuzzer{
		target:   strings.TrimRight(target, "/"),
		wordlist: wordlist,
		threads:  threads,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (f *Fuzzer) probe(word string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	url := fmt.Sprintf("%s/%s", f.target, strings.TrimSpace(word))
	start := time.Now()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Lyussfyuring002/1.0 (Arch;Kali)")

	resp, err := f.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	if resp.StatusCode != 404 {
		result := Result{
			URL:        url,
			StatusCode: resp.StatusCode,
			Size:       resp.ContentLength,
			Duration:   elapsed,
		}

		f.mu.Lock()
		f.results = append(f.results, result)
		f.mu.Unlock()

		printResult(result)
	}
}

func printResult(r Result) {
	var statusColor func(a ...interface{}) string
	switch {
	case r.StatusCode >= 200 && r.StatusCode < 300:
		statusColor = color.New(color.FgGreen, color.Bold).SprintFunc()
	case r.StatusCode >= 300 && r.StatusCode < 400:
		statusColor = color.New(color.FgCyan).SprintFunc()
	case r.StatusCode >= 400 && r.StatusCode < 500:
		statusColor = color.New(color.FgYellow).SprintFunc()
	default:
		statusColor = color.New(color.FgRed).SprintFunc()
	}

	fmt.Printf("[%s] %-60s [size: %d] [%s]\n",
		statusColor(fmt.Sprintf("%d", r.StatusCode)),
		r.URL,
		r.Size,
		r.Duration.Round(time.Millisecond),
	)
}

func (f *Fuzzer) Run() ([]Result, error) {
	file, err := os.Open(f.wordlist)
	if err != nil {
		return nil, fmt.Errorf("wordlist open failed: %w", err)
	}
	defer file.Close()

	color.Cyan("[*] target  : %s\n", f.target)
	color.Cyan("[*] wordlist: %s\n", f.wordlist)
	color.Cyan("[*] threads : %d\n", f.threads)
	fmt.Println(strings.Repeat("-", 72))

	sem := make(chan struct{}, f.threads)
	var wg sync.WaitGroup
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		wg.Add(1)
		go f.probe(line, &wg, sem)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("wordlist scan error: %w", err)
	}

	wg.Wait()
	fmt.Println(strings.Repeat("-", 72))
	color.Green("[+] fuzzing complete. %d results found.\n", len(f.results))
	return f.results, nil
}

func Run(target, wordlist string, threads int) error {
	f := New(target, wordlist, threads)
	_, err := f.Run()
	return err
}
