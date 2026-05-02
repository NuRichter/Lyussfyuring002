package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/NuRichter/Lyussfyuring002/pkg/fuzzer"
	"github.com/NuRichter/Lyussfyuring002/pkg/harvester"
	"github.com/NuRichter/Lyussfyuring002/pkg/owasp"
	"github.com/NuRichter/Lyussfyuring002/pkg/shodan"
	"github.com/NuRichter/Lyussfyuring002/pkg/xss"
)

var (
	banner = `
  ██╗  ██╗   ██╗██╗   ██╗███████╗███████╗
  ██║  ╚██╗ ██╔╝██║   ██║██╔════╝██╔════╝
  ██║   ╚████╔╝ ██║   ██║███████╗███████╗
  ██║    ╚██╔╝  ██║   ██║╚════██║╚════██║
  ███████╗██║   ╚██████╔╝███████║███████║
  ╚══════╝╚═╝    ╚═════╝ ╚══════╝╚══════╝
  Lyussfyuring002 -- Web Exploitation & OSINT
  [ OWASP | FFUF | NIKTO | SHODAN | MALTEGO ]
  only runs on Arch Linux and Kali Linux.
`
)

var rootCmd = &cobra.Command{
	Use:   "lyuss",
	Short: "Web Exploitation + OSINT toolkit",
	Long:  "Lyussfyuring002: modular web exploitation and OSINT recon suite.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		color.Cyan(banner)
	},
}

var fuzzCmd = &cobra.Command{
	Use:   "fuzz [url]",
	Short: "Directory and parameter fuzzer (FFUF-style)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		wordlist, _ := cmd.Flags().GetString("wordlist")
		threads, _ := cmd.Flags().GetInt("threads")
		return fuzzer.Run(args[0], wordlist, threads)
	},
}

var harvestCmd = &cobra.Command{
	Use:   "harvest [domain]",
	Short: "OSINT email/subdomain/IP harvester (TheHarvester-style)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		passive, _ := cmd.Flags().GetBool("passive")
		return harvester.Run(args[0], passive)
	},
}

var owaspCmd = &cobra.Command{
	Use:   "owasp [url]",
	Short: "OWASP TOP 10 vulnerability scan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		full, _ := cmd.Flags().GetBool("full")
		return owasp.Scan(args[0], full)
	},
}

var shodanCmd = &cobra.Command{
	Use:   "shodan [query]",
	Short: "Shodan API search and banner grabbing",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		apiKey, _ := cmd.Flags().GetString("api-key")
		return shodan.Search(args[0], apiKey)
	},
}

var xssCmd = &cobra.Command{
	Use:   "xss [url]",
	Short: "XSS injection probe and payload fuzzer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		polyglot, _ := cmd.Flags().GetBool("polyglot")
		return xss.Probe(args[0], polyglot)
	},
}

func init() {
	fuzzCmd.Flags().StringP("wordlist", "w", "/usr/share/wordlists/dirb/common.txt", "path to wordlist")
	fuzzCmd.Flags().IntP("threads", "t", 50, "concurrent threads")

	harvestCmd.Flags().BoolP("passive", "p", true, "passive recon only")

	owaspCmd.Flags().BoolP("full", "f", false, "run all TOP 10 checks")

	shodanCmd.Flags().StringP("api-key", "k", "", "Shodan API key (or set SHODAN_API_KEY env)")

	xssCmd.Flags().BoolP("polyglot", "P", false, "use polyglot payloads")

	rootCmd.AddCommand(fuzzCmd, harvestCmd, owaspCmd, shodanCmd, xssCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
