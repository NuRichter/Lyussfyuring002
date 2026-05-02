# lyussfyuring002

> web exploitation + OSINT toolkit for people who actually know what they're doing

**only runs on arch linux and kali linux.** that's intentional. if you're on windows, unironically install a real OS first.

```
  ██╗  ██╗   ██╗██╗   ██╗███████╗███████╗
  ██║  ╚██╗ ██╔╝██║   ██║██╔════╝██╔════╝
  ██║   ╚████╔╝ ██║   ██║███████╗███████╗
  ██║    ╚██╔╝  ██║   ██║╚════██║╚════██║
  ███████╗██║   ╚██████╔╝███████║███████║
  ╚══════╝╚═╝    ╚═════╝ ╚══════╝╚══════╝
```

---

## what is this

lyussfyuring002 is a modular web exploitation and OSINT suite. it covers the full stack: passive recon, active scanning, XSS probing, OWASP checks, Shodan lookups, and entity graph mapping. the core is Go, the heavy OSINT stuff is Ruby, there's a tiny bit of Python for CVE enrichment (5%, capped, on purpose), and a C shellcode loader for binary analysis. shell scripts glue everything together.

built for:
- OWASP TOP 10 scanning
- FFUF-style directory fuzzing
- Nikto-style web banner/header/path scanning
- TheHarvester-style passive OSINT harvest
- Shodan API search and host enrichment
- Maltego-style entity graph mapping
- XSS reflection probing (basic + polyglot)
- OSINT Framework source dispatching

---

## tech stack

| layer         | tech           | weight |
|---------------|----------------|--------|
| core CLI      | Go 1.22        | ~50%   |
| OSINT + scan  | Ruby 3.3       | ~35%   |
| binary / PoC  | C (gcc)        | ~5%    |
| XSS payloads  | raw text / XSS | ~3%    |
| automation    | bash           | ~2%    |
| CVE enrichment| Python 3       | ~5%    |

---

## install

```bash
git clone https://github.com/NuRichter/Lyussfyuring002
cd Lyussfyuring002
bash install.sh
```

the installer auto-detects arch vs kali and installs the right packages. it also builds the Go binary and the C payload runner.

manual if you prefer:

**arch linux**
```bash
sudo pacman -Sy go ruby whois bind-tools nmap curl zip
sudo gem install colorize --no-document
make build
```

**kali linux**
```bash
sudo apt update && sudo apt install -y golang-go ruby ruby-dev whois dnsutils nmap curl zip build-essential
sudo gem install colorize --no-document
make build
```

---

## usage

### go CLI (lyuss)

```bash
# directory fuzzing (ffuf-style)
./lyuss fuzz https://target.com -w /usr/share/wordlists/dirb/common.txt -t 80

# OSINT harvest (theharvester-style)
./lyuss harvest target.com --passive

# OWASP TOP 10 scan
./lyuss owasp https://target.com --full

# Shodan search
./lyuss shodan "nginx port:443 country:ID" --api-key YOUR_KEY

# XSS probe (basic)
./lyuss xss "https://target.com/search?q=test"

# XSS probe (polyglot mode)
./lyuss xss "https://target.com/search?q=test" --polyglot
```

### ruby tools

```bash
# Nikto-style scan
ruby ruby/nikto_scan.rb https://target.com -o output/nikto.json

# Maltego-style entity graph mapper
ruby ruby/maltego_map.rb target.com -d 3 -o output/graph.json

# OSINT Framework dispatcher
ruby ruby/osint_framework.rb --type domain target.com
ruby ruby/osint_framework.rb --type username yourhandle --check
ruby ruby/osint_framework.rb --type email user@target.com
ruby ruby/osint_framework.rb --type ip 1.2.3.4
```

### full recon pipeline

```bash
# passive only
bash shell/recon.sh -p target.com

# full recon with Shodan
bash shell/recon.sh -k YOUR_SHODAN_KEY target.com

# custom wordlist + output dir
bash shell/recon.sh -w ~/wordlists/big.txt -o ~/results target.com
```

### C payload runner (binary analysis)

```bash
make c_build
./bin/payload_runner payload.lyu --dump   # hexdump only
./bin/payload_runner payload.lyu          # execute (PoC, lab use only)
```

### Python CVE enrichment

```bash
# lookup a specific CVE
python3 scripts/enrich.py cve CVE-2024-12345

# Shodan host enrichment
python3 scripts/enrich.py 1.2.3.4 YOUR_SHODAN_KEY
```

---

## XSS payloads

```bash
# basic payloads
cat xss/payloads/basic.txt

# polyglot payloads
cat xss/payloads/polyglot.txt
```

pass them directly to the XSS module or load into your burp intruder.

---

## project structure

```
Lyussfyuring002/
  cmd/lyuss/          go CLI entrypoint
  pkg/
    fuzzer/           ffuf-style directory fuzzer
    harvester/        passive OSINT recon (DNS + crt.sh)
    owasp/            OWASP TOP 10 checks
    shodan/           Shodan API client
    xss/              XSS reflection prober
  ruby/
    nikto_scan.rb     nikto-style web scanner
    maltego_map.rb    entity graph mapper
    osint_framework.rb OSINT source dispatcher
  shell/
    recon.sh          full recon pipeline
  bin/
    payload_runner.c  C shellcode loader (PoC)
  scripts/
    enrich.py         CVE + Shodan enrichment (Python, 5%)
  xss/payloads/
    basic.txt         basic XSS payloads
    polyglot.txt      polyglot XSS payloads
  .github/workflows/  CI (build + lint)
  install.sh          distro-aware installer
  Makefile
```

---

## environment variables

| var              | used by                     |
|------------------|-----------------------------|
| `SHODAN_API_KEY` | lyuss shodan, scripts/enrich.py |

---

## requirements

| tool   | arch pkg           | kali pkg        |
|--------|--------------------|-----------------|
| Go     | `go`               | `golang-go`     |
| Ruby   | `ruby`             | `ruby ruby-dev` |
| gcc    | `gcc`              | `build-essential` |
| dig    | `bind-tools`       | `dnsutils`      |
| whois  | `whois`            | `whois`         |
| nmap   | `nmap`             | `nmap`          |

---

## ethics

this is a security research toolkit. only run against targets you own or have explicit written permission to test. unauthorized scanning is illegal in most jurisdictions. the XSS payloads and shellcode loader are for CTF, lab, and authorized pentest use only.

---

## author

**ibnu khoirul anwar** // NuRichter Workspace, Jakarta

> built for the people who stay up debugging at 2am and think it's fun

---

## license

MIT. do whatever. just don't be weird about it.
