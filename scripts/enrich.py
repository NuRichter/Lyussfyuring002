#!/usr/bin/env python3
"""
Lyussfyuring002 :: enrich.py
Minimal Python utility for Shodan host enrichment + CVE lookup.
This is intentionally small - 5% of the stack only.
Target: Arch Linux / Kali Linux
"""

import sys
import json
import urllib.request
import urllib.parse
import os


def shodan_host(ip: str, api_key: str) -> dict:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read())


def nvd_cve(cve_id: str) -> dict:
    encoded = urllib.parse.quote(cve_id)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={encoded}"
    req = urllib.request.Request(url, headers={"User-Agent": "Lyussfyuring002/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: enrich.py <ip> [shodan_api_key]")
        print("       enrich.py cve CVE-2024-XXXX")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "cve":
        cve_id = sys.argv[2] if len(sys.argv) > 2 else None
        if not cve_id:
            print("error: CVE ID required")
            sys.exit(1)
        data = nvd_cve(cve_id)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"no data for {cve_id}")
            return
        cve = vulns[0]["cve"]
        desc = cve["descriptions"][0]["value"]
        print(f"\n[CVE] {cve_id}")
        print(f"  description : {desc[:200]}")
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            sev   = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            print(f"  CVSS v3.1   : {score} ({sev})")
        return

    ip      = mode
    api_key = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        print("error: Shodan API key required (arg or SHODAN_API_KEY env)")
        sys.exit(1)

    data = shodan_host(ip, api_key)
    print(f"\n[HOST] {ip}")
    print(f"  org       : {data.get('org', 'n/a')}")
    print(f"  isp       : {data.get('isp', 'n/a')}")
    print(f"  os        : {data.get('os', 'n/a')}")
    print(f"  country   : {data.get('country_name', 'n/a')}")
    print(f"  city      : {data.get('city', 'n/a')}")
    print(f"  ports     : {data.get('ports', [])}")
    vulns = data.get("vulns", [])
    if vulns:
        print(f"  vulns     : {', '.join(list(vulns)[:10])}")


if __name__ == "__main__":
    main()
