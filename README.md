# CDN Finder – Origin Reveal PRO

[![Go Version](https://img.shields.io/badge/go-1.21-blue)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![GitHub stars](https://img.shields.io/github/stars/MRvirusIR/cdn-finder?style=social)](https://github.com/MRvirusIR/cdn-finder/stargazers)

## 🔹 Overview

**CDN Finder / Origin Reveal PRO** is a powerful CLI tool designed to identify **real IP addresses behind CDN-protected websites**. It combines **passive reconnaissance** with optional **active verification** to generate detailed **JSON and HTML reports**.

---

## ⚙️ Features

* Collects **current DNS records (A, AAAA, MX)**
* Detects **subdomains** using crt.sh and optional external tools
* Filters out **CDN IPs** (Cloudflare, Fastly, Akamai, CloudFront, Imperva, etc.)
* Discovers **real IP candidates** using passive heuristics and active probing
* Active verification: compares status code, page title, server headers, and content SHA256
* Generates **per-domain JSON + HTML reports** for analysis or sharing
* Compatible with optional external tools: `subfinder`, `amass`, `dnsx`, `httpx`, `nuclei`

---

## 🛠 Prerequisites

* Go 1.21 or higher
* Internet connection for passive and active sources
* (Optional) External tools installed for enhanced subdomain enumeration

---

## 📥 Installation

### Install via `go install`:

```bash
go install github.com/MRvirusIR/cdn-finder@latest
```

> After installation, the binary `cdn-finder` will be available in `$GOPATH/bin` or `$HOME/go/bin`.

### Run directly from source:

```bash
git clone https://github.com/MRvirusIR/cdn-finder.git
cd cdn-finder
./cdn-finder -d example.com
#go run ./script.go -d example.com
```

---

## 💻 Usage

### Passive Scan

```bash
cdn-finder -d example.com
```

### Active Verification

```bash
cdn-finder -d example.com -active
```

### Scan Multiple Domains

```bash
cdn-finder -f domains.txt -active
```

### Important Flags

| Flag              | Description                                                            |      |
| ----------------- | ---------------------------------------------------------------------- | ---- |
| `-d`              | Single domain to scan (e.g., example.com)                              |      |
| `-f`              | File containing a list of domains (one per line)                       |      |
| `-timeout`        | Passive HTTP source timeout in seconds (default: 25)                   |      |
| `-active`         | Enable active verification against candidate IPs                       |      |
| `-active-timeout` | Active HTTP probe timeout in seconds (default: 12)                     |      |
| `-ua`             | Custom User-Agent string for HTTP requests                             |      |
| `-scheme`         | Scheme for baseline/active fetch (`http` or `https`, default: `https`) |      |
| `-ports`          | Comma-separated ports for active probes (default: 80                   | 443) |
| `-no-tools`       | Disable external tool execution even if installed                      |      |

---

## 📂 Output

* Each scanned domain creates a folder: `results/<domain>/`
* Reports are saved as:

  * `<domain>.json` – structured JSON output
  * `<domain>.html` – user-friendly HTML report

### Example

```bash
results/example.com/
  ├─ example.com.json
  └─ example.com.html
```

---

## ⚖️ Legal Notice

* Use this tool **only on domains you are authorized to test**.
* Always comply with local laws and ethical guidelines for cybersecurity testing.

---

## 🔗 Links

* Repository: [https://github.com/MRvirusIR/cdn-finder](https://github.com/MRvirusIR/cdn-finder)
* Go Documentation: [https://golang.org/doc/](https://golang.org/doc/)
* License: MIT

---

## 🎬 Screenshots / Demo

*Coming soon: Add GIFs or screenshots to showcase reports and scans.*
