# CDN-Finder

CDN-Finder is a Go-based tool to discover real/origin IPs of websites behind CDNs such as Cloudflare, CloudFront, etc. It supports both passive and active verification and produces results in JSON and HTML formats.

---

## Features

* Detect CDN provider and real IP candidates.
* Passive detection using DNS, MX records, reverse DNS, and SSL SANs.
* Active verification via HTTP probes (requires authorization).
* Subdomain enumeration using `subfinder` and `amass` if installed.
* Supports multiple output formats: JSON and HTML.
* Logs tool outputs separately for clarity.

---

## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/MRvirusIR/cdn-finder.git
cd cdn-finder
```

2. **Install the tool:**

```bash
go install github.com/MRvirusIR/cdn-finder@latest
```

> Ensure your `$GOPATH/bin` is in your system PATH.

3. **Install optional dependencies for enhanced scanning:**

```bash
# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# amass (or via system package manager)
sudo apt install amass
# or
 go install -v github.com/owasp-amass/amass/v3/...@latest

# dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

---

## Usage

**Single Domain Scan:**

```bash
cdn-finder -d example.com
```

**Multiple Domains (from file):**

```bash
cdn-finder -f domains.txt
```

**Enable Active Verification (requires permission):**

```bash
cdn-finder -d example.com -active
```

**Optional Flags:**

```
-timeout N          Passive source timeout (default 25s)
-no-tools           Skip calling external tools
-active-timeout N   Active HTTP probe timeout (default 12s)
-ua STRING          Custom HTTP User-Agent
-scheme http|https  Scheme for active fetch (default https)
-ports 80,443       Custom ports for active verification
```

---

## Outputs

* **JSON report:** `results/<domain>/results.json`
* **HTML report:** `results/<domain>/results.html`
* **Tool logs:** `results/<domain>/<tool>.log`

> Note: Active verification sends HTTP requests. Always ensure you have proper authorization before scanning.

---

## Contributing

* Fork the repository.
* Create a new branch for your feature or fix.
* Submit a pull request with detailed description.

---

## License

This project is licensed under the MIT License.
