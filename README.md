

# CDN-Finder

CDN-Finder is a Go-based tool to discover real/origin IPs of websites behind CDNs like Cloudflare, CloudFront, etc. It supports passive and active verification and generates results in JSON and HTML formats.

---

## Features

- Detect CDN provider and real IP candidates
- Passive detection using DNS, MX records, and SSL SANs
- Active verification via HTTP probes (requires authorization)
- Subdomain enumeration with `subfinder` and `amass`
- Supports multiple output formats (JSON & HTML)
- Logs tool outputs separately

---

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/MRvirusIR/cdn-finder.git
cd cdn-finder
```

2. **Install dependencies/tools:**

- **Go:** Install guide: [https://go.dev/doc/install](https://go.dev/doc/install)

- **subfinder:**
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

- **amass:**
```bash
sudo apt install amass
# or via Go:
go install -v github.com/owasp-amass/amass/v3/...@latest
```

- **dnsx:**
```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

- **httpx:**
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

- **httpx-toolkit:** Optional alternative for HTTP probing

- **nuclei:**
```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

> Make sure `$GOPATH/bin` is in your PATH to use installed tools globally.

---

## Usage

### Single Domain
```bash
go run ./script.go -d example.com
```

### Domain List
```bash
go run ./script.go -f domains.txt
```

### Active Verification (requires permission)
```bash
go run ./script.go -d example.com -active
```

---

## Outputs

- **JSON:** `results/<domain>/results.json`  
- **HTML:** `results/<domain>/results.html`  
- **Tool logs:** `results/<domain>/<tool>.log`  

---

## Notes

- Verify you have permission before running active scans.
- Passive detection is safe; active verification sends HTTP requests.
- Real IP candidates are heuristically determined; always cross-check before use.
- Subdomain enumeration depends on installed tools.

---

## Contributing

- Fork the repo
- Create a new branch for your feature/fix
- Submit a pull request with detailed description

---

## License

This project is licensed under **MIT License**
```

