package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
  CDN-Finder Pro — Passive + Active Verify with Progress UI

  New in this build:
  - Rich progress logs per stage (toggle with -progress=false)
  - Tool selection via -tools:
      * all (default)
      * none
      * or comma-separated list: subfinder,amass,dnsx,httpx,nuclei
  - End-of-run colored summary for each domain
  - Safer JSON tags, robust err handling, cleaner HTML template
  - Same outputs: results/<domain>/results.json + results.html + per-tool logs
  - Respect authorization. Active verify sends HTTP(S) with SNI+Host. Legal/ethical only.
*/

// ---------- Colors ----------
const (
	CLR_RESET = "\033[0m"
	CLR_DIM   = "\033[2m"
	CLR_RED   = "\033[31m"
	CLR_GRN   = "\033[32m"
	CLR_YEL   = "\033[33m"
	CLR_BLU   = "\033[34m"
	CLR_CYN   = "\033[36m"
)

// ---------- Types ----------
type ToolUsage struct {
	Tool   string `json:"tool"`
	Status string `json:"status"` // success | error | not installed | skipped
	Log    string `json:"log"`
}

type ActiveProbe struct {
	IP            string            `json:"ip"`
	Port          int               `json:"port"`
	Scheme        string            `json:"scheme"`
	StatusCode    int               `json:"status_code"`
	Title         string            `json:"title"`
	ServerHeader  string            `json:"server_header"`
	ContentSHA256 string            `json:"content_sha256"`
	BytesSampled  int               `json:"bytes_sampled"`
	RoundTripMS   int64             `json:"round_trip_ms"`
	SimilarityNote string           `json:"similarity_note"`
	MatchScore    int               `json:"match_score"` // 0..100
	Headers       map[string]string `json:"headers"`
	Error         string            `json:"error,omitempty"`
}

type ActiveBaseline struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Title          string            `json:"title"`
	ServerHeader   string            `json:"server_header"`
	ContentSHA256  string            `json:"content_sha256"`
	BytesSampled   int               `json:"bytes_sampled"`
	Headers        map[string]string `json:"headers"`
	Error          string            `json:"error,omitempty"`
}

type ScanResult struct {
	Domain            string            `json:"domain"`
	ScannedAt         string            `json:"scanned_at"`
	ResolvedIPs       []string          `json:"resolved_ips"`
	AAAAIPs           []string          `json:"aaaa_ips"`
	MXHosts           []string          `json:"mx_hosts"`
	MXIPs             []string          `json:"mx_ips"`
	ReverseDNS        []string          `json:"reverse_dns"`
	CDNProvider       string            `json:"cdn_provider"`
	SSL_SANs          []string          `json:"ssl_sans"`
	Subdomains        []string          `json:"subdomains"`
	HistoricalA       []string          `json:"historical_a"`
	HistoricalAAAA    []string          `json:"historical_aaaa"`
	FilteredIPs       []string          `json:"filtered_ips"`
	RealIPCandidates  []string          `json:"real_ip_candidates"`
	RealIPPassive     string            `json:"real_ip_passive"`
	ActiveEnabled     bool              `json:"active_enabled"`
	ActiveBaseline    *ActiveBaseline   `json:"active_baseline,omitempty"`
	ActiveProbes      []ActiveProbe     `json:"active_probes,omitempty"`
	ActiveBestIP      string            `json:"active_best_ip,omitempty"`
	ActiveBestScore   int               `json:"active_best_score,omitempty"`
	ToolsUsed         []ToolUsage       `json:"tools_used"`
	Notes             []string          `json:"notes"`
	PassiveSourcesHit map[string]string `json:"passive_sources_hit"`
}

// ---------- CDN ranges & heuristics ----------
var cdnCIDRs = []string{
	// Cloudflare IPv4
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"172.64.0.0/13", "131.0.72.0/22",
	// Cloudflare IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	// Fastly (sample)
	"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "199.27.72.0/21", "151.101.0.0/16",
	// Akamai (sample)
	"23.0.0.0/12", "23.64.0.0/14", "23.72.0.0/13", "72.246.0.0/15",
	// CloudFront (sample)
	"13.32.0.0/15", "13.224.0.0/12", "52.46.0.0/18", "52.84.0.0/15", "54.182.0.0/16", "54.230.0.0/16",
	// Imperva (sample)
	"199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
}
var cdnRDNSHints = []string{
	"cloudflare", "cloudfront", "fastly", "akamai", "akamaiedge", "edgesuite", "imperva", "incapsula", "stackpath", "cdn77", "cachefly",
}

// ---------- Utils ----------
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05") }

func uniqSorted(ss []string) []string {
	m := map[string]struct{}{}
	out := []string{}
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := m[s]; !ok {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
func uniqInt(in []int) []int {
	m := map[int]struct{}{}
	out := []int{}
	for _, v := range in {
		if _, ok := m[v]; !ok {
			m[v] = struct{}{}
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}
func writeFile(path string, data []byte) {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, data, 0o644)
}
func ipInCIDRs(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		_, nw, err := net.ParseCIDR(c)
		if err == nil && nw.Contains(ip) {
			return true
		}
	}
	return false
}
func looksLikeCDNByRDNS(ptr string) bool {
	p := strings.ToLower(ptr)
	for _, k := range cdnRDNSHints {
		if strings.Contains(p, k) {
			return true
		}
	}
	return false
}

// ---------- Simple progress logger ----------
type logger struct {
	enabled bool
	prefix  string
}
func (l logger) Step(format string, a ...any) {
	if !l.enabled { return }
	fmt.Printf("%s%s[*]%s %s\n", CLR_CYN, l.prefix, CLR_RESET, fmt.Sprintf(format, a...))
}
func (l logger) OK(format string, a ...any) {
	if !l.enabled { return }
	fmt.Printf("%s%s[OK]%s %s\n", CLR_GRN, l.prefix, CLR_RESET, fmt.Sprintf(format, a...))
}
func (l logger) Warn(format string, a ...any) {
	if !l.enabled { return }
	fmt.Printf("%s%s[!]%s %s\n", CLR_YEL, l.prefix, CLR_RESET, fmt.Sprintf(format, a...))
}
func (l logger) Err(format string, a ...any) {
	if !l.enabled { return }
	fmt.Printf("%s%s[x]%s %s\n", CLR_RED, l.prefix, CLR_RESET, fmt.Sprintf(format, a...))
}
func (l logger) Info(format string, a ...any) {
	if !l.enabled { return }
	fmt.Printf("%s%s[-]%s %s\n", CLR_DIM, l.prefix, CLR_RESET, fmt.Sprintf(format, a...))
}

// ---------- External tools ----------
func runToolSaveLog(tool string, args []string, logPath string) ToolUsage {
	if _, err := exec.LookPath(tool); err != nil {
		return ToolUsage{Tool: tool, Status: "not installed", Log: ""}
	}
	cmd := exec.Command(tool, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	writeFile(logPath, out.Bytes())
	if err != nil {
		return ToolUsage{Tool: tool, Status: "error", Log: logPath}
	}
	return ToolUsage{Tool: tool, Status: "success", Log: logPath}
}

// ---------- HTTP helpers ----------
var httpClient = &http.Client{
	Timeout: 25 * time.Second,
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}
func fetchJSON(ctx context.Context, u string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("User-Agent", "CDN-Finder-Pro/1.1")
	resp, err := httpClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// crt.sh — CT logs
func fetchCrtShSANs(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	data, err := fetchJSON(ctx, u)
	if err != nil { return nil, err }
	body := strings.TrimSpace(string(data))
	if body == "" || body == "[]" { return nil, nil }
	if !strings.HasPrefix(body, "[") {
		body = "[" + strings.ReplaceAll(body, "}{", "},{") + "]"
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(body), &arr); err != nil { return nil, err }
	sans := []string{}
	for _, o := range arr {
		if n, ok := o["name_value"].(string); ok {
			for _, line := range strings.Split(n, "\n") {
				line = strings.TrimSpace(line)
				if line == "" { continue }
				line = strings.TrimPrefix(line, "*.")
				if line == domain || strings.HasSuffix(line, "."+domain) {
					sans = append(sans, line)
				}
			}
		}
	}
	return uniqSorted(sans), nil
}

// bufferover — historical dns
type bufferOverResp struct {
	FDNS_A     []string `json:"FDNS_A"`
	RDNS_A     []string `json:"RDNS_A"`
	FDNS_AAAA  []string `json:"FDNS_AAAA"`
	RDNS_AAAA  []string `json:"RDNS_AAAA"`
}
func fetchBufferOver(ctx context.Context, domain string) (as, aaaas []string, err error) {
	u := fmt.Sprintf("https://dns.bufferover.run/dns?q=%s", url.QueryEscape(domain))
	data, err := fetchJSON(ctx, u)
	if err != nil { return nil, nil, err }
	var out bufferOverResp
	if err := json.Unmarshal(data, &out); err != nil { return nil, nil, err }
	collect := func(lines []string, wantIPv6 bool) []string {
		acc := []string{}
		for _, l := range lines {
			parts := strings.Split(l, ",") // "<host>,<ip>"
			if len(parts) != 2 { continue }
			ip := strings.TrimSpace(parts[1])
			parsed := net.ParseIP(ip)
			if parsed == nil { continue }
			if wantIPv6 && parsed.To4() == nil { acc = append(acc, ip) }
			if !wantIPv6 && parsed.To4() != nil { acc = append(acc, ip) }
		}
		return uniqSorted(acc)
	}
	a := uniqSorted(append(collect(out.FDNS_A, false), collect(out.RDNS_A, false)...))
	aaaa := uniqSorted(append(collect(out.FDNS_AAAA, true), collect(out.RDNS_AAAA, true)...))
	return a, aaaa, nil
}

// ---------- DNS helpers ----------
func resolveA(host string) []string {
	ips, _ := net.LookupIP(host)
	out := []string{}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return uniqSorted(out)
}
func resolveAAAA(host string) []string {
	ips, _ := net.LookupIP(host)
	out := []string{}
	for _, ip := range ips {
		if ip.To4() == nil {
			out = append(out, ip.String())
		}
	}
	return uniqSorted(out)
}
func resolveMX(host string) (hosts []string, ips []string) {
	mx, _ := net.LookupMX(host)
	for _, m := range mx {
		h := strings.TrimSuffix(m.Host, ".")
		hosts = append(hosts, h)
		ips = append(ips, resolveA(m.Host)...)
		ips = append(ips, resolveAAAA(m.Host)...)
	}
	return uniqSorted(hosts), uniqSorted(ips)
}
func ptrOf(ip string) []string {
	ptrs, _ := net.LookupAddr(ip)
	for i := range ptrs { ptrs[i] = strings.TrimSpace(ptrs[i]) }
	return uniqSorted(ptrs)
}

// ---------- Passive heuristics ----------
func detectCDNProvider(resolvedIPs, reversePTRs []string) string {
	for _, p := range reversePTRs {
		if looksLikeCDNByRDNS(p) {
			lp := strings.ToLower(p)
			switch {
			case strings.Contains(lp, "cloudflare"): return "Cloudflare"
			case strings.Contains(lp, "fastly"): return "Fastly"
			case strings.Contains(lp, "akamai"): return "Akamai"
			case strings.Contains(lp, "cloudfront"): return "Amazon CloudFront"
			case strings.Contains(lp, "imperva"), strings.Contains(lp, "incapsula"): return "Imperva"
			}
		}
	}
	for _, ip := range resolvedIPs {
		if ipInCIDRs(ip, cdnCIDRs) {
			if ipInCIDRs(ip, []string{"104.16.0.0/13", "172.64.0.0/13"}) {
				return "Cloudflare"
			}
			return "CDN"
		}
	}
	return ""
}
func filterNonCDN(ips []string, rdns []string) []string {
	non := []string{}
	for _, ip := range ips {
		if ipInCIDRs(ip, cdnCIDRs) { continue }
		isCDN := false
		ptrs := ptrOf(ip)
		for _, p := range append(rdns, ptrs...) {
			if looksLikeCDNByRDNS(p) { isCDN = true; break }
		}
		if !isCDN { non = append(non, ip) }
	}
	return uniqSorted(non)
}
func chooseBestRealIP(candidates []string) string {
	for _, ip := range candidates {
		if ipInCIDRs(ip, cdnCIDRs) { continue }
		// skip RFC1918/CGNAT
		if ipInCIDRs(ip, []string{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10"}) { continue }
		return ip
	}
	return ""
}

// ---------- Active verify ----------
type httpFetchConfig struct {
	Scheme    string
	Domain    string
	IP        string // if non-empty, force dial to this IP
	Port      int
	UA        string
	TimeoutSec int
}
func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func extractTitle(htmlBody []byte) string {
	s := strings.ToLower(string(htmlBody))
	start := strings.Index(s, "<title>")
	end := strings.Index(s, "</title>")
	if start >= 0 && end > start {
		return html.UnescapeString(strings.TrimSpace(string(htmlBody[start+7 : end])))
	}
	return ""
}
func doFetch(cfg httpFetchConfig) (status int, bodyHash, title, server string, headers map[string]string, rttMS int64, sampled int, err error) {
	headers = map[string]string{}
	port := cfg.Port
	if port == 0 {
		if cfg.Scheme == "http" { port = 80 } else { port = 443 }
	}
	targetHost := cfg.Domain
	addr := cfg.Domain
	if cfg.IP != "" { addr = cfg.IP }
	urlStr := fmt.Sprintf("%s://%s/", cfg.Scheme, targetHost)

	dialer := &net.Dialer{ Timeout: time.Duration(cfg.TimeoutSec) * time.Second }
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			start := time.Now()
			c, e := dialer.DialContext(ctx, network, net.JoinHostPort(addr, strconv.Itoa(port)))
			if e == nil { rttMS = time.Since(start).Milliseconds() }
			return c, e
		},
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.Domain, // SNI
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
		Transport: tr,
	}
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.Host = cfg.Domain
	if cfg.UA != "" { req.Header.Set("User-Agent", cfg.UA) } else { req.Header.Set("User-Agent", "CDN-Finder-Pro/1.1") }
	resp, e := client.Do(req)
	if e != nil { err = e; return }
	defer resp.Body.Close()

	status = resp.StatusCode
	for k, v := range resp.Header {
		if len(v) > 0 { headers[k] = v[0] }
	}
	server = headers["Server"]
	limit := int64(512 * 1024)
	lr := io.LimitReader(resp.Body, limit)
	buf, _ := io.ReadAll(lr)
	sampled = len(buf)
	bodyHash = hashOf(buf)
	title = extractTitle(buf)
	return
}
func activeBaselineFetch(scheme, domain, ua string, timeout int) *ActiveBaseline {
	st, bh, ti, srv, hdrs, _, sampled, err := doFetch(httpFetchConfig{
		Scheme: scheme, Domain: domain, TimeoutSec: timeout, UA: ua,
	})
	ab := &ActiveBaseline{
		URL:           fmt.Sprintf("%s://%s/", scheme, domain),
		StatusCode:    st,
		Title:         ti,
		ServerHeader:  srv,
		ContentSHA256: bh,
		BytesSampled:  sampled,
		Headers:       hdrs,
	}
	if err != nil { ab.Error = err.Error() }
	return ab
}
func scoreCandidate(b *ActiveBaseline, p *ActiveProbe) (score int, note string) {
	if b == nil || p == nil { return 0, "no baseline/probe" }
	s := 0
	if b.StatusCode != 0 && b.StatusCode == p.StatusCode { s += 40 }
	if b.ContentSHA256 != "" && b.ContentSHA256 == p.ContentSHA256 { s += 30 }
	if strings.TrimSpace(strings.ToLower(b.Title)) != "" && strings.ToLower(b.Title) == strings.ToLower(p.Title) { s += 10 }
	if b.ServerHeader != "" && b.ServerHeader == p.ServerHeader { s += 10 }
	if b.ContentSHA256 != "" && b.ContentSHA256 != p.ContentSHA256 && b.StatusCode == p.StatusCode && strings.ToLower(b.Title) == strings.ToLower(p.Title) { s += 10 }
	if s > 100 { s = 100 }
	switch {
	case s >= 80: note = "strong match"
	case s >= 60: note = "likely match"
	case s >= 40: note = "weak match"
	default: note = "poor match"
	}
	return s, note
}

// ---------- HTML report ----------
const htmlTpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>CDN Bypass Report - {{.Domain}}</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
body { font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; line-height:1.5; padding:24px; color:#111; background:#fafafa;}
h1 { margin: 0 0 10px; }
.pill { display:inline-block; padding:4px 10px; border-radius:999px; background:#eef2ff; font-size:12px; margin-left:8px;}
section { margin-top: 22px; }
pre, code { background:#f8fafc; padding:12px; border-radius:12px; overflow:auto; }
.card { border:1px solid #e5e7eb; border-radius:16px; padding:16px; margin:12px 0; background:#fff; }
.good { color:#065f46; } .warn { color:#b45309; } .bad { color:#7f1d1d; } .hl { background:#ecfccb; padding:2px 6px; border-radius:6px; }
table { border-collapse: collapse; width:100%; background:#fff; border:1px solid #e5e7eb; border-radius:12px; overflow:hidden;}
th, td { text-align:left; padding:10px; border-bottom:1px solid #e5e7eb; font-size:14px; }
th { background:#f1f5f9; }
small { color:#6b7280; }
.score { font-weight:600; }
</style>
</head>
<body>
<h1>CDN Bypass Report for {{.Domain}} <span class="pill">{{.ScannedAt}}</span></h1>
<div class="card">
  <p><b>Detected CDN:</b> {{if .CDNProvider}}{{.CDNProvider}}{{else}}<span class="warn">Unknown</span>{{end}}</p>
  <p><b>Passive Real IP:</b> {{if .RealIPPassive}}<span class="hl">{{.RealIPPassive}}</span>{{else}}<span class="warn">Not determined</span>{{end}}</p>
  {{if .ActiveEnabled}}
  <p><b>Active Best IP:</b> {{if .ActiveBestIP}}<span class="hl">{{.ActiveBestIP}}</span> <span class="score">({{.ActiveBestScore}})</span>{{else}}<span class="warn">No confident match</span>{{end}}</p>
  {{end}}
</div>

<section>
  <h2>Current DNS</h2>
  <table>
    <tr><th>A (IPv4)</th><th>AAAA (IPv6)</th><th>MX Hosts</th></tr>
    <tr>
      <td>{{range .ResolvedIPs}}{{.}}<br>{{end}}</td>
      <td>{{range .AAAAIPs}}{{.}}<br>{{end}}</td>
      <td>{{range .MXHosts}}{{.}}<br>{{end}}</td>
    </tr>
  </table>
</section>

<section>
  <h2>Reverse DNS (PTR)</h2>
  <pre>{{range .ReverseDNS}}{{.}} {{end}}</pre>
</section>

<section>
  <h2>Filtered Non-CDN (from current DNS)</h2>
  <pre>{{range .FilteredIPs}}{{.}} {{end}}</pre>
</section>

<section>
  <h2>Passive Sources</h2>
  <div class="card">
    <p><b>crt.sh SANs</b></p>
    <pre>{{range .SSL_SANs}}{{.}} {{end}}</pre>
  </div>
  <div class="card">
    <p><b>Historical A</b></p>
    <pre>{{range .HistoricalA}}{{.}} {{end}}</pre>
  </div>
  <div class="card">
    <p><b>Historical AAAA</b></p>
    <pre>{{range .HistoricalAAAA}}{{.}} {{end}}</pre>
  </div>
</section>

<section>
  <h2>Subdomains (tools & CT)</h2>
  <pre>{{range .Subdomains}}{{.}} {{end}}</pre>
</section>

{{if .ActiveEnabled}}
<section>
  <h2>Active Verification</h2>
  <div class="card">
    <p><b>Baseline:</b> {{if .ActiveBaseline}}{{.ActiveBaseline.URL}} — Status: {{.ActiveBaseline.StatusCode}}, Title: "{{.ActiveBaseline.Title}}", SHA256: {{.ActiveBaseline.ContentSHA256}}{{if .ActiveBaseline.Error}} — <span class="bad">{{.ActiveBaseline.Error}}</span>{{end}}{{end}}</p>
  </div>
  <table>
    <tr><th>IP</th><th>Port</th><th>Status</th><th>Title</th><th>Server</th><th>SHA256</th><th>RTT (ms)</th><th>Score</th><th>Note</th></tr>
    {{range .ActiveProbes}}
    <tr>
      <td>{{.IP}}</td><td>{{.Port}}</td><td>{{.StatusCode}}</td>
      <td>{{.Title}}</td><td>{{.ServerHeader}}</td>
      <td><small>{{.ContentSHA256}}</small></td>
      <td>{{.RoundTripMS}}</td>
      <td class="score">{{.MatchScore}}</td>
      <td>{{.SimilarityNote}}{{if .Error}} — <span class="bad">{{.Error}}</span>{{end}}</td>
    </tr>
    {{end}}
  </table>
</section>
{{end}}

<section>
  <h2>Tools Used</h2>
  <table>
    <tr><th>Tool</th><th>Status</th><th>Log</th></tr>
    {{range .ToolsUsed}}
    <tr><td>{{.Tool}}</td><td>{{.Status}}</td><td>{{.Log}}</td></tr>
    {{end}}
  </table>
</section>

<section>
  <h2>Notes</h2>
  <pre>{{range .Notes}}{{.}} {{end}}</pre>
  <p><small>Authorized use only. Active verification uses SNI + Host header to test origins and may be blocked by ACL/WAF.</small></p>
</section>
</body>
</html>`

// ---------- Scan pipeline ----------
type runConfig struct {
	Scheme            string // http|https
	PassiveTimeoutSec int
	Active            bool
	ActiveTimeoutSec  int
	UserAgent         string
	Ports             []int
	Tools             map[string]bool // subfinder, amass, dnsx, httpx, nuclei
	Progress          bool
}

func parsePorts(csv string) []int {
	if strings.TrimSpace(csv) == "" { return nil }
	out := []int{}
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" { continue }
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return uniqInt(out)
}
func parseTools(s string) map[string]bool {
	all := map[string]bool{
		"subfinder": true,
		"amass":     true,
		"dnsx":      true,
		"httpx":     true,
		"nuclei":    true,
	}
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "", "all":
		return all
	case "none":
		for k := range all { all[k] = false }
		return all
	default:
		for k := range all { all[k] = false }
		for _, t := range strings.Split(s, ",") {
			t = strings.TrimSpace(t)
			if t == "" { continue }
			if _, ok := all[t]; ok { all[t] = true }
		}
		return all
	}
}

func scanDomain(domain string, cfg *runConfig, log logger) {
	log.Step("%sScanning %s%s", CLR_BLU, domain, CLR_RESET)
	outDir := filepath.Join("results", domain)
	_ = os.MkdirAll(outDir, 0o755)

	r := ScanResult{
		Domain:            domain,
		ScannedAt:         nowStr(),
		Notes:             []string{},
		PassiveSourcesHit: map[string]string{},
		ActiveEnabled:     cfg.Active,
	}

	// 1) Passive: current DNS
	log.Step("Resolving current DNS (A/AAAA/MX/PTR)")
	r.ResolvedIPs = resolveA(domain)
	r.AAAAIPs = resolveAAAA(domain)
	r.MXHosts, r.MXIPs = resolveMX(domain)
	ptrs := []string{}
	for _, ip := range r.ResolvedIPs {
		ptrs = append(ptrs, ptrOf(ip)...)
	}
	r.ReverseDNS = uniqSorted(ptrs)
	log.OK("DNS: A=%d, AAAA=%d, MX=%d, PTR=%d", len(r.ResolvedIPs), len(r.AAAAIPs), len(r.MXHosts), len(r.ReverseDNS))

	// 2) CDN detection
	r.CDNProvider = detectCDNProvider(r.ResolvedIPs, r.ReverseDNS)
	if r.CDNProvider != "" {
		log.Info("Detected CDN provider: %s", r.CDNProvider)
	} else {
		log.Warn("CDN provider not clearly detected")
	}

	// 3) External tools (optional + selectable)
	if cfg.Tools["subfinder"] || cfg.Tools["amass"] || cfg.Tools["dnsx"] || cfg.Tools["httpx"] || cfg.Tools["nuclei"] {
		log.Step("Running external tools (selected)")
	} else {
		log.Info("External tools disabled (none)")
	}

	if cfg.Tools["subfinder"] {
		log.Step("subfinder ...")
		sf := runToolSaveLog("subfinder", []string{"-d", domain, "-all", "-silent"}, filepath.Join(outDir, "subfinder.log"))
		r.ToolsUsed = append(r.ToolsUsed, sf)
		if sf.Status == "success" {
			raw, _ := os.ReadFile(filepath.Join(outDir, "subfinder.log"))
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && (line == domain || strings.HasSuffix(line, "."+domain)) {
					r.Subdomains = append(r.Subdomains, line)
				}
			}
		}
		log.Info("subfinder: %s", sf.Status)
	}
	if cfg.Tools["amass"] {
		log.Step("amass passive enum ...")
		am := runToolSaveLog("amass", []string{"enum", "-passive", "-norecursive", "-d", domain}, filepath.Join(outDir, "amass.log"))
		r.ToolsUsed = append(r.ToolsUsed, am)
		if am.Status == "success" {
			raw, _ := os.ReadFile(filepath.Join(outDir, "amass.log"))
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") { continue }
				parts := strings.Fields(line)
				if len(parts) == 0 { continue }
				host := parts[0]
				if host == domain || strings.HasSuffix(host, "."+domain) {
					r.Subdomains = append(r.Subdomains, host)
				}
			}
		}
		log.Info("amass: %s", am.Status)
	}
	if cfg.Tools["dnsx"] {
		log.Step("dnsx (A/AAAA) ...")
		dx := runToolSaveLog("dnsx", []string{"-silent", "-a", "-aaaa", "-retries", "1", "-rl", "100", "-d", domain}, filepath.Join(outDir, "dnsx.log"))
		r.ToolsUsed = append(r.ToolsUsed, dx)
		log.Info("dnsx: %s", dx.Status)
	} else {
		r.ToolsUsed = append(r.ToolsUsed, ToolUsage{Tool: "dnsx", Status: "skipped", Log: ""})
	}
	if len(r.Subdomains) > 0 && cfg.Tools["httpx"] {
		subListPath := filepath.Join(outDir, "subdomains.txt")
		writeFile(subListPath, []byte(strings.Join(uniqSorted(r.Subdomains), "\n")))
		log.Step("httpx (title/status/tech) ...")
		hx := runToolSaveLog("httpx",
			[]string{"-silent", "-title", "-tech-detect", "-status-code", "-follow-host-redirects", "-l", subListPath},
			filepath.Join(outDir, "httpx.log"))
		r.ToolsUsed = append(r.ToolsUsed, hx)
		log.Info("httpx: %s", hx.Status)
	} else if cfg.Tools["httpx"] {
		r.ToolsUsed = append(r.ToolsUsed, ToolUsage{Tool: "httpx", Status: "skipped (no subdomains)", Log: ""})
	}
	if cfg.Tools["nuclei"] {
		log.Step("nuclei (info/low) ...")
		nuc := runToolSaveLog("nuclei", []string{"-silent", "-u", cfg.Scheme + "://" + domain, "-severity", "info,low"}, filepath.Join(outDir, "nuclei.log"))
		r.ToolsUsed = append(r.ToolsUsed, nuc)
		log.Info("nuclei: %s", nuc.Status)
	}

	r.Subdomains = uniqSorted(r.Subdomains)

	// 4) Passive external sources
	log.Step("Passive sources: crt.sh & bufferover")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.PassiveTimeoutSec)*time.Second)
	defer cancel()

	if sans, err := fetchCrtShSANs(ctx, domain); err == nil {
		r.PassiveSourcesHit["crt.sh"] = "ok"
		r.SSL_SANs = uniqSorted(append(r.SSL_SANs, sans...))
		log.OK("crt.sh SANs: %d", len(sans))
	} else {
		r.PassiveSourcesHit["crt.sh"] = "error: " + err.Error()
		log.Err("crt.sh error: %v", err)
	}
	if a, aaaa, err := fetchBufferOver(ctx, domain); err == nil {
		r.PassiveSourcesHit["bufferover"] = "ok"
		r.HistoricalA = uniqSorted(append(r.HistoricalA, a...))
		r.HistoricalAAAA = uniqSorted(append(r.HistoricalAAAA, aaaa...))
		log.OK("bufferover A=%d AAAA=%d", len(a), len(aaaa))
	} else {
		r.PassiveSourcesHit["bufferover"] = "error: " + err.Error()
		log.Err("bufferover error: %v", err)
	}

	// Resolve SANs/subdomains for more IPs
	log.Step("Resolving derived hosts from SANs/Subdomains")
	derivedA := []string{}
	derivedAAAA := []string{}
	for _, host := range uniqSorted(append(r.Subdomains, r.SSL_SANs...)) {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			derivedA = append(derivedA, resolveA(host)...)
			derivedAAAA = append(derivedAAAA, resolveAAAA(host)...)
		}
	}
	derivedA = uniqSorted(derivedA)
	derivedAAAA = uniqSorted(derivedAAAA)
	log.OK("Derived IPs: A=%d AAAA=%d", len(derivedA), len(derivedAAAA))

	// 5) Filtering & candidates
	r.FilteredIPs = filterNonCDN(r.ResolvedIPs, r.ReverseDNS)
	pool := uniqSorted(append(append(r.HistoricalA, derivedA...), r.MXIPs...))
	cands := filterNonCDN(pool, nil)
	for _, ip6 := range append(r.HistoricalAAAA, derivedAAAA...) {
		if !ipInCIDRs(ip6, cdnCIDRs) {
			cands = append(cands, ip6)
		}
	}
	r.RealIPCandidates = uniqSorted(cands)
	r.RealIPPassive = chooseBestRealIP(r.RealIPCandidates)
	log.Step("Candidates: %d (passive best: %s)", len(r.RealIPCandidates), r.RealIPPassive)

	// 6) Active verification
	if cfg.Active && (len(r.RealIPCandidates) > 0 || len(r.FilteredIPs) > 0) {
		log.Step("Active verification enabled (scheme=%s)", cfg.Scheme)
		base := activeBaselineFetch(cfg.Scheme, domain, cfg.UserAgent, cfg.ActiveTimeoutSec)
		r.ActiveBaseline = base
		if base.Error != "" {
			log.Warn("Baseline error: %s", base.Error)
		} else {
			log.OK("Baseline: status=%d title=%q sha=%s", base.StatusCode, base.Title, base.ContentSHA256)
		}

		all := uniqSorted(append(r.RealIPCandidates, r.FilteredIPs...))
		ports := cfg.Ports
		if len(ports) == 0 {
			if cfg.Scheme == "http" { ports = []int{80} } else { ports = []int{443} }
		}

		bestScore := -1
		bestIP := ""
		for _, ip := range all {
			for _, port := range ports {
				st, bh, ti, srv, hdrs, rtt, sampled, err := doFetch(httpFetchConfig{
					Scheme: cfg.Scheme, Domain: domain, IP: ip, Port: port, UA: cfg.UserAgent, TimeoutSec: cfg.ActiveTimeoutSec,
				})
				pr := ActiveProbe{
					IP: ip, Port: port, Scheme: cfg.Scheme,
					StatusCode: st, Title: ti, ServerHeader: srv,
					ContentSHA256: bh, BytesSampled: sampled, RoundTripMS: rtt, Headers: hdrs,
				}
				if err != nil { pr.Error = err.Error() }
				score, note := scoreCandidate(base, &pr)
				pr.MatchScore = score
				pr.SimilarityNote = note
				r.ActiveProbes = append(r.ActiveProbes, pr)
				if score > bestScore {
					bestScore = score
					bestIP = ip
				}
				log.Info("Probe %s:%d -> status=%d title=%q score=%d (%s)", ip, port, st, ti, score, note)
			}
		}
		if bestScore >= 0 {
			r.ActiveBestIP = bestIP
			r.ActiveBestScore = bestScore
			log.OK("Active best: %s (score=%d)", bestIP, bestScore)
		}
	} else if cfg.Active {
		r.Notes = append(r.Notes, "Active verify requested but no candidates available (target likely fully proxied).")
		log.Warn("Active verify requested but no candidates found")
	}

	// 7) Notes
	if len(r.RealIPCandidates) == 0 {
		r.Notes = append(r.Notes, "No strong origin candidates from passive sources; target likely fully proxied/sanitized.")
	} else {
		r.Notes = append(r.Notes, "Review real_ip_candidates; verify authorization before any active checks.")
	}
	if r.RealIPPassive != "" {
		r.Notes = append(r.Notes, "Passive heuristic selected a likely origin IP (non-CDN, public).")
	}
	if r.ActiveBestIP != "" {
		r.Notes = append(r.Notes, fmt.Sprintf("Active verification suggests %s as the best match (score=%d).", r.ActiveBestIP, r.ActiveBestScore))
	}

	// 8) Save outputs
	jsonPath := filepath.Join(outDir, "results.json")
	htmlPath := filepath.Join(outDir, "results.html")
	jb, _ := json.MarshalIndent(r, "", "  ")
	writeFile(jsonPath, jb)
	t := template.Must(template.New("rep").Parse(htmlTpl))
	var buf bytes.Buffer
	_ = t.Execute(&buf, r)
	writeFile(htmlPath, buf.Bytes())

	log.OK("Saved: JSON=%s | HTML=%s", jsonPath, htmlPath)

	// 9) Console summary
	fmt.Printf("\n%s=== Summary: %s ===%s\n", CLR_BLU, domain, CLR_RESET)
	fmt.Printf("  CDN: %s\n", ternary(r.CDNProvider != "", r.CDNProvider, "Unknown"))
	fmt.Printf("  A/AAAA Records: %d / %d\n", len(r.ResolvedIPs), len(r.AAAAIPs))
	fmt.Printf("  Subdomains: %d | SANs: %d\n", len(r.Subdomains), len(r.SSL_SANs))
	fmt.Printf("  Historical IPs: A=%d AAAA=%d\n", len(r.HistoricalA), len(r.HistoricalAAAA))
	fmt.Printf("  Candidates: %d | Passive best: %s\n", len(r.RealIPCandidates), ternary(r.RealIPPassive != "", r.RealIPPassive, "-"))
	if r.ActiveEnabled {
		fmt.Printf("  Active: best=%s (score=%d)\n", ternary(r.ActiveBestIP != "", r.ActiveBestIP, "-"), r.ActiveBestScore)
	}
	fmt.Printf("  Outputs: %s , %s\n\n", jsonPath, htmlPath)
}

func ternary[T any](cond bool, a, b T) T {
	if cond { return a }
	return b
}

// ---------- Banner ----------
const banner = `
   ____ ____  _   _     _____ _           _           
  / ___|  _ \| \ | |   |  ___(_)_ __   __| | ___ _ __ 
 | |   | | | |  \| |   | |_  | | '_ \ / _' |/ _ \ '__|
 | |___| |_| | |\  |   |  _| | | | | | (_| |  __/ |   
  \____|____/|_| \_|   |_|   |_|_| |_|\__,_|\___|_|   
                                                     
  T.me/BugCod3       CDN-FINDER      T.me/Exploit_Forge
`

func printBanner() {
	fmt.Printf("%s%s%s\n", CLR_GRN, banner, CLR_RESET)
}
// ---------- CLI ----------
func main() {
	printBanner()

	single := flag.String("d", "", "Single domain to scan (e.g., example.com)")
	list := flag.String("f", "", "Path to file with domains (one per line)")

	timeout := flag.Int("timeout", 25, "Passive HTTP source timeout (seconds)")
	active := flag.Bool("active", false, "Enable active verification against candidate IPs")
	activeTimeout := flag.Int("active-timeout", 12, "HTTP(S) active probe timeout (seconds)")
	ua := flag.String("ua", "CDN-Finder-Pro/1.1", "HTTP User-Agent for active requests")
	scheme := flag.String("scheme", "https", "Scheme for baseline/active fetch (http or https)")
	portsCSV := flag.String("ports", "", "Comma-separated ports for active verify (default 80|443 based on scheme)")

	tools := flag.String("tools", "all", "Tool selection: all | none | comma list (subfinder,amass,dnsx,httpx,nuclei)")
	progress := flag.Bool("progress", true, "Show step-by-step progress logs")

	flag.Parse()

	if *single == "" && *list == "" {
		fmt.Println("Usage:")
		fmt.Println("  cdn-finder -d example.com [options]")
		fmt.Println("  cdn-finder -f domains.txt [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  -timeout N           Passive source timeout (default 25)")
		fmt.Println("  -active              Enable active verification")
		fmt.Println("  -active-timeout N    Active HTTP timeout (default 12)")
		fmt.Println("  -ua STRING           HTTP User-Agent for active fetch")
		fmt.Println("  -scheme http|https   Scheme for baseline/active (default https)")
		fmt.Println("  -ports 80,443        Ports for active verify (default based on scheme)")
		fmt.Println("  -tools all|none|list Tool selection, e.g. -tools=subfinder,amass,httpx")
	fmt.Println("  -progress=false     Disable stage progress logs")
		fmt.Println("\nExamples:")
		fmt.Println("  cdn-finder -d example.com -active -tools=all")
		fmt.Println("  cdn-finder -d example.com -tools=subfinder,amass -progress=false")
		fmt.Println("  cdn-finder -f domains.txt -tools=none")
		return
	}

	cfg := &runConfig{
		Scheme:            strings.ToLower(*scheme),
		PassiveTimeoutSec: *timeout,
		Active:            *active,
		ActiveTimeoutSec:  *activeTimeout,
		UserAgent:         *ua,
		Ports:             parsePorts(*portsCSV),
		Tools:             parseTools(*tools),
		Progress:          *progress,
	}

	targets := []string{}
	if *single != "" {
		targets = append(targets, strings.TrimSpace(*single))
	}
	if *list != "" {
		raw, err := os.ReadFile(*list)
		if err != nil {
			fmt.Println("File read error:", err)
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	for _, d := range targets {
		domain := strings.TrimSpace(d)
		if strings.Count(domain, ".") < 1 || strings.ContainsAny(domain, " /:\\") {
			fmt.Printf("%s[-] Skipping invalid domain:%s %s\n", CLR_RED, CLR_RESET, domain)
			continue
		}
		func(domain string) {
			log := logger{enabled: cfg.Progress, prefix: "[" + domain + "] "}
			defer func() {
				if rec := recover(); rec != nil {
					log.Err("Panic: %v", rec)
				}
			}()
			scanDomain(domain, cfg, log)
		}(domain)
	}
}

