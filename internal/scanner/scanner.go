package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MRvirusIR/Revelar/internal/asn"
	"github.com/MRvirusIR/Revelar/internal/cdn"
	"github.com/MRvirusIR/Revelar/internal/dnsr"
	"github.com/MRvirusIR/Revelar/internal/favicon"
	"github.com/MRvirusIR/Revelar/internal/sources"
	"github.com/MRvirusIR/Revelar/internal/tools"
	"github.com/MRvirusIR/Revelar/internal/util"
	"github.com/MRvirusIR/Revelar/internal/verify"
)

// Config controls a scan.
type Config struct {
	Version        string
	Scheme         string
	UA             string
	Resolvers      []string
	DNSTimeout     time.Duration
	DNSRetries     int
	PassiveTimeout time.Duration
	ActiveTimeout  time.Duration
	Threads        int
	SourceSpec     string
	UseTools       bool
	ToolTimeout    time.Duration
	Active         bool
	Ports          []int
	Wordlist       []string
	Brute          bool
	MinScore       int
	RefreshCDN     bool
	Deep           bool
	DeepASN        bool
	DeepMax        int
}

// Logger receives progress messages.
type Logger interface {
	Step(string, ...any)
	OK(string, ...any)
	Warn(string, ...any)
	Info(string, ...any)
	Err(string, ...any)
}

// Scanner runs scans.
type Scanner struct {
	cfg   Config
	cdnDB *cdn.DB
	res   *dnsr.Resolver
	asn   *asn.Resolver
	http  *http.Client
	log   Logger
}

// New builds a Scanner. db may be nil to build a fresh one.
func New(cfg Config, db *cdn.DB, log Logger) *Scanner {
	if db == nil {
		db = cdn.NewBuiltin()
	}
	hc := NewHTTPClient(cfg.PassiveTimeout)
	return &Scanner{
		cfg:   cfg,
		cdnDB: db,
		res:   dnsr.New(cfg.Resolvers, cfg.DNSTimeout, cfg.DNSRetries),
		asn:   asn.New(),
		http:  hc,
		log:   log,
	}
}

// NewHTTPClient returns the shared HTTP client used for passive lookups.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: 10,
			DialContext:         (&net.Dialer{Timeout: 12 * time.Second}).DialContext,
		},
	}
}

// Scan runs the full pipeline for one domain.
func (s *Scanner) Scan(ctx context.Context, domain string) *ScanResult {
	start := time.Now()
	r := &ScanResult{
		Domain:         domain,
		ScannedAt:      time.Now().UTC().Format(time.RFC3339),
		RevelarVersion: s.cfg.Version,
		ActiveEnabled:  s.cfg.Active,
		SourcesUsed:    map[string]string{},
	}
	hosts := util.NewStringSet()
	hosts.Add(domain)

	// 1) Current DNS of the apex.
	s.log.Step("Resolving apex DNS for %s", domain)
	r.FrontIPsV4, r.FrontIPsV6 = s.res.IPs(ctx, domain)
	r.Nameservers = s.res.NS(ctx, domain)
	r.MXHosts = s.res.MX(ctx, domain)
	txt := s.res.TXT(ctx, domain)
	spf := dnsr.ParseSPF(txt)
	r.SPFIPs, r.SPFNetworks = spf.IPs, spf.Networks
	for _, h := range spf.Hosts {
		if util.InScope(h, domain) {
			hosts.Add(h)
		}
	}

	// 2) Front-door CDN detection.
	s.detectCDN(ctx, r)
	s.log.OK("Front door: A=%d AAAA=%d | CDN=%s", len(r.FrontIPsV4), len(r.FrontIPsV6), orDash(r.CDNProvider))

	// 3) Favicon hash (used by Shodan/Censys pivots).
	fctx, fcancel := context.WithTimeout(ctx, s.cfg.PassiveTimeout)
	r.FaviconHash = favicon.Hash(fctx, s.http, s.cfg.Scheme, domain)
	fcancel()
	if r.FaviconHash != 0 {
		s.log.Info("Favicon hash: %d", r.FaviconHash)
	}

	// 4) Passive sources (concurrent).
	ipHits := s.runSources(ctx, r, hosts)

	// 5) External tools (optional).
	if s.cfg.UseTools {
		s.runTools(ctx, r, hosts)
	}

	// 6) Native brute force (optional).
	if s.cfg.Brute && len(s.cfg.Wordlist) > 0 {
		s.runBrute(ctx, r, hosts, &ipHits)
	}

	r.Subdomains = hosts.Sorted()
	s.log.OK("Collected %d subdomains", len(r.Subdomains))

	// 7) Resolve every discovered host to gather candidate IPs.
	s.resolveHosts(ctx, r, hosts, &ipHits)

	// 8) Build, enrich and filter candidates.
	s.buildCandidates(ctx, r, ipHits)
	s.log.OK("%d origin candidate IP(s) after CDN filtering", len(r.Candidates))

	// 9) Active verification (optional).
	if s.cfg.Active {
		s.verify(ctx, r)
	} else {
		s.scorePassive(r)
	}

	s.finalize(r)
	r.DurationSec = time.Since(start).Seconds()
	return r
}

func (s *Scanner) detectCDN(ctx context.Context, r *ScanResult) {
	ev := util.NewStringSet()
	provider := ""
	setp := func(p, why string) {
		if p != "" && provider == "" {
			provider = p
		}
		if why != "" {
			ev.Add(why)
		}
	}
	for _, ip := range append(append([]string{}, r.FrontIPsV4...), r.FrontIPsV6...) {
		if p := s.cdnDB.Lookup(ip); p != "" {
			setp(p, fmt.Sprintf("%s in %s range", ip, p))
		}
		for _, ptr := range s.res.PTR(ctx, ip) {
			if p := cdn.ByHostname(ptr); p != "" {
				setp(p, fmt.Sprintf("PTR %s", ptr))
			}
		}
	}
	if c := s.res.CNAME(ctx, r.Domain); c != "" {
		if p := cdn.ByHostname(c); p != "" {
			setp(p, fmt.Sprintf("CNAME %s", c))
		}
	}
	// HTTP header fingerprint.
	hctx, cancel := context.WithTimeout(ctx, s.cfg.PassiveTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(hctx, http.MethodGet, s.cfg.Scheme+"://"+r.Domain+"/", nil)
	if req != nil {
		req.Header.Set("User-Agent", s.cfg.UA)
		if resp, err := s.http.Do(req); err == nil {
			if p := cdn.ByHeaders(resp.Header); p != "" {
				setp(p, "HTTP response headers")
			}
			resp.Body.Close()
		}
	}
	r.CDNProvider = provider
	r.CDNEvidence = ev.Sorted()
}

func (s *Scanner) runSources(ctx context.Context, r *ScanResult, hosts *util.StringSet) []sources.IPHit {
	sel := sources.Select(s.cfg.SourceSpec)
	client := &sources.Client{HTTP: s.http, UA: s.cfg.UA}
	q := sources.Query{Domain: r.Domain, FaviconHash: r.FaviconHash}
	type out struct {
		name string
		res  sources.Result
		err  error
		skip bool
	}
	results := make([]out, len(sel))
	util.ParallelEach(indexes(len(sel)), s.cfg.Threads, func(i int) {
		src := sel[i]
		if src.NeedsKey() && !src.Enabled() {
			results[i] = out{name: src.Name(), skip: true}
			return
		}
		s.log.Step("source: %s", src.Name())
		c, cancel := context.WithTimeout(ctx, s.cfg.PassiveTimeout)
		defer cancel()
		res, err := src.Run(c, client, q)
		results[i] = out{name: src.Name(), res: res, err: err}
	})
	allHits := []sources.IPHit{}
	for _, o := range results {
		if o.skip {
			r.SourcesUsed[o.name] = "skipped (no API key)"
			continue
		}
		if o.err != nil {
			r.SourcesUsed[o.name] = "error: " + o.err.Error()
			s.log.Warn("%s: %v", o.name, o.err)
			continue
		}
		hosts.Add(o.res.Hosts...)
		allHits = append(allHits, o.res.IPs...)
		r.SourcesUsed[o.name] = fmt.Sprintf("ok (%d hosts, %d ips)", len(o.res.Hosts), len(o.res.IPs))
		s.log.Info("%s: %d hosts, %d ips", o.name, len(o.res.Hosts), len(o.res.IPs))
	}
	// crt.sh SANs feed CertSANs too.
	sans := []string{}
	for _, h := range hosts.Sorted() {
		sans = append(sans, h)
	}
	r.CertSANs = sans
	return allHits
}

func (s *Scanner) runTools(ctx context.Context, r *ScanResult, hosts *util.StringSet) {
	s.log.Step("external tools")
	if h, u := tools.Subfinder(ctx, r.Domain, s.cfg.ToolTimeout); true {
		hosts.Add(h...)
		r.ToolsUsed = append(r.ToolsUsed, u)
	}
	if h, u := tools.Amass(ctx, r.Domain, s.cfg.ToolTimeout); true {
		hosts.Add(h...)
		r.ToolsUsed = append(r.ToolsUsed, u)
	}
}

func (s *Scanner) runBrute(ctx context.Context, r *ScanResult, hosts *util.StringSet, hits *[]sources.IPHit) {
	s.log.Step("brute-forcing %d labels", len(s.cfg.Wordlist))
	wc := s.res.Brute(ctx, r.Domain, s.cfg.Wordlist, s.cfg.Threads, func(br dnsr.BruteResult) {
		hosts.Add(br.Host)
		for _, ip := range append(append([]string{}, br.V4...), br.V6...) {
			*hits = append(*hits, sources.IPHit{IP: ip, Host: br.Host, Source: "bruteforce"})
		}
	})
	if len(wc) > 0 {
		r.Notes = append(r.Notes, "Wildcard DNS detected; brute-force answers matching "+strings.Join(wc, ",")+" were ignored.")
	}
}

func (s *Scanner) resolveHosts(ctx context.Context, r *ScanResult, hosts *util.StringSet, hits *[]sources.IPHit) {
	s.log.Step("resolving %d hosts to IPs", hosts.Len())
	var mu sync.Mutex
	util.ParallelEach(hosts.Sorted(), s.cfg.Threads, func(h string) {
		v4, v6 := s.res.IPs(ctx, h)
		if len(v4)+len(v6) == 0 {
			return
		}
		mu.Lock()
		for _, ip := range append(append([]string{}, v4...), v6...) {
			*hits = append(*hits, sources.IPHit{IP: ip, Host: h, Source: "dns"})
		}
		mu.Unlock()
	})
}

func (s *Scanner) buildCandidates(ctx context.Context, r *ScanResult, hits []sources.IPHit) {
	type agg struct {
		srcs  *util.StringSet
		hosts *util.StringSet
		notes *util.StringSet
	}
	m := map[string]*agg{}
	frontSet := map[string]bool{}
	for _, ip := range append(append([]string{}, r.FrontIPsV4...), r.FrontIPsV6...) {
		frontSet[ip] = true
	}
	for _, ip := range r.SPFIPs {
		hits = append(hits, sources.IPHit{IP: ip, Host: r.Domain, Source: "spf"})
	}
	for _, h := range hits {
		ip := strings.TrimSpace(h.IP)
		if net.ParseIP(ip) == nil || !util.IsPublicIP(ip) {
			continue
		}
		a := m[ip]
		if a == nil {
			a = &agg{util.NewStringSet(), util.NewStringSet(), util.NewStringSet()}
			m[ip] = a
		}
		a.srcs.Add(h.Source)
		if h.Host != "" {
			a.hosts.Add(h.Host)
		}
		if h.Note != "" {
			a.notes.Add(h.Note)
		}
	}
	cands := []Candidate{}
	for ip, a := range m {
		cdnName := s.cdnDB.Lookup(ip)
		ptrs := s.res.PTR(ctx, ip)
		for _, p := range ptrs {
			if cdnName == "" {
				if hp := cdn.ByHostname(p); hp != "" {
					cdnName = hp
				}
			}
		}
		if cdnName != "" {
			continue // drop CDN-owned IPs; they are never the origin
		}
		if frontSet[ip] && r.CDNProvider != "" {
			continue // front IP that is behind the CDN
		}
		ai := s.asn.Lookup(ctx, ip)
		if ai.Org != "" {
			if p := cdn.ByHostname(strings.ToLower(ai.Org)); p != "" {
				continue // ASN belongs to a known CDN/WAF network
			}
		}
		c := Candidate{
			IP:        ip,
			IsIPv6:    util.IsIPv6(ip),
			Sources:   a.srcs.Sorted(),
			Hostnames: a.hosts.Sorted(),
			PTR:       ptrs,
			ASN:       ai.ASN,
			ASOrg:     ai.Org,
			Notes:     a.notes.Sorted(),
		}
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })
	r.Candidates = cands
}

func (s *Scanner) scorePassive(r *ScanResult) {
	for i := range r.Candidates {
		c := &r.Candidates[i]
		score := len(c.Sources) * 10
		if len(c.Hostnames) > 0 {
			score += 10
		}
		for _, src := range c.Sources {
			switch src {
			case "spf", "securitytrails", "viewdns", "shodan", "censys":
				score += 15
			}
		}
		if score > 100 {
			score = 100
		}
		c.PassiveScore = score
	}
	sort.SliceStable(r.Candidates, func(i, j int) bool {
		return r.Candidates[i].PassiveScore > r.Candidates[j].PassiveScore
	})
	if len(r.Candidates) > 0 {
		r.BestOrigin = r.Candidates[0].IP
		r.BestScore = r.Candidates[0].PassiveScore
	}
}

// defaultPorts returns ports to probe. When the user did not specify any, common
// origin ports are included (not just 80/443) because origins frequently listen on
// alternative ports that the CDN also accepts.
func (s *Scanner) defaultPorts() []int {
	if len(s.cfg.Ports) > 0 {
		return s.cfg.Ports
	}
	if s.cfg.Scheme == "http" {
		return []int{80, 8080, 8000, 8880}
	}
	return []int{443, 8443, 2053, 2083, 2087, 2096}
}

func (s *Scanner) verify(ctx context.Context, r *ScanResult) {
	if len(r.Candidates) == 0 {
		r.Notes = append(r.Notes, "Active verification requested but no candidates to probe.")
		return
	}
	s.log.Step("active verification against %d candidates", len(r.Candidates))
	p := &verify.Prober{Scheme: s.cfg.Scheme, UA: s.cfg.UA, Timeout: s.cfg.ActiveTimeout}
	bctx, cancel := context.WithTimeout(ctx, s.cfg.ActiveTimeout+5*time.Second)
	base := p.Baseline(bctx, r.Domain)
	cancel()
	r.Baseline = &base
	if base.Error != "" {
		s.log.Warn("baseline fetch failed: %s", base.Error)
	} else {
		s.log.OK("baseline: status=%d title=%q", base.StatusCode, base.Title)
	}
	ports := s.defaultPorts()
	var mu sync.Mutex
	util.ParallelEach(indexes(len(r.Candidates)), s.cfg.Threads, func(i int) {
		c := &r.Candidates[i]
		bestScore, bestNote := -1, ""
		var bestFp verify.Fingerprint
		if s.cfg.Scheme == "https" {
			for _, port := range ports {
				tctx, cancel := context.WithTimeout(ctx, s.cfg.ActiveTimeout+3*time.Second)
				covers, subj, _ := p.TLSPeek(tctx, r.Domain, c.IP, port)
				cancel()
				if covers {
					mu.Lock()
					c.Notes = append(c.Notes, fmt.Sprintf("TLS cert on :%d covers domain (CN=%s)", port, subj))
					mu.Unlock()
					break
				}
			}
		}
		for _, port := range ports {
			pctx, cancel := context.WithTimeout(ctx, s.cfg.ActiveTimeout+5*time.Second)
			fp := p.Probe(pctx, r.Domain, c.IP, port)
			cancel()
			score, note := verify.Score(base, fp)
			if score > bestScore {
				bestScore, bestNote, bestFp = score, note, fp
			}
		}
		mu.Lock()
		c.MatchScore = bestScore
		c.MatchNote = bestNote
		c.Probe = &bestFp
		c.Verified = bestScore >= s.cfg.MinScore
		mu.Unlock()
		s.log.Info("probe %s -> score %d (%s)", c.IP, bestScore, bestNote)
	})
	sort.SliceStable(r.Candidates, func(i, j int) bool {
		return r.Candidates[i].MatchScore > r.Candidates[j].MatchScore
	})
	if len(r.Candidates) > 0 && r.Candidates[0].MatchScore > 0 {
		r.BestOrigin = r.Candidates[0].IP
		r.BestScore = r.Candidates[0].MatchScore
	}
	if s.cfg.Deep {
		s.deepScan(ctx, r, base)
	}
}

func (s *Scanner) finalize(r *ScanResult) {
	if r.CDNProvider == "" {
		r.Notes = append(r.Notes, "No CDN/WAF detected on the front door; the apex IP may already be the origin.")
	}
	verified := 0
	for _, c := range r.Candidates {
		if c.Verified {
			verified++
		}
	}
	switch {
	case s.cfg.Active && verified > 0:
		r.Notes = append(r.Notes, fmt.Sprintf("%d candidate(s) actively confirmed as likely origin (score >= %d).", verified, s.cfg.MinScore))
	case len(r.Candidates) == 0:
		r.Notes = append(r.Notes, "No non-CDN candidate IPs found; target appears fully proxied.")
	case !s.cfg.Active:
		r.Notes = append(r.Notes, "Run with -active to confirm which candidate serves the real origin content.")
	}
}

func orDash(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func indexes(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}
