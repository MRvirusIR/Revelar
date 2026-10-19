// Package verify performs active origin confirmation: it fetches the real site to build
// a baseline fingerprint, then probes candidate IPs with the correct Host/SNI and scores
// how closely each response matches the origin.
package verify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Fingerprint summarizes an HTTP response for comparison.
type Fingerprint struct {
	URL          string            `json:"url,omitempty"`
	IP           string            `json:"ip,omitempty"`
	Port         int               `json:"port,omitempty"`
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title"`
	Server       string            `json:"server"`
	BodySHA256   string            `json:"body_sha256"`
	SimHash      uint64            `json:"simhash"`
	BodyLen      int               `json:"body_len"`
	CertSANsHash string            `json:"cert_sans_hash,omitempty"`
	CertSubject  string            `json:"cert_subject,omitempty"`
	CertCovers   bool              `json:"cert_covers,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	RTTms        int64             `json:"rtt_ms"`
	Error        string            `json:"error,omitempty"`
}

// Prober issues verification requests.
type Prober struct {
	Scheme  string
	UA      string
	Timeout time.Duration
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(b []byte) string {
	m := titleRe.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

// tokenShingles returns 4-gram word shingles for SimHash.
func simhash(b []byte) uint64 {
	text := strings.ToLower(string(b))
	// strip tags crudely for a content-oriented hash
	text = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]+>`).ReplaceAllString(text, " ")
	fields := strings.Fields(text)
	var vec [64]int
	add := func(tok string) {
		h := sha256.Sum256([]byte(tok))
		v := uint64(h[0]) | uint64(h[1])<<8 | uint64(h[2])<<16 | uint64(h[3])<<24 |
			uint64(h[4])<<32 | uint64(h[5])<<40 | uint64(h[6])<<48 | uint64(h[7])<<56
		for i := 0; i < 64; i++ {
			if v&(1<<uint(i)) != 0 {
				vec[i]++
			} else {
				vec[i]--
			}
		}
	}
	if len(fields) < 4 {
		for _, f := range fields {
			add(f)
		}
	} else {
		for i := 0; i+4 <= len(fields); i++ {
			add(strings.Join(fields[i:i+4], " "))
		}
	}
	var out uint64
	for i := 0; i < 64; i++ {
		if vec[i] > 0 {
			out |= 1 << uint(i)
		}
	}
	return out
}

func hamming(a, b uint64) int {
	x := a ^ b
	c := 0
	for x != 0 {
		x &= x - 1
		c++
	}
	return c
}

func (p *Prober) client(dialIP string, port int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	if dialIP != "" {
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: p.Timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(dialIP, strconv.Itoa(port)))
		}
	}
	return &http.Client{
		Timeout:   p.Timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func certHash(resp *http.Response, domain string) (sansHash, subject string, covers bool) {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", "", false
	}
	c := resp.TLS.PeerCertificates[0]
	names := append([]string{}, c.DNSNames...)
	h := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hex.EncodeToString(h[:8]), c.Subject.CommonName, certCovers(c, domain)
}

func (p *Prober) fetch(ctx context.Context, domain, ip string, port int) Fingerprint {
	fp := Fingerprint{IP: ip, Port: port}
	u := p.Scheme + "://" + domain + "/"
	if port != 0 && !((p.Scheme == "https" && port == 443) || (p.Scheme == "http" && port == 80)) {
		u = p.Scheme + "://" + domain + ":" + strconv.Itoa(port) + "/"
	}
	fp.URL = u
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		fp.Error = err.Error()
		return fp
	}
	req.Host = domain
	req.Header.Set("User-Agent", p.UA)
	start := time.Now()
	resp, err := p.client(ip, port).Do(req)
	if err != nil {
		fp.Error = err.Error()
		fp.RTTms = time.Since(start).Milliseconds()
		return fp
	}
	defer resp.Body.Close()
	fp.RTTms = time.Since(start).Milliseconds()
	fp.StatusCode = resp.StatusCode
	fp.Server = resp.Header.Get("Server")
	fp.Headers = map[string]string{}
	for _, k := range []string{"Server", "X-Powered-By", "Content-Type", "Set-Cookie", "Location"} {
		if v := resp.Header.Get(k); v != "" {
			fp.Headers[k] = v
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	fp.BodyLen = len(body)
	sum := sha256.Sum256(body)
	fp.BodySHA256 = hex.EncodeToString(sum[:])
	fp.Title = extractTitle(body)
	fp.SimHash = simhash(body)
	fp.CertSANsHash, fp.CertSubject, fp.CertCovers = certHash(resp, domain)
	return fp
}

// certCovers reports whether cert's CN or SANs match domain (incl. wildcards).
func certCovers(cert *x509.Certificate, domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	names := append([]string{cert.Subject.CommonName}, cert.DNSNames...)
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		if n == domain {
			return true
		}
		if strings.HasPrefix(n, "*.") {
			suffix := n[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) && strings.Count(domain, ".") == strings.Count(n, ".") {
				return true
			}
			if domain == n[2:] {
				return true
			}
		}
	}
	return false
}

// TLSPeek dials ip:port with SNI=domain and reports whether the presented
// certificate covers the domain. It works even when the origin refuses or
// alters HTTP responses, making it a strong standalone origin signal.
func (p *Prober) TLSPeek(ctx context.Context, domain, ip string, port int) (covers bool, subject, sansHash string) {
	d := &net.Dialer{Timeout: p.Timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false, "", ""
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(p.Timeout))
	conn := tls.Client(raw, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
	if err := conn.HandshakeContext(ctx); err != nil {
		return false, "", ""
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return false, "", ""
	}
	c := cs.PeerCertificates[0]
	h := sha256.Sum256([]byte(strings.Join(c.DNSNames, ",")))
	return certCovers(c, domain), c.Subject.CommonName, hex.EncodeToString(h[:8])
}

// Baseline fetches the site through its normal (CDN) front door.
func (p *Prober) Baseline(ctx context.Context, domain string) Fingerprint {
	fp := p.fetch(ctx, domain, "", 0)
	fp.IP = ""
	return fp
}

// Probe fetches domain forcing the connection to ip:port.
func (p *Prober) Probe(ctx context.Context, domain, ip string, port int) Fingerprint {
	return p.fetch(ctx, domain, ip, port)
}

// Score compares a probe to the baseline and returns 0..100 plus a human note.
func Score(base, probe Fingerprint) (int, string) {
	if probe.Error != "" || probe.StatusCode == 0 {
		return 0, "no response"
	}
	score := 0
	reasons := []string{}
	if probe.BodySHA256 != "" && probe.BodySHA256 == base.BodySHA256 {
		score += 60
		reasons = append(reasons, "identical body")
	} else if base.SimHash != 0 && probe.SimHash != 0 {
		d := hamming(base.SimHash, probe.SimHash)
		switch {
		case d <= 3:
			score += 45
			reasons = append(reasons, "near-identical content")
		case d <= 8:
			score += 32
			reasons = append(reasons, "very similar content")
		case d <= 14:
			score += 18
			reasons = append(reasons, "similar content")
		}
	}
	if base.CertSANsHash != "" && probe.CertSANsHash == base.CertSANsHash {
		score += 22
		reasons = append(reasons, "matching TLS certificate")
	} else if probe.CertCovers {
		score += 20
		reasons = append(reasons, "TLS cert covers domain")
	} else if probe.CertSubject != "" && base.CertSubject != "" && strings.EqualFold(probe.CertSubject, base.CertSubject) {
		score += 12
		reasons = append(reasons, "matching cert CN")
	}
	if base.StatusCode != 0 && probe.StatusCode == base.StatusCode {
		score += 10
		reasons = append(reasons, "same status")
	}
	if base.Title != "" && strings.EqualFold(base.Title, probe.Title) {
		score += 10
		reasons = append(reasons, "same title")
	}
	if base.Server != "" && probe.Server != "" && strings.EqualFold(base.Server, probe.Server) {
		score += 5
	}
	if score > 100 {
		score = 100
	}
	note := "poor match"
	switch {
	case score >= 85:
		note = "confirmed origin"
	case score >= 65:
		note = "likely origin"
	case score >= 45:
		note = "possible origin"
	case score >= 25:
		note = "weak match"
	}
	if len(reasons) > 0 {
		note += " (" + strings.Join(reasons, ", ") + ")"
	}
	return score, note
}
