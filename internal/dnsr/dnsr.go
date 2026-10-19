// Package dnsr wraps DNS resolution with custom resolvers, retries, SPF parsing
// and a fast native subdomain brute-forcer with wildcard detection.
package dnsr

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MRvirusIR/Revelar/internal/util"
)

// Resolver resolves DNS records using system or custom upstream servers.
type Resolver struct {
	servers []string
	idx     uint32
	timeout time.Duration
	retries int
	sys     *net.Resolver
}

// New builds a Resolver. servers may be empty to use the system resolver.
func New(servers []string, timeout time.Duration, retries int) *Resolver {
	r := &Resolver{timeout: timeout, retries: retries}
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		r.servers = append(r.servers, s)
	}
	if len(r.servers) == 0 {
		r.sys = net.DefaultResolver
	}
	return r
}

func (r *Resolver) res() *net.Resolver {
	if r.sys != nil {
		return r.sys
	}
	srv := r.servers[int(atomic.AddUint32(&r.idx, 1))%len(r.servers)]
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, network, srv)
		},
	}
}

func (r *Resolver) try(ctx context.Context, fn func(context.Context, *net.Resolver) error) error {
	var err error
	for i := 0; i <= r.retries; i++ {
		c, cancel := context.WithTimeout(ctx, r.timeout)
		err = fn(c, r.res())
		cancel()
		if err == nil {
			return nil
		}
		if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}

// IPs returns A and AAAA records for host.
func (r *Resolver) IPs(ctx context.Context, host string) (v4, v6 []string) {
	var addrs []net.IPAddr
	_ = r.try(ctx, func(c context.Context, res *net.Resolver) (e error) {
		addrs, e = res.LookupIPAddr(c, host)
		return
	})
	for _, a := range addrs {
		if a.IP.To4() != nil {
			v4 = append(v4, a.IP.String())
		} else {
			v6 = append(v6, a.IP.String())
		}
	}
	return util.UniqSorted(v4), util.UniqSorted(v6)
}

// CNAME returns the canonical name chain target for host (empty if none).
func (r *Resolver) CNAME(ctx context.Context, host string) string {
	var c string
	_ = r.try(ctx, func(cx context.Context, res *net.Resolver) (e error) {
		c, e = res.LookupCNAME(cx, host)
		return
	})
	c = strings.TrimSuffix(c, ".")
	if strings.EqualFold(c, host) {
		return ""
	}
	return c
}

// MX returns MX hostnames.
func (r *Resolver) MX(ctx context.Context, host string) []string {
	var mx []*net.MX
	_ = r.try(ctx, func(c context.Context, res *net.Resolver) (e error) {
		mx, e = res.LookupMX(c, host)
		return
	})
	out := []string{}
	for _, m := range mx {
		out = append(out, strings.TrimSuffix(m.Host, "."))
	}
	return util.UniqSorted(out)
}

// NS returns nameserver hostnames.
func (r *Resolver) NS(ctx context.Context, host string) []string {
	var ns []*net.NS
	_ = r.try(ctx, func(c context.Context, res *net.Resolver) (e error) {
		ns, e = res.LookupNS(c, host)
		return
	})
	out := []string{}
	for _, n := range ns {
		out = append(out, strings.TrimSuffix(n.Host, "."))
	}
	return util.UniqSorted(out)
}

// TXT returns TXT records.
func (r *Resolver) TXT(ctx context.Context, host string) []string {
	var t []string
	_ = r.try(ctx, func(c context.Context, res *net.Resolver) (e error) {
		t, e = res.LookupTXT(c, host)
		return
	})
	return t
}

// PTR returns reverse DNS names for ip.
func (r *Resolver) PTR(ctx context.Context, ip string) []string {
	var p []string
	_ = r.try(ctx, func(c context.Context, res *net.Resolver) (e error) {
		p, e = res.LookupAddr(c, ip)
		return
	})
	for i := range p {
		p[i] = strings.TrimSuffix(p[i], ".")
	}
	return util.UniqSorted(p)
}

// SPF holds IPs and hostnames extracted from SPF records.
type SPF struct {
	IPs      []string // single addresses from ip4:/ip6:
	Networks []string // CIDR ranges (non-/32)
	Hosts    []string // a:/mx:/include: hosts
}

// ParseSPF extracts mechanisms from SPF TXT records.
func ParseSPF(txts []string) SPF {
	var s SPF
	for _, t := range txts {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			continue
		}
		for _, f := range strings.Fields(t) {
			f = strings.TrimLeft(f, "+~?-")
			lf := strings.ToLower(f)
			switch {
			case strings.HasPrefix(lf, "ip4:"), strings.HasPrefix(lf, "ip6:"):
				v := f[4:]
				if ip, n, err := net.ParseCIDR(v); err == nil {
					ones, bits := n.Mask.Size()
					if ones == bits {
						s.IPs = append(s.IPs, ip.String())
					} else {
						s.Networks = append(s.Networks, n.String())
					}
				} else if ip := net.ParseIP(v); ip != nil {
					s.IPs = append(s.IPs, ip.String())
				}
			case strings.HasPrefix(lf, "a:"), strings.HasPrefix(lf, "mx:"), strings.HasPrefix(lf, "include:"):
				h := f[strings.Index(f, ":")+1:]
				if i := strings.Index(h, "/"); i >= 0 {
					h = h[:i]
				}
				s.Hosts = append(s.Hosts, strings.ToLower(h))
			}
		}
	}
	s.IPs = util.UniqSorted(s.IPs)
	s.Networks = util.UniqSorted(s.Networks)
	s.Hosts = util.UniqSorted(s.Hosts)
	return s
}

// LoadWordlist reads non-empty, non-comment lines.
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		l := strings.ToLower(strings.TrimSpace(sc.Text()))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, strings.TrimSuffix(l, "."))
	}
	return out, sc.Err()
}

// DefaultWords is a small built-in list of labels that commonly bypass CDNs.
var DefaultWords = []string{
	"origin", "origin-www", "direct", "direct-connect", "backend", "server", "srv", "host", "real",
	"www", "www1", "www2", "web", "web1", "web2", "app", "api", "api2", "dev", "development", "stage",
	"staging", "stg", "test", "testing", "qa", "uat", "beta", "demo", "preprod", "old", "legacy",
	"new", "mail", "mail2", "smtp", "pop", "pop3", "imap", "webmail", "mx", "mx1", "mx2", "email",
	"ftp", "sftp", "ssh", "vpn", "remote", "rdp", "cpanel", "whm", "webdisk", "plesk", "panel",
	"admin", "administrator", "portal", "dashboard", "cp", "control", "manage", "ns", "ns1", "ns2",
	"dns", "dns1", "dns2", "git", "gitlab", "jenkins", "ci", "jira", "confluence", "wiki", "status",
	"monitor", "grafana", "kibana", "prometheus", "db", "mysql", "sql", "redis", "cdn", "static",
	"assets", "img", "images", "media", "files", "upload", "uploads", "download", "s3", "storage",
	"backup", "bak", "m", "mobile", "shop", "store", "blog", "forum", "support", "help", "docs",
	"secure", "login", "auth", "sso", "id", "accounts", "billing", "pay", "payment", "crm", "erp",
	"intranet", "internal", "corp", "office", "exchange", "owa", "autodiscover", "lyncdiscover",
	"cloud", "node", "node1", "node2", "edge", "lb", "proxy", "gateway", "ws", "socket", "chat",
	"video", "stream", "live", "news", "go", "my", "client", "clients", "partner", "partners",
}

func randLabel() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "rvl-" + hex.EncodeToString(b)
}

// BruteResult is one discovered host.
type BruteResult struct {
	Host string
	V4   []string
	V6   []string
}

// Brute resolves word.domain for each word concurrently, filtering wildcard answers.
func (r *Resolver) Brute(ctx context.Context, domain string, words []string, threads int, onFound func(BruteResult)) (wildcard []string) {
	wc := util.NewStringSet()
	for i := 0; i < 3; i++ {
		v4, v6 := r.IPs(ctx, randLabel()+"."+domain)
		wc.Add(v4...)
		wc.Add(v6...)
	}
	wildcard = wc.Sorted()
	seen := util.NewStringSet()
	var mu sync.Mutex
	util.ParallelEach(words, threads, func(w string) {
		if ctx.Err() != nil {
			return
		}
		host := w + "." + domain
		if seen.Add(host) == 0 {
			return
		}
		v4, v6 := r.IPs(ctx, host)
		if len(v4)+len(v6) == 0 {
			return
		}
		if wc.Len() > 0 {
			all := true
			for _, ip := range append(append([]string{}, v4...), v6...) {
				if !wc.Has(ip) {
					all = false
					break
				}
			}
			if all {
				return
			}
		}
		mu.Lock()
		onFound(BruteResult{Host: host, V4: v4, V6: v6})
		mu.Unlock()
	})
	return wildcard
}
