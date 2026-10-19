package sources

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/MRvirusIR/Revelar/internal/util"
)

func scoped(domain string, hosts ...string) []string {
	out := []string{}
	for _, h := range hosts {
		for _, l := range strings.Split(h, "\n") {
			l = util.NormalizeHost(l)
			if l != "" && util.InScope(l, domain) && !strings.Contains(l, "*") && !strings.Contains(l, "@") {
				out = append(out, l)
			}
		}
	}
	return util.UniqSorted(out)
}

func day(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// ---------- crt.sh ----------
type crtsh struct{}

func (crtsh) Name() string   { return "crtsh" }
func (crtsh) NeedsKey() bool { return false }
func (crtsh) Enabled() bool  { return true }
func (crtsh) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	var arr []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	u := "https://crt.sh/?q=" + url.QueryEscape("%."+q.Domain) + "&output=json&exclude=expired"
	if err := c.getJSON(ctx, u, nil, &arr); err != nil {
		return Result{}, err
	}
	hosts := []string{}
	for _, o := range arr {
		hosts = append(hosts, o.NameValue, o.CommonName)
	}
	return Result{Hosts: scoped(q.Domain, hosts...)}, nil
}

// ---------- CertSpotter ----------
type certspotter struct{}

func (certspotter) Name() string   { return "certspotter" }
func (certspotter) NeedsKey() bool { return false }
func (certspotter) Enabled() bool  { return true }
func (certspotter) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	var arr []struct {
		DNSNames []string `json:"dns_names"`
	}
	hdr := map[string]string{}
	if k := env("CERTSPOTTER_API_KEY"); k != "" {
		hdr["Authorization"] = "Bearer " + k
	}
	u := "https://api.certspotter.com/v1/issuances?include_subdomains=true&expand=dns_names&domain=" + url.QueryEscape(q.Domain)
	if err := c.getJSON(ctx, u, hdr, &arr); err != nil {
		return Result{}, err
	}
	hosts := []string{}
	for _, o := range arr {
		hosts = append(hosts, o.DNSNames...)
	}
	return Result{Hosts: scoped(q.Domain, hosts...)}, nil
}

// ---------- HackerTarget ----------
type hackertarget struct{}

func (hackertarget) Name() string   { return "hackertarget" }
func (hackertarget) NeedsKey() bool { return false }
func (hackertarget) Enabled() bool  { return true }
func (hackertarget) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	b, err := c.do(ctx, "GET", "https://api.hackertarget.com/hostsearch/?q="+url.QueryEscape(q.Domain), nil, nil)
	if err != nil {
		return Result{}, err
	}
	s := string(b)
	if strings.Contains(s, "API count exceeded") || strings.HasPrefix(s, "error") {
		return Result{}, fmt.Errorf("%s", strings.TrimSpace(s))
	}
	res := Result{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		p := strings.Split(sc.Text(), ",")
		if len(p) != 2 {
			continue
		}
		h := util.NormalizeHost(p[0])
		if !util.InScope(h, q.Domain) {
			continue
		}
		res.Hosts = append(res.Hosts, h)
		if net.ParseIP(p[1]) != nil {
			res.IPs = append(res.IPs, IPHit{IP: p[1], Host: h, Source: "hackertarget"})
		}
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

// ---------- AlienVault OTX passive DNS ----------
type otx struct{}

func (otx) Name() string   { return "otx" }
func (otx) NeedsKey() bool { return false }
func (otx) Enabled() bool  { return true }
func (otx) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	var out struct {
		PassiveDNS []struct {
			Address  string `json:"address"`
			Hostname string `json:"hostname"`
			First    string `json:"first"`
			Last     string `json:"last"`
		} `json:"passive_dns"`
	}
	hdr := map[string]string{}
	if k := env("OTX_API_KEY"); k != "" {
		hdr["X-OTX-API-KEY"] = k
	}
	u := "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(q.Domain) + "/passive_dns"
	if err := c.getJSON(ctx, u, hdr, &out); err != nil {
		return Result{}, err
	}
	res := Result{}
	for _, p := range out.PassiveDNS {
		h := util.NormalizeHost(p.Hostname)
		if !util.InScope(h, q.Domain) {
			continue
		}
		res.Hosts = append(res.Hosts, h)
		if net.ParseIP(p.Address) != nil {
			res.IPs = append(res.IPs, IPHit{IP: p.Address, Host: h, Source: "otx", Note: fmt.Sprintf("seen %s to %s", day(p.First), day(p.Last))})
		}
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

// ---------- urlscan.io ----------
type urlscan struct{}

func (urlscan) Name() string   { return "urlscan" }
func (urlscan) NeedsKey() bool { return false }
func (urlscan) Enabled() bool  { return true }
func (urlscan) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	var out struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
				IP     string `json:"ip"`
			} `json:"page"`
		} `json:"results"`
	}
	hdr := map[string]string{}
	if k := env("URLSCAN_API_KEY"); k != "" {
		hdr["API-Key"] = k
	}
	u := "https://urlscan.io/api/v1/search/?q=" + url.QueryEscape("page.domain:"+q.Domain) + "&size=1000"
	if err := c.getJSON(ctx, u, hdr, &out); err != nil {
		return Result{}, err
	}
	res := Result{}
	for _, r := range out.Results {
		h := util.NormalizeHost(r.Page.Domain)
		if h != "" && util.InScope(h, q.Domain) {
			res.Hosts = append(res.Hosts, h)
			if net.ParseIP(r.Page.IP) != nil {
				res.IPs = append(res.IPs, IPHit{IP: r.Page.IP, Host: h, Source: "urlscan"})
			}
		}
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

// ---------- Anubis (jonlu.ca) ----------
type anubis struct{}

func (anubis) Name() string   { return "anubis" }
func (anubis) NeedsKey() bool { return false }
func (anubis) Enabled() bool  { return true }
func (anubis) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	var arr []string
	if err := c.getJSON(ctx, "https://jldc.me/anubis/subdomains/"+url.PathEscape(q.Domain), nil, &arr); err != nil {
		return Result{}, err
	}
	return Result{Hosts: scoped(q.Domain, arr...)}, nil
}

// ---------- Wayback Machine ----------
type wayback struct{}

func (wayback) Name() string   { return "wayback" }
func (wayback) NeedsKey() bool { return false }
func (wayback) Enabled() bool  { return true }
func (wayback) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	u := "https://web.archive.org/cdx/search/cdx?url=*." + url.QueryEscape(q.Domain) +
		"/*&output=text&fl=original&collapse=urlkey&limit=50000"
	b, err := c.do(ctx, "GET", u, nil, nil)
	if err != nil {
		return Result{}, err
	}
	hosts := []string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		hosts = append(hosts, util.NormalizeHost(sc.Text()))
	}
	return Result{Hosts: scoped(q.Domain, hosts...)}, nil
}
