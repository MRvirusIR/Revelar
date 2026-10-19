package sources

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/MRvirusIR/Revelar/internal/util"
)

// ---------- SecurityTrails ----------
type securitytrails struct{}

func (securitytrails) Name() string   { return "securitytrails" }
func (securitytrails) NeedsKey() bool { return true }
func (securitytrails) Enabled() bool  { return env("SECURITYTRAILS_API_KEY") != "" }
func (securitytrails) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	key := env("SECURITYTRAILS_API_KEY")
	hdr := map[string]string{"APIKEY": key}
	res := Result{}

	var sub struct {
		Subdomains []string `json:"subdomains"`
	}
	su := "https://api.securitytrails.com/v1/domain/" + url.PathEscape(q.Domain) + "/subdomains?children_only=false"
	if err := c.getJSON(ctx, su, hdr, &sub); err == nil {
		hs := []string{}
		for _, s := range sub.Subdomains {
			hs = append(hs, s+"."+q.Domain)
		}
		res.Hosts = scoped(q.Domain, hs...)
	}

	var hist struct {
		Records []struct {
			Values []struct {
				IP string `json:"ip"`
			} `json:"values"`
			FirstSeen string `json:"first_seen"`
			LastSeen  string `json:"last_seen"`
		} `json:"records"`
	}
	hu := "https://api.securitytrails.com/v1/history/" + url.PathEscape(q.Domain) + "/dns/a"
	if err := c.getJSON(ctx, hu, hdr, &hist); err == nil {
		for _, r := range hist.Records {
			for _, v := range r.Values {
				if net.ParseIP(v.IP) != nil {
					res.IPs = append(res.IPs, IPHit{IP: v.IP, Host: q.Domain, Source: "securitytrails",
						Note: "A history " + day(r.FirstSeen) + " to " + day(r.LastSeen)})
				}
			}
		}
	}
	return res, nil
}

// ---------- Shodan ----------
type shodan struct{}

func (shodan) Name() string   { return "shodan" }
func (shodan) NeedsKey() bool { return true }
func (shodan) Enabled() bool  { return env("SHODAN_API_KEY") != "" }
func (shodan) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	key := env("SHODAN_API_KEY")
	res := Result{}

	var dns struct {
		Subdomains []string `json:"subdomains"`
		Data       []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"data"`
	}
	du := "https://api.shodan.io/dns/domain/" + url.PathEscape(q.Domain) + "?key=" + url.QueryEscape(key)
	if err := c.getJSON(ctx, du, nil, &dns); err == nil {
		hs := []string{}
		for _, s := range dns.Subdomains {
			hs = append(hs, s+"."+q.Domain)
		}
		res.Hosts = scoped(q.Domain, hs...)
		for _, d := range dns.Data {
			if (d.Type == "A" || d.Type == "AAAA") && net.ParseIP(d.Value) != nil {
				res.IPs = append(res.IPs, IPHit{IP: d.Value, Host: q.Domain, Source: "shodan", Note: "DNS " + d.Type})
			}
		}
	}

	// Favicon hash pivot: find hosts serving the same favicon.
	if q.FaviconHash != 0 {
		var sr struct {
			Matches []struct {
				IPStr string `json:"ip_str"`
				Port  int    `json:"port"`
			} `json:"matches"`
		}
		query := "http.favicon.hash:" + strconv.Itoa(int(q.FaviconHash))
		su := "https://api.shodan.io/shodan/host/search?key=" + url.QueryEscape(key) + "&query=" + url.QueryEscape(query)
		if err := c.getJSON(ctx, su, nil, &sr); err == nil {
			for _, m := range sr.Matches {
				if net.ParseIP(m.IPStr) != nil {
					res.IPs = append(res.IPs, IPHit{IP: m.IPStr, Source: "shodan", Note: "favicon match :" + strconv.Itoa(m.Port)})
				}
			}
		}
	}
	return res, nil
}

// ---------- Censys ----------
type censys struct{}

func (censys) Name() string   { return "censys" }
func (censys) NeedsKey() bool { return true }
func (censys) Enabled() bool  { return env("CENSYS_API_ID") != "" && env("CENSYS_API_SECRET") != "" }
func (censys) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	id, sec := env("CENSYS_API_ID"), env("CENSYS_API_SECRET")
	auth := "Basic " + basic(id, sec)
	res := Result{}
	terms := []string{"services.tls.certificates.leaf_data.names: " + q.Domain}
	if q.FaviconHash != 0 {
		terms = append(terms, "services.http.response.favicons.md5_hash: "+q.Domain)
	}
	q5 := "services.tls.certificates.leaf_data.names:" + q.Domain + " or name:" + q.Domain
	u := "https://search.censys.io/api/v2/hosts/search?per_page=100&q=" + url.QueryEscape(q5)
	var out struct {
		Result struct {
			Hits []struct {
				IP    string   `json:"ip"`
				Names []string `json:"dns.names"`
			} `json:"hits"`
		} `json:"result"`
	}
	if err := c.getJSON(ctx, u, map[string]string{"Authorization": auth}, &out); err != nil {
		return Result{}, err
	}
	for _, h := range out.Result.Hits {
		if net.ParseIP(h.IP) != nil {
			res.IPs = append(res.IPs, IPHit{IP: h.IP, Source: "censys", Note: "cert/name match"})
		}
		res.Hosts = append(res.Hosts, scoped(q.Domain, h.Names...)...)
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

// ---------- VirusTotal ----------
type virustotal struct{}

func (virustotal) Name() string   { return "virustotal" }
func (virustotal) NeedsKey() bool { return true }
func (virustotal) Enabled() bool  { return env("VT_API_KEY") != "" }
func (virustotal) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	hdr := map[string]string{"x-apikey": env("VT_API_KEY")}
	res := Result{}
	var subs struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	su := "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(q.Domain) + "/subdomains?limit=1000"
	if err := c.getJSON(ctx, su, hdr, &subs); err == nil {
		hs := []string{}
		for _, d := range subs.Data {
			hs = append(hs, d.ID)
		}
		res.Hosts = scoped(q.Domain, hs...)
	}
	var res2 struct {
		Data []struct {
			Attributes struct {
				IPAddress string `json:"ip_address"`
				Date      int64  `json:"date"`
			} `json:"attributes"`
		} `json:"data"`
	}
	ru := "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(q.Domain) + "/resolutions?limit=100"
	if err := c.getJSON(ctx, ru, hdr, &res2); err == nil {
		for _, d := range res2.Data {
			if net.ParseIP(d.Attributes.IPAddress) != nil {
				res.IPs = append(res.IPs, IPHit{IP: d.Attributes.IPAddress, Host: q.Domain, Source: "virustotal", Note: "resolution"})
			}
		}
	}
	return res, nil
}

// ---------- ViewDNS.info IP history ----------
type viewdns struct{}

func (viewdns) Name() string   { return "viewdns" }
func (viewdns) NeedsKey() bool { return true }
func (viewdns) Enabled() bool  { return env("VIEWDNS_API_KEY") != "" }
func (viewdns) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	key := env("VIEWDNS_API_KEY")
	u := "https://api.viewdns.info/iphistory/?domain=" + url.QueryEscape(q.Domain) + "&apikey=" + url.QueryEscape(key) + "&output=json"
	var out struct {
		Response struct {
			Records []struct {
				IP       string `json:"ip"`
				LastSeen string `json:"lastseen"`
			} `json:"records"`
		} `json:"response"`
	}
	if err := c.getJSON(ctx, u, nil, &out); err != nil {
		return Result{}, err
	}
	res := Result{}
	for _, r := range out.Response.Records {
		if net.ParseIP(strings.TrimSpace(r.IP)) != nil {
			res.IPs = append(res.IPs, IPHit{IP: strings.TrimSpace(r.IP), Host: q.Domain, Source: "viewdns", Note: "IP history " + r.LastSeen})
		}
	}
	return res, nil
}
