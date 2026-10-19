package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/MRvirusIR/Revelar/internal/util"
)

// ---------- Netlas.io ----------
type netlas struct{}

func (netlas) Name() string   { return "netlas" }
func (netlas) NeedsKey() bool { return true }
func (netlas) Enabled() bool  { return env("NETLAS_API_KEY") != "" }
func (netlas) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	hdr := map[string]string{"X-API-Key": env("NETLAS_API_KEY")}
	res := Result{}
	query := "domain:*." + q.Domain
	if q.FaviconHash != 0 {
		query = "(" + query + ") OR http.favicon.hash_sim:" + strconv.Itoa(int(q.FaviconHash))
	}
	u := "https://app.netlas.io/api/responses/?q=" + url.QueryEscape(query) + "&source_type=include&limit=100"
	var out struct {
		Items []struct {
			Data struct {
				IP   string `json:"ip"`
				Host string `json:"host"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := c.getJSON(ctx, u, hdr, &out); err != nil {
		return Result{}, err
	}
	for _, it := range out.Items {
		if net.ParseIP(it.Data.IP) != nil {
			res.IPs = append(res.IPs, IPHit{IP: it.Data.IP, Host: it.Data.Host, Source: "netlas"})
		}
		if h := util.NormalizeHost(it.Data.Host); util.InScope(h, q.Domain) {
			res.Hosts = append(res.Hosts, h)
		}
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

// ---------- FOFA ----------
type fofa struct{}

func (fofa) Name() string   { return "fofa" }
func (fofa) NeedsKey() bool { return true }
func (fofa) Enabled() bool  { return env("FOFA_EMAIL") != "" && env("FOFA_KEY") != "" }
func (fofa) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	rule := `domain="` + q.Domain + `"`
	if q.FaviconHash != 0 {
		rule = `(` + rule + `) || icon_hash="` + strconv.Itoa(int(q.FaviconHash)) + `"`
	}
	qb := base64.StdEncoding.EncodeToString([]byte(rule))
	u := "https://fofa.info/api/v1/search/all?email=" + url.QueryEscape(env("FOFA_EMAIL")) +
		"&key=" + url.QueryEscape(env("FOFA_KEY")) + "&qbase64=" + url.QueryEscape(qb) +
		"&fields=ip,host,domain&size=100"
	var out struct {
		Error   bool       `json:"error"`
		Errmsg  string     `json:"errmsg"`
		Results [][]string `json:"results"`
	}
	if err := c.getJSON(ctx, u, nil, &out); err != nil {
		return Result{}, err
	}
	res := Result{}
	for _, row := range out.Results {
		if len(row) == 0 {
			continue
		}
		ip := row[0]
		if i := strings.LastIndex(ip, ":"); i >= 0 && net.ParseIP(ip[:i]) != nil {
			ip = ip[:i]
		}
		if net.ParseIP(ip) != nil {
			res.IPs = append(res.IPs, IPHit{IP: ip, Source: "fofa"})
		}
		if len(row) > 1 {
			if h := util.NormalizeHost(row[1]); util.InScope(h, q.Domain) {
				res.Hosts = append(res.Hosts, h)
			}
		}
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

// ---------- ZoomEye ----------
type zoomeye struct{}

func (zoomeye) Name() string   { return "zoomeye" }
func (zoomeye) NeedsKey() bool { return true }
func (zoomeye) Enabled() bool  { return env("ZOOMEYE_API_KEY") != "" }
func (zoomeye) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	hdr := map[string]string{"API-KEY": env("ZOOMEYE_API_KEY")}
	u := "https://api.zoomeye.org/host/search?query=" + url.QueryEscape("hostname:"+q.Domain)
	var out struct {
		Matches []struct {
			IP string `json:"ip"`
		} `json:"matches"`
	}
	if err := c.getJSON(ctx, u, hdr, &out); err != nil {
		return Result{}, err
	}
	res := Result{}
	for _, m := range out.Matches {
		if net.ParseIP(m.IP) != nil {
			res.IPs = append(res.IPs, IPHit{IP: m.IP, Source: "zoomeye"})
		}
	}
	return res, nil
}

// ---------- BinaryEdge ----------
type binaryedge struct{}

func (binaryedge) Name() string   { return "binaryedge" }
func (binaryedge) NeedsKey() bool { return true }
func (binaryedge) Enabled() bool  { return env("BINARYEDGE_API_KEY") != "" }
func (binaryedge) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	hdr := map[string]string{"X-Key": env("BINARYEDGE_API_KEY")}
	u := "https://api.binaryedge.io/v2/query/domains/subdomain/" + url.PathEscape(q.Domain)
	var out struct {
		Events []string `json:"events"`
	}
	if err := c.getJSON(ctx, u, hdr, &out); err != nil {
		return Result{}, err
	}
	return Result{Hosts: scoped(q.Domain, out.Events...)}, nil
}

// ---------- Quake (360) ----------
type quake struct{}

func (quake) Name() string   { return "quake" }
func (quake) NeedsKey() bool { return true }
func (quake) Enabled() bool  { return env("QUAKE_API_KEY") != "" }
func (quake) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	hdr := map[string]string{"X-QuakeToken": env("QUAKE_API_KEY"), "Content-Type": "application/json"}
	body := `{"query":"domain:\"` + q.Domain + `\"","start":0,"size":100,"ignore_cache":true}`
	b, err := c.do(ctx, "POST", "https://quake.360.net/api/v3/search/quake_service", strings.NewReader(body), hdr)
	if err != nil {
		return Result{}, err
	}
	var out struct {
		Data []struct {
			IP      string `json:"ip"`
			Service struct {
				HTTP struct {
					Host string `json:"host"`
				} `json:"http"`
			} `json:"service"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &out) != nil {
		return Result{}, nil
	}
	res := Result{}
	for _, d := range out.Data {
		if net.ParseIP(d.IP) != nil {
			res.IPs = append(res.IPs, IPHit{IP: d.IP, Source: "quake"})
		}
		if h := util.NormalizeHost(d.Service.HTTP.Host); util.InScope(h, q.Domain) {
			res.Hosts = append(res.Hosts, h)
		}
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

// ---------- RapidDNS (free) ----------
type rapiddns struct{}

func (rapiddns) Name() string   { return "rapiddns" }
func (rapiddns) NeedsKey() bool { return false }
func (rapiddns) Enabled() bool  { return true }
func (rapiddns) Run(ctx context.Context, c *Client, q Query) (Result, error) {
	b, err := c.do(ctx, "GET", "https://rapiddns.io/subdomain/"+url.PathEscape(q.Domain)+"?full=1", nil, nil)
	if err != nil {
		return Result{}, err
	}
	res := Result{}
	// Parse the simple HTML table rows: <td>host</td><td>ip</td><td>A</td>
	text := string(b)
	for _, cell := range strings.Split(text, "<td") {
		inner := cell
		if i := strings.Index(inner, ">"); i >= 0 {
			inner = inner[i+1:]
		}
		if j := strings.Index(inner, "</td>"); j >= 0 {
			inner = inner[:j]
		}
		inner = strings.TrimSpace(stripTags(inner))
		if h := util.NormalizeHost(inner); util.InScope(h, q.Domain) && strings.Contains(inner, ".") {
			res.Hosts = append(res.Hosts, h)
		} else if net.ParseIP(inner) != nil {
			res.IPs = append(res.IPs, IPHit{IP: inner, Source: "rapiddns"})
		}
	}
	res.Hosts = util.UniqSorted(res.Hosts)
	return res, nil
}

func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
