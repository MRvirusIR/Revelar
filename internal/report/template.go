package report

const htmlTpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Revelar &middot; {{.Domain}}</title>
<style>
:root{
  --bg:#05070e;--bg2:#0a0f1d;--panel:#0d1424;--panel2:#121b30;--line:#1d2a47;
  --txt:#e9f0ff;--muted:#8695bd;--cyan:#22d3ee;--blue:#5b9dff;--green:#2ee6a6;
  --red:#ff5d7a;--amber:#ffcf4d;--violet:#a98bff;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:
  radial-gradient(900px 500px at 12% -8%,rgba(34,211,238,.10),transparent 60%),
  radial-gradient(800px 500px at 100% 0%,rgba(169,139,255,.10),transparent 55%),
  var(--bg);
  color:var(--txt);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.55}
.mono{font-family:ui-monospace,SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace}
.wrap{max-width:1120px;margin:0 auto;padding:30px 20px 70px}

/* Header */
.hero{position:relative;border:1px solid var(--line);border-radius:20px;overflow:hidden;
  background:linear-gradient(120deg,rgba(34,211,238,.08),rgba(91,157,255,.05) 40%,rgba(169,139,255,.08));
  padding:26px 26px 22px}
.hero::before{content:"";position:absolute;inset:0;background-image:
  linear-gradient(rgba(91,157,255,.05) 1px,transparent 1px),
  linear-gradient(90deg,rgba(91,157,255,.05) 1px,transparent 1px);
  background-size:26px 26px;mask:linear-gradient(180deg,#000,transparent);pointer-events:none}
.brand{display:flex;align-items:center;gap:14px;flex-wrap:wrap;position:relative}
.logo{width:46px;height:46px;flex:0 0 46px}
h1{font-size:24px;margin:0;letter-spacing:.3px}
h1 .g{background:linear-gradient(90deg,var(--cyan),var(--blue) 50%,var(--violet));-webkit-background-clip:text;background-clip:text;color:transparent}
.tag{color:var(--muted);font-size:13px;margin-top:4px;position:relative}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;position:relative}
.chip{font-size:12px;padding:4px 11px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--muted)}
.chip b{color:var(--txt)}

/* Verdict */
.verdict{margin-top:18px;display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px;position:relative;overflow:hidden}
.stat .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.stat .v{font-size:21px;font-weight:700;margin-top:6px;word-break:break-all}
.stat.flag{border-color:rgba(46,230,166,.4);box-shadow:0 0 0 1px rgba(46,230,166,.15),0 10px 30px -14px rgba(46,230,166,.5)}
.hl{background:linear-gradient(90deg,rgba(46,230,166,.22),rgba(34,211,238,.18));padding:2px 9px;border-radius:9px;color:var(--green)}

h2{font-size:14px;letter-spacing:.14em;text-transform:uppercase;color:var(--cyan);margin:30px 0 12px;
  display:flex;align-items:center;gap:10px}
h2::before{content:"";width:9px;height:9px;border-radius:2px;background:var(--cyan);box-shadow:0 0 12px var(--cyan)}

table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;font-size:13px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--panel2);color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:rgba(91,157,255,.05)}
td code{color:var(--cyan)}
pre{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:13px;overflow:auto;font-size:12px;color:var(--muted);max-height:320px}

.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:700;font-family:ui-monospace,monospace}
.s-high{background:rgba(46,230,166,.16);color:var(--green);box-shadow:0 0 0 1px rgba(46,230,166,.3)}
.s-mid{background:rgba(91,157,255,.16);color:var(--blue)}
.s-low{background:rgba(255,207,77,.16);color:var(--amber)}
.s-none{background:rgba(255,93,122,.14);color:var(--red)}
.tag2{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:1px 8px;margin:2px;font-size:11px;color:var(--muted)}
.ok{color:var(--green)} .bad{color:var(--red)} .warn{color:var(--amber)}
.sub{color:var(--muted);font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:13px;margin-top:5px;word-break:break-all}
.foot{margin-top:38px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
a{color:var(--blue)}
.bar{height:6px;border-radius:999px;background:var(--panel2);overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--cyan),var(--green))}
</style>
</head>
<body>
<div class="wrap">

<div class="hero">
  <div class="brand">
    <svg class="logo" viewBox="0 0 240 240" xmlns="http://www.w3.org/2000/svg">
      <defs><linearGradient id="lg" x1="0" y1="0" x2="240" y2="240">
        <stop stop-color="#22d3ee"/><stop offset="1" stop-color="#2ee6a6"/></linearGradient></defs>
      <path d="M120 16 C165 40 200 44 222 44 C222 120 196 196 120 232 C44 196 18 120 18 44 C40 44 75 40 120 16 Z" fill="none" stroke="url(#lg)" stroke-width="10" stroke-linejoin="round"/>
      <path d="M64 116 C86 82 154 82 176 116 C154 150 86 150 64 116 Z" fill="none" stroke="url(#lg)" stroke-width="9"/>
      <circle cx="120" cy="116" r="24" fill="url(#lg)"/>
    </svg>
    <div>
      <h1>Revelar <span class="g">Origin Report</span></h1>
      <div class="tag mono">{{.Domain}} &middot; unmask the real IP behind any CDN &middot; WAF</div>
    </div>
  </div>
  <div class="chips mono">
    <span class="chip">scanned <b>{{.ScannedAt}}</b></span>
    <span class="chip">took <b>{{printf "%.1fs" .DurationSec}}</b></span>
    {{if .RevelarVersion}}<span class="chip">engine <b>v{{.RevelarVersion}}</b></span>{{end}}
    <span class="chip">candidates <b>{{len .Candidates}}</b></span>
    <span class="chip">subdomains <b>{{len .Subdomains}}</b></span>
  </div>

  <div class="verdict">
    <div class="stat"><div class="k">Detected CDN / WAF</div><div class="v">{{orDash .CDNProvider}}</div></div>
    <div class="stat {{if .BestOrigin}}flag{{end}}"><div class="k">Best origin candidate</div><div class="v">{{if .BestOrigin}}<span class="hl mono">{{.BestOrigin}}</span>{{else}}&mdash;{{end}}</div></div>
    <div class="stat"><div class="k">Confidence</div><div class="v"><span class="pill {{scoreClass .BestScore}}">{{.BestScore}}/100</span><div class="bar"><i style="width:{{.BestScore}}%"></i></div></div></div>
    <div class="stat"><div class="k">Mode</div><div class="v">{{if .ActiveEnabled}}<span class="ok">active</span>{{else}}passive{{end}}</div></div>
  </div>
</div>

{{if .CDNEvidence}}<h2>CDN evidence</h2><p>{{range .CDNEvidence}}<span class="tag2">{{.}}</span>{{end}}</p>{{end}}

<h2>Origin candidates</h2>
{{if .Candidates}}
<table>
<tr><th>#</th><th>IP</th><th>ASN / Org</th><th>Hostnames &amp; PTR</th><th>Sources</th>{{if .ActiveEnabled}}<th>Match</th>{{end}}</tr>
{{range $i,$c := .Candidates}}
<tr>
  <td class="sub mono">{{add $i 1}}</td>
  <td><code class="mono">{{$c.IP}}</code>{{if $c.IsIPv6}} <span class="tag2">v6</span>{{end}}</td>
  <td>{{orDash $c.ASN}}<br><span class="sub">{{$c.ASOrg}}</span></td>
  <td>{{range $c.Hostnames}}<span class="tag2">{{.}}</span>{{end}}{{if $c.PTR}}<br>{{range $c.PTR}}<span class="sub mono">{{.}} </span>{{end}}{{end}}{{if $c.Notes}}<br>{{range $c.Notes}}<span class="sub ok">{{.}}</span><br>{{end}}{{end}}</td>
  <td>{{range $c.Sources}}<span class="tag2">{{.}}</span>{{end}}</td>
  {{if $.ActiveEnabled}}<td><span class="pill {{scoreClass $c.MatchScore}}">{{$c.MatchScore}}</span><br><span class="sub">{{$c.MatchNote}}</span></td>{{end}}
</tr>
{{end}}
</table>
{{else}}<p class="sub">No non-CDN candidate IPs were found.</p>{{end}}

{{if and .ActiveEnabled .Baseline}}
<h2>Active baseline</h2>
<table>
<tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Body SHA256</th></tr>
<tr><td class="mono">{{.Baseline.URL}}</td><td>{{.Baseline.StatusCode}}</td><td>{{.Baseline.Title}}</td><td>{{.Baseline.Server}}</td><td><code class="sub mono">{{.Baseline.BodySHA256}}</code></td></tr>
</table>
{{end}}

<h2>Infrastructure</h2>
<div class="cards">
  <div class="card"><div class="k">Front A (IPv4)</div><div class="v mono">{{orDash (join .FrontIPsV4)}}</div></div>
  <div class="card"><div class="k">Front AAAA (IPv6)</div><div class="v mono">{{orDash (join .FrontIPsV6)}}</div></div>
  <div class="card"><div class="k">Nameservers</div><div class="v mono">{{orDash (join .Nameservers)}}</div></div>
  <div class="card"><div class="k">MX hosts</div><div class="v mono">{{orDash (join .MXHosts)}}</div></div>
</div>

{{if or .SPFIPs .SPFNetworks}}<h2>SPF-advertised infrastructure</h2><p>{{range .SPFIPs}}<span class="tag2">{{.}}</span>{{end}}{{range .SPFNetworks}}<span class="tag2">{{.}}</span>{{end}}</p>{{end}}

<h2>Subdomains ({{len .Subdomains}})</h2>
<pre class="mono">{{range .Subdomains}}{{.}}
{{end}}</pre>

<h2>Sources used</h2>
<table>
<tr><th>Source</th><th>Result</th></tr>
{{range $k,$v := .SourcesUsed}}<tr><td class="mono">{{$k}}</td><td class="sub">{{$v}}</td></tr>{{end}}
</table>

{{if .ToolsUsed}}<h2>External tools</h2><table><tr><th>Tool</th><th>Status</th><th>Hosts</th></tr>{{range .ToolsUsed}}<tr><td>{{.Tool}}</td><td>{{.Status}}</td><td>{{.Hosts}}</td></tr>{{end}}</table>{{end}}

{{if .Notes}}<h2>Notes</h2><ul class="sub">{{range .Notes}}<li>{{.}}</li>{{end}}</ul>{{end}}

<div class="foot">
  <span>Generated by <b>Revelar</b> &middot; Origin Reveal PRO. Authorized testing only.</span>
  <span class="mono">t.me/BugCod3 &middot; t.me/RootAccessClub</span>
</div>
</div>
</body>
</html>`
