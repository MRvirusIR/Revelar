package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MRvirusIR/Revelar/internal/cdn"
	"github.com/MRvirusIR/Revelar/internal/dnsr"
	"github.com/MRvirusIR/Revelar/internal/report"
	"github.com/MRvirusIR/Revelar/internal/scanner"
	"github.com/MRvirusIR/Revelar/internal/util"
)

func run() int {
	var (
		domain     = flag.String("d", "", "single domain to scan, e.g. example.com")
		listFile   = flag.String("f", "", "file with one domain per line")
		outDir     = flag.String("o", "results", "output directory for reports")
		scheme     = flag.String("scheme", "https", "scheme for HTTP checks (http|https)")
		ua         = flag.String("ua", "Revelar/"+version+" (+https://github.com/MRvirusIR/Revelar)", "HTTP User-Agent")
		threads    = flag.Int("threads", 40, "concurrent workers")
		srcSpec    = flag.String("sources", "all", "sources: all|free|none|comma list (crtsh,otx,shodan,...)")
		active     = flag.Bool("active", false, "actively verify candidates by probing their IPs")
		ports      = flag.String("ports", "", "comma-separated ports for active probing (default 80/443 by scheme)")
		minScore   = flag.Int("min-score", 65, "minimum match score to mark a candidate verified")
		deep       = flag.Bool("deep", false, "deep mode: with -active, probe SPF/ASN provider ranges to brute-force the origin")
		deepASN    = flag.Bool("deep-asn", false, "with -deep, also expand candidate ASNs into their announced prefixes")
		deepMax    = flag.Int("deep-max", 4096, "max IPs to probe in deep mode")
		useTools   = flag.Bool("tools", false, "also use external tools if installed (subfinder, amass)")
		brute      = flag.Bool("brute", false, "enable native subdomain brute force")
		wordlist   = flag.String("w", "", "wordlist path for brute force (falls back to built-in list)")
		noBuiltin  = flag.Bool("no-builtin-words", false, "with -brute, do not append the built-in wordlist")
		passTO     = flag.Int("timeout", 25, "per-source passive timeout (seconds)")
		actTO      = flag.Int("active-timeout", 12, "per-probe active timeout (seconds)")
		dnsTO      = flag.Int("dns-timeout", 5, "per-query DNS timeout (seconds)")
		dnsRetry   = flag.Int("dns-retries", 1, "DNS retries per query")
		refreshCDN = flag.Bool("refresh-cdn", true, "refresh CDN ranges from official feeds (cached 24h)")
		quiet      = flag.Bool("quiet", false, "suppress progress logs")
		noColor    = flag.Bool("no-color", false, "disable colored output")
		jsonOut    = flag.Bool("json", false, "print the JSON result to stdout")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	var resolvers stringList
	flag.Var(&resolvers, "resolver", "custom DNS resolver host[:port] (repeatable or comma list)")

	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("Revelar", version)
		return 0
	}
	if os.Getenv("NO_COLOR") != "" {
		*noColor = true
	}

	targets, err := collectTargets(*domain, *listFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if len(targets) == 0 {
		usage()
		return 2
	}

	if !*noColor {
		fmt.Print(cCyn + banner + cReset + "\n")
		fmt.Printf(cDim+tagline+cReset, version)
	} else {
		fmt.Println(banner)
		fmt.Printf(tagline, version)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Shared, optionally live-refreshed CDN database.
	db := cdn.NewBuiltin()
	initLog := clog{enabled: !*quiet, prefix: "[init] ", noColor: *noColor}
	if *refreshCDN {
		initLog.Step("refreshing CDN ranges from provider feeds")
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_ = db.Refresh(rctx, scanner.NewHTTPClient(time.Duration(*passTO)*time.Second))
		cancel()
	}
	initLog.OK("CDN database ready: %d ranges (%s)", db.Count(), db.Source)

	words := []string{}
	if *brute {
		if *wordlist != "" {
			w, werr := dnsr.LoadWordlist(*wordlist)
			if werr != nil {
				initLog.Warn("wordlist: %v", werr)
			}
			words = append(words, w...)
		}
		if *wordlist == "" || !*noBuiltin {
			words = append(words, dnsr.DefaultWords...)
		}
		words = util.UniqSorted(words)
	}

	cfg := scanner.Config{
		Version:        version,
		Scheme:         strings.ToLower(*scheme),
		UA:             *ua,
		Resolvers:      resolvers,
		DNSTimeout:     time.Duration(*dnsTO) * time.Second,
		DNSRetries:     *dnsRetry,
		PassiveTimeout: time.Duration(*passTO) * time.Second,
		ActiveTimeout:  time.Duration(*actTO) * time.Second,
		Threads:        *threads,
		SourceSpec:     *srcSpec,
		UseTools:       *useTools,
		ToolTimeout:    180 * time.Second,
		Active:         *active,
		Ports:          parsePorts(*ports),
		Wordlist:       words,
		Brute:          *brute,
		MinScore:       *minScore,
		RefreshCDN:     *refreshCDN,
		Deep:           *deep,
		DeepASN:        *deepASN,
		DeepMax:        *deepMax,
	}

	csvPath := *outDir + "/_summary.csv"
	exit := 0
	for _, d := range targets {
		if ctx.Err() != nil {
			break
		}
		log := clog{enabled: !*quiet, prefix: "[" + d + "] ", noColor: *noColor}
		sc := scanner.New(cfg, db, log)
		res := sc.Scan(ctx, d)
		jp, hp, serr := report.Save(*outDir, res)
		if serr != nil {
			log.Err("saving report: %v", serr)
			exit = 1
		}
		if werr := report.AppendCSV(csvPath, res); werr != nil {
			log.Warn("summary: %v", werr)
		}
		printSummary(res, *noColor)
		if !*quiet {
			fmt.Printf("  reports: %s , %s\n\n", jp, hp)
		}
		if *jsonOut {
			if b, jerr := report.JSON(res); jerr == nil {
				fmt.Println(string(b))
			}
		}
	}
	return exit
}

func collectTargets(single, listFile string) ([]string, error) {
	raw := []string{}
	if single != "" {
		raw = append(raw, single)
	}
	if listFile != "" {
		b, err := os.ReadFile(listFile)
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(string(b), "\n") {
			raw = append(raw, strings.TrimSpace(l))
		}
	}
	out := []string{}
	for _, d := range raw {
		d = util.NormalizeHost(d)
		if d == "" || strings.Count(d, ".") < 1 || strings.ContainsAny(d, " /\\") {
			if d != "" {
				fmt.Fprintf(os.Stderr, "%sskipping invalid domain:%s %s\n", cRed, cReset, d)
			}
			continue
		}
		out = append(out, d)
	}
	return util.UniqSorted(out), nil
}

func printSummary(r *scanner.ScanResult, noColor bool) {
	b, g, y, rst := cBlu, cGrn, cYel, cReset
	if noColor {
		b, g, y, rst = "", "", "", ""
	}
	cdnTxt := r.CDNProvider
	if cdnTxt == "" {
		cdnTxt = "none detected"
	}
	fmt.Printf("\n%s=== %s ===%s\n", b, r.Domain, rst)
	fmt.Printf("  CDN/WAF      : %s\n", cdnTxt)
	fmt.Printf("  Subdomains   : %d\n", len(r.Subdomains))
	fmt.Printf("  Candidates   : %d\n", len(r.Candidates))
	best := r.BestOrigin
	if best == "" {
		fmt.Printf("  %sBest origin  : none found%s\n", y, rst)
	} else {
		fmt.Printf("  %sBest origin  : %s (score %d)%s\n", g, best, r.BestScore, rst)
	}
	shown := 0
	for _, c := range r.Candidates {
		if shown >= 5 {
			fmt.Printf("  ... and %d more\n", len(r.Candidates)-shown)
			break
		}
		extra := c.ASOrg
		if r.ActiveEnabled {
			extra = fmt.Sprintf("score %d · %s", c.MatchScore, c.MatchNote)
		}
		fmt.Printf("    - %-39s %s\n", c.IP, extra)
		shown++
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Revelar %s — Origin Reveal PRO

Usage:
  Revelar -d example.com [options]
  Revelar -f domains.txt -active -brute

Core:
  -d domain           single target domain
  -f file             file with one domain per line
  -o dir              output directory (default "results")
  -json               also print JSON result to stdout
  -quiet              suppress progress logs
  -no-color           disable colored output
  -version            print version

Discovery:
  -sources spec       all|free|none|comma list (default "all")
  -tools              also run subfinder/amass if installed
  -brute              native subdomain brute force
  -w file             wordlist for -brute (built-in list used otherwise)
  -resolver host      custom DNS resolver (repeatable)
  -refresh-cdn        refresh CDN ranges from official feeds (default true)

Verification:
  -active             probe candidate IPs and score against the real site
  -ports list         ports for active probing (default 80/443 by scheme)
  -min-score n        score to mark a candidate verified (default 65)
  -deep               with -active, probe SPF/ASN ranges to brute-force the origin
  -deep-asn           with -deep, also scan the ASNs of found candidates
  -deep-max n         max IPs to probe in deep mode (default 4096)
  -scheme http|https  scheme for HTTP checks (default https)

Tuning:
  -threads n          concurrent workers (default 40)
  -timeout n          passive source timeout seconds (default 25)
  -active-timeout n   active probe timeout seconds (default 12)
  -dns-timeout n      DNS query timeout seconds (default 5)
  -dns-retries n      DNS retries (default 1)

Optional API keys (auto-enabled when set in the environment):
  SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET, SECURITYTRAILS_API_KEY,
  VT_API_KEY, VIEWDNS_API_KEY, URLSCAN_API_KEY, CERTSPOTTER_API_KEY, OTX_API_KEY

Authorized security testing only.
`, version)
}
