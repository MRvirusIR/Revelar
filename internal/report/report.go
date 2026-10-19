// Package report renders ScanResults to JSON, a modern self-contained HTML report,
// a CSV summary line and a colored console summary.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/MRvirusIR/Revelar/internal/scanner"
	"github.com/MRvirusIR/Revelar/internal/util"
)

// JSON marshals a result.
func JSON(r *scanner.ScanResult) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Save writes JSON + HTML for a result under outDir/<domain>/.
func Save(outDir string, r *scanner.ScanResult) (jsonPath, htmlPath string, err error) {
	dir := filepath.Join(outDir, r.Domain)
	jsonPath = filepath.Join(dir, "results.json")
	htmlPath = filepath.Join(dir, "results.html")
	jb, err := JSON(r)
	if err != nil {
		return
	}
	if err = util.WriteFile(jsonPath, jb); err != nil {
		return
	}
	hb, err := HTML(r)
	if err != nil {
		return
	}
	err = util.WriteFile(htmlPath, hb)
	return
}

// HTML renders the report template.
func HTML(r *scanner.ScanResult) ([]byte, error) {
	t, err := template.New("r").Funcs(template.FuncMap{
		"join": func(s []string) string { return strings.Join(s, ", ") },
		"add":  func(a, b int) int { return a + b },
		"orDash": func(s string) string {
			if s == "" {
				return "—"
			}
			return s
		},
		"scoreClass": func(n int) string {
			switch {
			case n >= 85:
				return "s-high"
			case n >= 65:
				return "s-mid"
			case n >= 45:
				return "s-low"
			default:
				return "s-none"
			}
		},
	}).Parse(htmlTpl)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	if err := t.Execute(&b, r); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// AppendCSV appends one summary row to path, writing a header if new.
func AppendCSV(path string, r *scanner.ScanResult) error {
	header := "domain,cdn,front_v4,front_v6,subdomains,candidates,best_origin,best_score,active,scanned_at\n"
	esc := func(s string) string {
		if strings.ContainsAny(s, ",\"\n") {
			return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
		}
		return s
	}
	line := fmt.Sprintf("%s,%s,%d,%d,%d,%d,%s,%d,%t,%s\n",
		esc(r.Domain), esc(orDash(r.CDNProvider)), len(r.FrontIPsV4), len(r.FrontIPsV6),
		len(r.Subdomains), len(r.Candidates), esc(orDash(r.BestOrigin)), r.BestScore, r.ActiveEnabled, r.ScannedAt)
	if !util.FileExists(path) {
		return util.WriteFile(path, []byte(header+line))
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
