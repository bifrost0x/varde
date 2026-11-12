// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bifrost0x/varde/internal/buildinfo"
	"github.com/bifrost0x/varde/internal/coverage"
	"github.com/bifrost0x/varde/internal/integrations"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// pages are rendered with the full layout; barePages without navigation.
var (
	pages     = []string{"overview", "findings", "finding", "inventory", "coverage", "hosts", "agents", "sources", "settings", "error", "kit", "network", "connect", "system", "agentinstall", "paths", "noise", "history"}
	barePages = []string{"login", "setup"}
)

// Banner is a page-wide notice.
type Banner struct {
	Kind string // warn, info, ok, alert
	Icon string
	Text string
}

// view is the data every template receives.
type view struct {
	Title        string
	Nav          string
	Product      string
	Version      string
	AssetVersion string
	User         store.User
	CSRF         string
	Banners      []Banner
	Notice       string
	Lit          bool
	// Refresh reloads the page after this many seconds, for pages that
	// show work in progress.
	Refresh int
	// Tabs are the pages of the current area (Systems, Connections,
	// Settings), shown under the main navigation.
	Tabs []navTab
	// OwnSecurityNote is set by pages that explain an unencrypted
	// connection themselves, instead of the banner.
	OwnSecurityNote bool
	Data            any
}

// navTab is one page of an area.
type navTab struct {
	Label, Href string
	Current     bool
}

// The areas of the UI: each has a few pages, the first is its landing page.
var areaTabs = map[string][]navTab{
	"findings":    {{Label: "Findings", Href: "/findings"}, {Label: "Attack paths", Href: "/findings/paths"}, {Label: "Background noise", Href: "/findings/noise"}, {Label: "History", Href: "/findings/history"}},
	"systems":     {{Label: "Systems", Href: "/systems"}, {Label: "Apps and containers", Href: "/systems/apps"}, {Label: "Gaps", Href: "/systems/gaps"}},
	"connections": {{Label: "Network and platforms", Href: "/connections"}, {Label: "Agents", Href: "/connections/agents"}},
	"settings":    {{Label: "Settings", Href: "/settings"}, {Label: "Advisory data", Href: "/settings/sources"}},
}

// tabs returns the tabs of an area with the page at href marked current.
func tabs(area, href string) []navTab {
	src := areaTabs[area]
	out := make([]navTab, len(src))
	for i, t := range src {
		t.Current = t.Href == href
		out[i] = t
	}
	return out
}

type renderer struct {
	sets map[string]*template.Template
}

func newRenderer() (*renderer, error) {
	base, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html")
	if err != nil {
		return nil, fmt.Errorf("parse layout: %w", err)
	}
	r := &renderer{sets: map[string]*template.Template{}}
	for _, name := range append(append([]string{}, pages...), barePages...) {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(templateFS, "templates/"+name+".html"); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		r.sets[name] = t
	}
	return r, nil
}

func (r *renderer) render(w http.ResponseWriter, status int, page string, v view) {
	t, ok := r.sets[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	v.Product, v.Version, v.AssetVersion = buildinfo.Product, buildinfo.Version, assetVersion
	root := "layout"
	for _, b := range barePages {
		if b == page {
			root = "bare"
		}
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, root, v); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// assetVersion busts caches of embedded assets across releases.
var assetVersion = strings.NewReplacer("+", "-", " ", "").Replace(buildinfo.Version)

var funcs = template.FuncMap{
	"since": func(t any) string {
		tm := toTime(t)
		if tm.IsZero() {
			return "never"
		}
		d := time.Since(tm)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return plural(int(d/time.Minute), "minute") + " ago"
		case d < 48*time.Hour:
			return plural(int(d/time.Hour), "hour") + " ago"
		default:
			return plural(int(d/(24*time.Hour)), "day") + " ago"
		}
	},
	"date": func(t any) string {
		tm := toTime(t)
		if tm.IsZero() {
			return ""
		}
		return tm.Local().Format("2006-01-02 15:04")
	},
	// clock is the local time of day, for lists already grouped by day.
	"clock": func(t any) string {
		tm := toTime(t)
		if tm.IsZero() {
			return ""
		}
		return tm.Local().Format("15:04")
	},
	"plural":     plural,
	"noticeLink": noticeLink,
	"machineKind": func(kind string) string {
		switch kind {
		case "vm":
			return "VM"
		case "lxc":
			return "LXC container"
		case string(inventory.HostBareMetal):
			return "Proxmox node"
		case string(inventory.HostDocker):
			return "Docker host"
		case string(inventory.HostAppliance):
			return "Appliance"
		case string(inventory.HostLinux):
			return "Linux host"
		}
		return "Device"
	},
	"evidenceLabel": func(source string) string {
		switch source {
		case coverage.EvidenceScan:
			return "Network scan"
		case coverage.EvidenceProxmox:
			return "Proxmox VE"
		case coverage.EvidenceSSH:
			return "Docker over SSH"
		case coverage.EvidenceSSHInventory:
			return "Packages over SSH"
		case coverage.EvidenceEndpoint:
			return "Version endpoint"
		case coverage.EvidenceNodeInventory:
			return "Packages via the Proxmox node"
		case coverage.EvidenceLease:
			return "Router or DHCP"
		case coverage.EvidenceAppliance:
			return "Device API"
		case coverage.EvidenceAgent:
			return "Agent"
		case coverage.EvidenceLocal:
			return "Docker on this server"
		case coverage.EvidenceManual:
			return "Manual entry"
		}
		return source
	},
	// port shows the port of a listen address such as ":8443".
	"port": func(addr string) string {
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			return addr[i+1:]
		}
		return addr
	},
	"truncate":    truncate,
	"serviceName": func(kind string) string { return integrations.ServiceKinds[kind].Name },
	"join":        strings.Join,
	"list":        func(s ...string) []string { return s },
	"title": func(s string) string {
		if s == "" {
			return s
		}
		return strings.ToUpper(s[:1]) + s[1:]
	},
	"meterClass": func(pct int) string {
		pct = max(0, min(100, pct))
		return fmt.Sprintf("meter__fill--w%d", pct/5*5)
	},
}

func toTime(t any) time.Time {
	switch v := t.(type) {
	case time.Time:
		return v
	case *time.Time:
		if v != nil {
			return *v
		}
	}
	return time.Time{}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	if strings.HasSuffix(word, "y") && !strings.HasSuffix(word, "ay") {
		return fmt.Sprintf("%d %sies", n, word[:len(word)-1])
	}
	if strings.HasSuffix(word, "ch") {
		return fmt.Sprintf("%d %ses", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // constant path
	}
	fileServer := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r) // no directory listings
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(w, r)
	})
}
