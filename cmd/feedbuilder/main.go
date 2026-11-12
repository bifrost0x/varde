// SPDX-License-Identifier: Apache-2.0

//go:build feeddev

// Command feedbuilder writes a signed feed for tests and local end-to-end
// runs. It is NOT the production pipeline: it generates development keys on
// disk and marks its roots as "development". It only builds with
// `-tags feeddev`; release builds and the container image never contain it.
//
//	go run -tags feeddev ./cmd/feedbuilder -keys ./dev-keys -out ./feed -from-db /path/varde.db
//
// With -license it also writes a development uplink license, signed with a
// license key the root lists, for trying the uplink switch of the settings.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
	"github.com/bifrost0x/varde/internal/store"
)

func main() {
	keys := flag.String("keys", "", "directory for development keys (created if missing)")
	out := flag.String("out", "", "output directory (static feed layout)")
	fromDB := flag.String("from-db", "", "Varde database (direct mode) to export advisories, KEV and EPSS from")
	catalogDir := flag.String("catalog", "", "catalog directory (default: the built-in catalog)")
	seq := flag.Int64("sequence", time.Now().Unix(), "manifest sequence")
	valid := flag.Duration("valid", 7*24*time.Hour, "manifest validity")
	license := flag.String("license", "", "write a development uplink license to this file")
	licenseDays := flag.Int("license-days", 30, "validity of the license in days")
	channel := flag.String("channel", "", "channel the feed is published on: package, uplink, or empty for VARDE_MODE=feed")
	indexFile := flag.String("index", "", "first-party index table to put into the feed (for example index/images.tsv)")
	flag.Parse()
	if err := run(*keys, *out, *fromDB, *catalogDir, *indexFile, *channel, *seq, *valid, *license, *licenseDays); err != nil {
		fmt.Fprintln(os.Stderr, "feedbuilder:", err)
		os.Exit(1)
	}
}

func run(keyDir, out, fromDB, catalogDir, indexFile, channel string, seq int64, valid time.Duration, licenseFile string, licenseDays int) error {
	if keyDir == "" || out == "" {
		return errors.New("-keys and -out are required")
	}
	rootKey, err := loadOrCreateKey(filepath.Join(keyDir, "root.key"))
	if err != nil {
		return err
	}
	feedKey, err := loadOrCreateKey(filepath.Join(keyDir, "feed.key"))
	if err != nil {
		return err
	}
	licenseKey, err := loadOrCreateKey(filepath.Join(keyDir, "license.key"))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	rootData, err := feed.SignRoot(feed.RootSpec{Version: 1, Expires: now.Add(365 * 24 * time.Hour), Environment: feed.EnvDevelopment,
		RootKeys: []ed25519.PublicKey{rootKey.Public().(ed25519.PublicKey)}, FeedKeys: []ed25519.PublicKey{feedKey.Public().(ed25519.PublicKey)},
		LicenseKeys:   []ed25519.PublicKey{licenseKey.Public().(ed25519.PublicKey)},
		RootThreshold: 1, FeedThreshold: 1}, rootKey)
	if err != nil {
		return err
	}
	if err := feed.WriteRoot(out, 1, rootData); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(keyDir, "root.json"), rootData, 0o644); err != nil { //nolint:gosec // public metadata
		return err
	}

	src := catalogdata.FS()
	if catalogDir != "" {
		src = os.DirFS(catalogDir)
	}
	entries, err := catalog.ReadEntries(src)
	if err != nil {
		return err
	}
	cat, err := catalog.Build(entries, catalog.OriginBuiltin, nil)
	if err != nil {
		return err
	}
	snap := feed.Snapshot{Channel: channel, Sequence: seq, CreatedAt: now, ExpiresAt: now.Add(valid), CatalogVersion: now.Format("2006.01.02"),
		Catalog: entries, KEV: []feed.KEVLine{}, EPSS: []feed.EPSSLine{}}
	if indexFile != "" {
		data, err := os.ReadFile(indexFile) //nolint:gosec // path given by the developer
		if err != nil {
			return err
		}
		snap.Index = data
	}
	if fromDB != "" {
		if err := export(fromDB, cat, &snap); err != nil {
			return err
		}
	}
	if _, err := feed.WriteSnapshot(out, snap, feedKey); err != nil {
		return err
	}
	fmt.Printf("feed written to %s: sequence %d, %d advisories, %d KEV, %d EPSS\ntrust root: %s\n",
		out, seq, len(snap.Advisories), len(snap.KEV), len(snap.EPSS), filepath.Join(keyDir, "root.json"))
	if licenseFile == "" {
		return nil
	}
	if licenseDays < 1 || licenseDays > 3650 {
		return errors.New("-license-days must be 1 to 3650")
	}
	id, err := licenseID()
	if err != nil {
		return err
	}
	doc, err := feed.IssueLicense(feed.License{ID: id, Plan: feed.PlanUplink, NotBefore: now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Duration(licenseDays) * 24 * time.Hour)}, licenseKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(licenseFile, append(doc, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("development license %s written to %s, valid %d days\n", id, licenseFile, licenseDays)
	return nil
}

// licenseID returns a random license ID.
func licenseID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "lic_" + hex.EncodeToString(b), nil
}

func export(path string, cat *catalog.Catalog, snap *feed.Snapshot) error {
	ctx := context.Background()
	st, err := store.Open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	for _, app := range cat.Apps() {
		recs, err := st.Advisories(ctx, app.ID)
		if err != nil {
			return err
		}
		for _, r := range recs {
			if r.Source == store.FeedSource {
				continue
			}
			snap.Advisories = append(snap.Advisories, feed.AdvisoryLine{AppID: app.ID, CVSS: r.CVSS, Severity: r.SeverityLabel, OSV: r.Vuln})
		}
	}
	kev, err := st.KEV(ctx)
	if err != nil {
		return err
	}
	for cve := range kev {
		snap.KEV = append(snap.KEV, feed.KEVLine{CVE: cve})
	}
	epss, err := st.EPSS(ctx)
	if err != nil {
		return err
	}
	for cve, score := range epss {
		snap.EPSS = append(snap.EPSS, feed.EPSSLine{CVE: cve, Score: score})
	}
	return nil
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // development key path from the command line
	if err == nil {
		b, _ := pem.Decode(data)
		if b == nil {
			return nil, fmt.Errorf("%s is not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an Ed25519 key", path)
		}
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	priv, err := feed.NewKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".key") {
		return nil, errors.New("key files end in .key")
	}
	return priv, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}
