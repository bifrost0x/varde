// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/httpx"
	"github.com/bifrost0x/varde/internal/match"
	"github.com/bifrost0x/varde/internal/store"
	"github.com/bifrost0x/varde/internal/vulndb"
)

// SourceVulnDB is the source name of the complete vulnerability datasets
// (ADR 0047): of their stored records and their state; each dataset keeps
// its state under its key.
const SourceVulnDB = match.SourceVulnDB

const (
	// vulnDBEvery is how often a dataset is checked for a newer file.
	vulnDBEvery = 24 * time.Hour
	// vulnDBRetry is the wait after a failed download.
	vulnDBRetry = time.Hour
)

// VulnDB checks every package Varde reads, of hosts and of images, against
// complete public datasets of its ecosystem (ADR 0047). The datasets are
// downloaded whole, the same files for every installation, so the requests
// reveal at most which distribution releases and package ecosystems are in
// use, never a package or a version. A dataset is checked for a newer file
// once a day; the records of the packages present are selected from the
// cache whenever the inventory changes.
type VulnDB struct {
	Deps
	// Dir holds the cache files; it is created when missing.
	Dir string
	// Packages returns the packages present, deduplicated: the system
	// packages of hosts and the packages of images.
	Packages func(ctx context.Context) ([]distro.Package, error)
	// Apps, if set, returns the distribution packages of catalog apps
	// installed on hosts, by app ID; their records are stored under it.
	Apps func(ctx context.Context) (map[string][]distro.Package, error)
	// Stored returns the app IDs with records of this source, so that
	// packages no longer present lose theirs.
	Stored func(ctx context.Context) ([]string, error)
	// URL, if set, replaces the address of a dataset (tests, mirrors).
	URL func(d vulndb.Dataset) string
	Log *slog.Logger

	mu sync.Mutex
	// stored is the signature of what was last stored: the wanted
	// packages and the cache files they were selected from.
	stored string
}

// Name implements Source.
func (*VulnDB) Name() string { return SourceVulnDB }

// Refresh implements Source. The apps argument is ignored: packages need
// no catalog entry.
func (v *VulnDB) Refresh(ctx context.Context, _ []*catalog.App) (Result, error) {
	var res Result
	if v.Packages == nil {
		return res, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	pkgs, err := v.Packages(ctx)
	if err != nil {
		return res, fmt.Errorf("vulndb packages: %w", err)
	}
	var byApp map[string][]distro.Package
	if v.Apps != nil {
		if byApp, err = v.Apps(ctx); err != nil {
			return res, fmt.Errorf("vulndb app packages: %w", err)
		}
	}
	if err := os.MkdirAll(v.Dir, 0o700); err != nil {
		return res, fmt.Errorf("vulndb directory: %w", err)
	}
	now := v.now()
	want := vulndb.Want(pkgs, byApp, now)
	byKey := map[string]vulndb.Dataset{}
	// Ecosystems whose every dataset has a cache file: only their
	// packages' stored records are replaced or removed.
	ready := map[string]bool{}
	for _, eco := range want.Ecosystems() {
		ok := true
		for _, d := range vulndb.Datasets(eco) {
			byKey[d.Key] = d
			if _, err := os.Stat(vulndb.CachePath(v.Dir, d)); err != nil {
				ok = false
			}
		}
		ready[eco] = ok
	}
	// The CVE ratings serve every dataset whose records carry no score.
	ratings := vulndb.CVEDataset()
	if want.Len() > 0 {
		byKey[ratings.Key] = ratings
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var failures []error
	for _, k := range keys {
		d := byKey[k]
		fetched, err := v.update(ctx, d, now, &res)
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if fetched {
			res.Updated++
		}
	}
	// Datasets downloaded in this run make their ecosystems ready.
	for eco := range ready {
		ok := true
		for _, d := range vulndb.Datasets(eco) {
			if _, err := os.Stat(vulndb.CachePath(v.Dir, d)); err != nil {
				ok = false
			}
		}
		ready[eco] = ok
	}
	changed, err := v.store(ctx, want, keys, byKey, ready, now)
	if err != nil {
		return res, err
	}
	if changed > 0 {
		res.Updated += changed
	}
	return res, errors.Join(failures...)
}

// update downloads a dataset when it is due, and normalises a new file
// into the cache. It reports whether the cache file changed.
func (v *VulnDB) update(ctx context.Context, d vulndb.Dataset, now time.Time, res *Result) (bool, error) {
	st, err := v.Store.SourceState(ctx, SourceVulnDB, d.Key)
	if err != nil {
		return false, err
	}
	path := vulndb.CachePath(v.Dir, d)
	_, statErr := os.Stat(path)
	have := statErr == nil
	if have && !due(st, now) {
		res.Skipped++
		return false, nil
	}
	u := d.URL
	if v.URL != nil {
		u = v.URL(d)
	}
	h := http.Header{}
	if have {
		// Validators count only while the file they belong to exists.
		if st.ETag != "" {
			h.Set("If-None-Match", st.ETag)
		}
		if st.LastModified != "" {
			h.Set("If-Modified-Since", st.LastModified)
		}
	}
	res.Requests++
	stream, err := v.HTTP.Open(ctx, httpx.Request{URL: u, Header: h})
	var se *httpx.StatusError
	switch {
	case errors.As(err, &se) && se.Status == http.StatusNotModified && have:
		res.NotModified++
		st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(vulnDBEvery)
		return false, v.Store.PutSourceState(ctx, st)
	case err != nil:
		return false, v.fail(ctx, st, now, d, err)
	}
	raw, err := v.download(stream, d)
	if err != nil {
		return false, v.fail(ctx, st, now, d, err)
	}
	defer func() { _ = os.Remove(raw) }()
	modified := now
	if t, err := http.ParseTime(stream.Header.Get("Last-Modified")); err == nil {
		modified = t.UTC()
	}
	stats, err := vulndb.Normalize(d, raw, path, modified)
	if err != nil {
		return false, v.fail(ctx, st, now, d, err)
	}
	st.ETag, st.LastModified = stream.Header.Get("ETag"), stream.Header.Get("Last-Modified")
	st.LastAttempt, st.LastSuccess, st.LastError, st.NextRun = now, now, "", now.Add(vulnDBEvery)
	if v.Log != nil {
		v.Log.Info("vulnerability dataset updated", "dataset", d.Key, "records", stats.Records, "packages", stats.Packages)
	}
	return true, v.Store.PutSourceState(ctx, st)
}

// download writes a response body to a temporary file in the cache
// directory, refusing more than the dataset's limit.
func (v *VulnDB) download(stream *httpx.Stream, d vulndb.Dataset) (string, error) {
	defer func() { _ = stream.Body.Close() }()
	f, err := os.CreateTemp(v.Dir, ".download-*")
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(stream.Body, d.MaxBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > d.MaxBytes {
		err = fmt.Errorf("larger than %d bytes", d.MaxBytes)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func (v *VulnDB) fail(ctx context.Context, st store.SourceState, now time.Time, d vulndb.Dataset, err error) error {
	err = fmt.Errorf("%s: %w", d.Title, err)
	if !isRateLimited(err) {
		st.NextRun = now.Add(vulnDBRetry)
	}
	return recordFailure(ctx, v.Store, st, now, err)
}

// store selects the records of the wanted packages from the cache files
// and replaces the stored records of every package whose ecosystem's
// datasets are all in the cache. It returns the number of packages whose
// records changed.
func (v *VulnDB) store(ctx context.Context, want *vulndb.Wanted, keys []string, byKey map[string]vulndb.Dataset,
	ready map[string]bool, now time.Time,
) (int, error) {
	sig := v.signature(want, keys, byKey)
	if sig == v.stored {
		return 0, nil
	}
	sel := map[string][]vulndb.Selected{}
	var ratings vulndb.Ratings
	for _, k := range keys {
		d := byKey[k]
		path := vulndb.CachePath(v.Dir, d)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if d.Format == vulndb.FormatUbuntuCVE {
			r, err := vulndb.LoadRatings(path)
			if err != nil {
				return 0, err
			}
			ratings = r
			continue
		}
		if err := vulndb.Select(path, want, sel); err != nil {
			return 0, err
		}
	}
	for _, rs := range sel {
		for i := range rs {
			ratings.Rate(&rs[i])
		}
	}
	vulndb.Tidy(sel)
	changed := 0
	for app, ecos := range want.Apps() {
		complete := true
		for eco := range ecos {
			complete = complete && ready[eco]
		}
		if !complete {
			// A dataset of the app is missing: its stored records stay
			// until the dataset is there.
			continue
		}
		recs := make([]store.AdvisoryRecord, 0, len(sel[app]))
		for _, s := range sel[app] {
			recs = append(recs, store.AdvisoryRecord{AppID: app, Source: SourceVulnDB, Vuln: s.Vuln, CVSS: s.CVSS, SeverityLabel: s.Severity})
		}
		same, err := v.sameStored(ctx, app, recs)
		if err != nil {
			return changed, err
		}
		if same {
			continue
		}
		if err := v.Store.ReplaceAdvisories(ctx, app, SourceVulnDB, recs, now); err != nil {
			return changed, err
		}
		changed++
	}
	// Packages no longer present lose their records.
	if v.Stored != nil {
		stored, err := v.Stored(ctx)
		if err != nil {
			return changed, err
		}
		wanted := want.Apps()
		for _, app := range stored {
			if _, ok := wanted[app]; ok {
				continue
			}
			if err := v.Store.ReplaceAdvisories(ctx, app, SourceVulnDB, nil, now); err != nil {
				return changed, err
			}
			changed++
		}
	}
	v.stored = sig
	return changed, nil
}

// sameStored reports whether the stored package records equal recs.
func (v *VulnDB) sameStored(ctx context.Context, app string, recs []store.AdvisoryRecord) (bool, error) {
	have, err := v.Store.Advisories(ctx, app)
	if err != nil {
		return false, err
	}
	var old []store.AdvisoryRecord
	for _, r := range have {
		if r.Source == SourceVulnDB {
			old = append(old, r)
		}
	}
	if len(old) != len(recs) {
		return false, nil
	}
	sort.Slice(old, func(i, j int) bool { return old[i].Vuln.ID < old[j].Vuln.ID })
	for i := range recs {
		a, err := recordJSON(old[i])
		if err != nil {
			return false, err
		}
		b, err := recordJSON(recs[i])
		if err != nil {
			return false, err
		}
		if !bytes.Equal(a, b) {
			return false, nil
		}
	}
	return true, nil
}

// recordJSON is what decides whether a stored record changed.
func recordJSON(r store.AdvisoryRecord) ([]byte, error) {
	return json.Marshal(struct {
		V advisory.Vulnerability
		C float64
		S string
	}{r.Vuln, r.CVSS, r.SeverityLabel})
}

// signature identifies the input of store: the wanted packages and the
// state of every cache file.
func (v *VulnDB) signature(want *vulndb.Wanted, keys []string, byKey map[string]vulndb.Dataset) string {
	h := sha256.New()
	apps := make([]string, 0)
	for a, ecos := range want.Apps() {
		for e := range ecos {
			apps = append(apps, a+"\x00"+e)
		}
	}
	sort.Strings(apps)
	_, _ = io.WriteString(h, strings.Join(apps, "\n"))
	for _, k := range keys {
		fi, err := os.Stat(vulndb.CachePath(v.Dir, byKey[k]))
		if err != nil {
			_, _ = fmt.Fprintf(h, "\n%s:missing", k)
			continue
		}
		_, _ = fmt.Fprintf(h, "\n%s:%d:%d", k, fi.Size(), fi.ModTime().UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VulnDBCovered reports whether every dataset of an ecosystem has a cache
// file in dir: its packages are checked without asking anyone.
func VulnDBCovered(dir, ecosystem string) bool {
	ds := vulndb.Datasets(ecosystem)
	if len(ds) == 0 {
		return false
	}
	for _, d := range ds {
		if _, err := os.Stat(vulndb.CachePath(filepath.Clean(dir), d)); err != nil {
			return false
		}
	}
	return true
}
