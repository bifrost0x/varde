// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/advisory"
)

// AdvisoryRecord is a stored advisory for one app from one source.
type AdvisoryRecord struct {
	AppID         string
	Source        string
	Vuln          advisory.Vulnerability
	CVSS          float64
	SeverityLabel string
	FetchedAt     time.Time
}

// ReplaceAdvisories makes the stored advisories of (appID, source) equal
// to recs in one transaction.
func (s *Store) ReplaceAdvisories(ctx context.Context, appID, source string, recs []AdvisoryRecord, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM advisories WHERE app_id = ? AND source = ?`, appID, source); err != nil {
			return fmt.Errorf("clear advisories %s/%s: %w", appID, source, err)
		}
		for i := range recs {
			recs[i].AppID = appID
		}
		return insertAdvisories(ctx, tx, source, recs, now)
	})
}

// insertAdvisories inserts records under their AppID.
func insertAdvisories(ctx context.Context, tx *sql.Tx, source string, recs []AdvisoryRecord, now time.Time) error {
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO advisories (app_id, source, id, osv_json, modified, withdrawn, aliases_json, severity_cvss, severity_label, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (app_id, source, id) DO UPDATE SET osv_json = excluded.osv_json, modified = excluded.modified`)
	if err != nil {
		return fmt.Errorf("prepare advisory insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, r := range recs {
		doc, err := json.Marshal(r.Vuln)
		if err != nil {
			return fmt.Errorf("encode advisory %s: %w", r.Vuln.ID, err)
		}
		aliases, err := json.Marshal(nonNil(r.Vuln.Aliases))
		if err != nil {
			return fmt.Errorf("encode aliases %s: %w", r.Vuln.ID, err)
		}
		var withdrawn, cvss any
		if r.Vuln.Withdrawn != nil {
			withdrawn = millis(*r.Vuln.Withdrawn)
		}
		if r.CVSS > 0 {
			cvss = r.CVSS
		}
		if _, err := stmt.ExecContext(ctx, r.AppID, source, r.Vuln.ID, string(doc), millis(r.Vuln.Modified), withdrawn,
			string(aliases), cvss, r.SeverityLabel, millis(now)); err != nil {
			return fmt.Errorf("insert advisory %s: %w", r.Vuln.ID, err)
		}
	}
	return nil
}

// AdvisoryCounts returns how many advisories are stored per app and source.
// It reads no advisory text, so it is cheap for a page that only says what
// is known.
func (s *Store) AdvisoryCounts(ctx context.Context) (map[string]map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT app_id, source, COUNT(*) FROM advisories GROUP BY app_id, source`)
	if err != nil {
		return nil, fmt.Errorf("count advisories: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string]int{}
	for rows.Next() {
		var app, source string
		var n int
		if err := rows.Scan(&app, &source, &n); err != nil {
			return nil, fmt.Errorf("scan advisory count: %w", err)
		}
		if out[app] == nil {
			out[app] = map[string]int{}
		}
		out[app][source] = n
	}
	return out, rows.Err()
}

// Advisories returns all advisories stored for appID, from every source.
func (s *Store) Advisories(ctx context.Context, appID string) ([]AdvisoryRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT app_id, source, osv_json, severity_cvss, severity_label, fetched_at FROM advisories WHERE app_id = ? ORDER BY source, id`, appID)
	if err != nil {
		return nil, fmt.Errorf("query advisories: %w", err)
	}
	return scanAdvisories(rows)
}

// AdvisoriesFor returns the advisories of several apps in one read, by app
// ID: a page that compares many packages of one container reads them
// together instead of once per package.
func (s *Store) AdvisoriesFor(ctx context.Context, appIDs []string) (map[string][]AdvisoryRecord, error) {
	out := map[string][]AdvisoryRecord{}
	if len(appIDs) == 0 {
		return out, nil
	}
	ids, err := json.Marshal(appIDs)
	if err != nil {
		return nil, fmt.Errorf("encode app IDs: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT app_id, source, osv_json, severity_cvss, severity_label, fetched_at FROM advisories
		WHERE app_id IN (SELECT value FROM json_each(?)) ORDER BY app_id, source, id`, string(ids))
	if err != nil {
		return nil, fmt.Errorf("query advisories: %w", err)
	}
	recs, err := scanAdvisories(rows)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		out[r.AppID] = append(out[r.AppID], r)
	}
	return out, nil
}

// scanAdvisories reads the rows of an advisories query and closes them.
func scanAdvisories(rows *sql.Rows) ([]AdvisoryRecord, error) {
	defer func() { _ = rows.Close() }()
	var out []AdvisoryRecord
	for rows.Next() {
		var r AdvisoryRecord
		var doc string
		var cvss sql.NullFloat64
		var fetched int64
		if err := rows.Scan(&r.AppID, &r.Source, &doc, &cvss, &r.SeverityLabel, &fetched); err != nil {
			return nil, fmt.Errorf("scan advisory: %w", err)
		}
		if err := json.Unmarshal([]byte(doc), &r.Vuln); err != nil {
			return nil, fmt.Errorf("decode advisory: %w", err)
		}
		r.CVSS = cvss.Float64
		r.FetchedAt = fromMillis(fetched)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate advisories: %w", err)
	}
	return out, nil
}

// AdvisoryCVEs returns every CVE ID referenced by stored advisories.
func (s *Store) AdvisoryCVEs(ctx context.Context) ([]string, error) {
	return s.AdvisoryCVEsExcept(ctx, "")
}

// AdvisoryCVEsExcept returns every CVE ID referenced by stored advisories
// that did not come from source. With a feed in use the feed brings the
// EPSS scores of its own CVEs; only the others are asked about.
func (s *Store) AdvisoryCVEsExcept(ctx context.Context, source string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, aliases_json FROM advisories WHERE source <> ?`, source)
	if err != nil {
		return nil, fmt.Errorf("query advisory ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var id, aliases string
		if err := rows.Scan(&id, &aliases); err != nil {
			return nil, fmt.Errorf("scan advisory ids: %w", err)
		}
		var as []string
		if err := json.Unmarshal([]byte(aliases), &as); err != nil {
			return nil, fmt.Errorf("decode aliases: %w", err)
		}
		// A per-CVE distribution record (DEBIAN-CVE-2024-6387) names its
		// CVE in the ID.
		if i := strings.Index(id, "-CVE-"); i > 0 {
			as = append(as, id[i+1:])
		}
		for _, x := range append(as, id) {
			if strings.HasPrefix(x, "CVE-") && !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate advisory ids: %w", err)
	}
	return out, nil
}

// KEVEntry is one CISA KEV catalog entry.
type KEVEntry struct {
	CVE        string
	DateAdded  string
	Ransomware string
}

// ReplaceKEV replaces the KEV table.
func (s *Store) ReplaceKEV(ctx context.Context, entries []KEVEntry) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
			return fmt.Errorf("clear kev: %w", err)
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO kev (cve_id, date_added, ransomware) VALUES (?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare kev insert: %w", err)
		}
		defer func() { _ = stmt.Close() }()
		for _, e := range entries {
			if _, err := stmt.ExecContext(ctx, e.CVE, e.DateAdded, e.Ransomware); err != nil {
				return fmt.Errorf("insert kev %s: %w", e.CVE, err)
			}
		}
		return nil
	})
}

// KEV returns the set of KEV-listed CVE IDs.
func (s *Store) KEV(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve_id FROM kev`)
	if err != nil {
		return nil, fmt.Errorf("query kev: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan kev: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// EPSSEntry is one EPSS score.
type EPSSEntry struct {
	CVE        string
	Score      float64
	Percentile float64
	Date       string
}

// UpsertEPSS stores scores.
func (s *Store) UpsertEPSS(ctx context.Context, entries []EPSSEntry) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO epss (cve_id, score, percentile, date) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare epss insert: %w", err)
		}
		defer func() { _ = stmt.Close() }()
		for _, e := range entries {
			if _, err := stmt.ExecContext(ctx, e.CVE, e.Score, e.Percentile, e.Date); err != nil {
				return fmt.Errorf("insert epss %s: %w", e.CVE, err)
			}
		}
		return nil
	})
}

// KEVEntries returns the stored KEV list with its dates, sorted by CVE.
func (s *Store) KEVEntries(ctx context.Context) ([]KEVEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve_id, date_added, ransomware FROM kev ORDER BY cve_id`)
	if err != nil {
		return nil, fmt.Errorf("query kev: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []KEVEntry
	for rows.Next() {
		var e KEVEntry
		if err := rows.Scan(&e.CVE, &e.DateAdded, &e.Ransomware); err != nil {
			return nil, fmt.Errorf("scan kev: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EPSSEntries returns the stored scores with percentile and date, sorted
// by CVE.
func (s *Store) EPSSEntries(ctx context.Context) ([]EPSSEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve_id, score, percentile, date FROM epss ORDER BY cve_id`)
	if err != nil {
		return nil, fmt.Errorf("query epss: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []EPSSEntry
	for rows.Next() {
		var e EPSSEntry
		if err := rows.Scan(&e.CVE, &e.Score, &e.Percentile, &e.Date); err != nil {
			return nil, fmt.Errorf("scan epss: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EPSS returns all stored scores keyed by CVE.
func (s *Store) EPSS(ctx context.Context) (map[string]float64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve_id, score FROM epss`)
	if err != nil {
		return nil, fmt.Errorf("query epss: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]float64{}
	for rows.Next() {
		var id string
		var score float64
		if err := rows.Scan(&id, &score); err != nil {
			return nil, fmt.Errorf("scan epss: %w", err)
		}
		out[id] = score
	}
	return out, rows.Err()
}

// SourceState is the persisted refresh state of one source key (e.g. one
// GitHub repository).
type SourceState struct {
	Source       string
	Key          string
	ETag         string
	LastModified string
	LastAttempt  time.Time
	LastSuccess  time.Time
	LastError    string
	NextRun      time.Time
}

// SourceState returns the state for (source, key); the zero value if none.
func (s *Store) SourceState(ctx context.Context, source, key string) (SourceState, error) {
	st := SourceState{Source: source, Key: key}
	var attempt, success, next sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT etag, last_modified, last_attempt, last_success, last_error, next_run FROM source_state WHERE source = ? AND key = ?`,
		source, key).Scan(&st.ETag, &st.LastModified, &attempt, &success, &st.LastError, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("query source state: %w", err)
	}
	st.LastAttempt, st.LastSuccess, st.NextRun = optTime(attempt), optTime(success), optTime(next)
	return st, nil
}

// PutSourceState stores st.
func (s *Store) PutSourceState(ctx context.Context, st SourceState) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO source_state (source, key, etag, last_modified, last_attempt, last_success, last_error, next_run)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (source, key) DO UPDATE SET etag = excluded.etag, last_modified = excluded.last_modified,
			last_attempt = excluded.last_attempt, last_success = excluded.last_success,
			last_error = excluded.last_error, next_run = excluded.next_run`,
		st.Source, st.Key, st.ETag, st.LastModified, optMillis(st.LastAttempt), optMillis(st.LastSuccess), truncate(st.LastError, 1024), optMillis(st.NextRun))
	if err != nil {
		return fmt.Errorf("store source state %s/%s: %w", st.Source, st.Key, err)
	}
	return nil
}

// DeleteSourceStates forgets the refresh state of one source, for a source
// that is no longer in use.
func (s *Store) DeleteSourceStates(ctx context.Context, source string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM source_state WHERE source = ?`, source); err != nil {
		return fmt.Errorf("delete source state %s: %w", source, err)
	}
	return nil
}

// SourceStates returns every stored source state.
func (s *Store) SourceStates(ctx context.Context) ([]SourceState, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, key, etag, last_modified, last_attempt, last_success, last_error, next_run FROM source_state ORDER BY source, key`)
	if err != nil {
		return nil, fmt.Errorf("query source states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SourceState
	for rows.Next() {
		var st SourceState
		var attempt, success, next sql.NullInt64
		if err := rows.Scan(&st.Source, &st.Key, &st.ETag, &st.LastModified, &attempt, &success, &st.LastError, &next); err != nil {
			return nil, fmt.Errorf("scan source state: %w", err)
		}
		st.LastAttempt, st.LastSuccess, st.NextRun = optTime(attempt), optTime(success), optTime(next)
		out = append(out, st)
	}
	return out, rows.Err()
}

func optTime(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return fromMillis(v.Int64)
}

func optMillis(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return millis(t)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// SystemAdvisoryApps returns the app IDs of system packages with stored
// records (ADR 0032).
func (s *Store) SystemAdvisoryApps(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT app_id FROM advisories WHERE app_id LIKE 'os:%'`)
	if err != nil {
		return nil, fmt.Errorf("query system package advisories: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan system package advisory: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate system package advisories: %w", err)
	}
	return out, nil
}
