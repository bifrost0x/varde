// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"fmt"
	"time"

	"github.com/bifrost0x/varde/internal/store"
)

// Integration health states.
const (
	// HealthOK: the last read succeeded.
	HealthOK = "ok"
	// HealthWaiting: no read finished yet, and none is overdue.
	HealthWaiting = "waiting"
	// HealthError: the last read failed, but a recent one succeeded; this
	// is shown, not notified.
	HealthError = "error"
	// HealthFailing: no successful read for three intervals, or none ever
	// with an error. Its hosts count as not reporting and a notice is
	// raised.
	HealthFailing = "failing"
	// HealthOff: switched off by the user.
	HealthOff = "off"
)

// staleAfter is how many missed intervals make an integration failing, as
// for agents (ADR 0019).
const staleAfter = 3

// IntegrationHealth is the state of one integration at now. interval is
// how often it reads; zero means unknown, and the integration then only
// fails when it never read successfully.
func IntegrationHealth(in store.Integration, now time.Time, interval time.Duration) string {
	if !in.Enabled {
		return HealthOff
	}
	ref := in.CreatedAt
	if in.LastSuccess != nil {
		ref = *in.LastSuccess
	}
	switch {
	case interval > 0 && now.Sub(ref) > staleAfter*interval:
		return HealthFailing
	case in.LastError != "" && in.LastSuccess == nil:
		// Never read successfully: a setup problem, shown at once.
		return HealthFailing
	case in.LastError != "":
		return HealthError
	case in.LastSuccess == nil:
		return HealthWaiting
	}
	return HealthOK
}

// IntegrationNotices lists the failing integrations as notices for the
// overview and the daily digest.
func IntegrationNotices(ins []store.Integration, now time.Time, interval func(kind string) time.Duration) []store.Notice {
	var out []store.Notice
	for _, in := range ins {
		var iv time.Duration
		if interval != nil {
			iv = interval(in.Kind)
		}
		if IntegrationHealth(in, now, iv) != HealthFailing {
			continue
		}
		last := "never"
		if in.LastSuccess != nil {
			last = in.LastSuccess.UTC().Format("2006-01-02 15:04 MST")
		}
		detail := fmt.Sprintf("Last successful read: %s.", last)
		if in.LastError != "" {
			detail += " Last error: " + truncateText(in.LastError, 300) + "."
		}
		detail += " Its hosts are not checked against new advisories until it reads again."
		out = append(out, store.Notice{
			Key:     store.NoticeIntegrationFailing + ":" + in.ID,
			Subject: in.ID,
			Title:   fmt.Sprintf("Integration %s is not reading", in.Name),
			Detail:  detail,
		})
	}
	return out
}

func truncateText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
