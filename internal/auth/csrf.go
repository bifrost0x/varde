// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// CSRF header and form field names.
const (
	CSRFHeader = "X-CSRF-Token"
	CSRFField  = "csrf"
)

// SafeMethod reports methods that must not change state.
func SafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// CheckOrigin rejects cross-site requests using Fetch Metadata and the
// Origin header. Requests from browsers always carry at least one of them on
// state-changing methods; clients without either (curl with a session
// cookie) still have to present the CSRF token.
//
// Sec-Fetch-Site is authoritative when present: browsers send Origin "null"
// on form posts under some referrer policies, so Origin is only consulted
// for clients that do not send fetch metadata.
func CheckOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}
	// Without fetch metadata (plain-HTTP origins are not secure contexts,
	// so browsers omit it) an Origin of "null" says nothing: browsers send it
	// for same-origin form posts under some referrer policies too. Such
	// requests are decided by the CSRF tokens every unsafe request carries.
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// CheckCSRF verifies the synchronizer token from the header or form field
// against the session's token.
func CheckCSRF(r *http.Request, cur *Current) bool {
	if cur == nil || cur.CSRFToken == "" {
		return false
	}
	got := r.Header.Get(CSRFHeader)
	if got == "" {
		got = r.PostFormValue(CSRFField)
	}
	return got != "" && EqualTokens(got, cur.CSRFToken)
}
