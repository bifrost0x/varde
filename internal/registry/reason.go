// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/bifrost0x/varde/internal/httpx"
)

// Reasons a registry gave no answer, in the words of the pages.
const (
	ReasonCredentials = "the registry asks for credentials"
	ReasonRateLimited = "the registry limits requests; Varde asks again later"
	ReasonNotFound    = "the registry does not list the image or tag"
	ReasonTimeout     = "the registry did not answer in time"
	ReasonUnreachable = "the registry could not be reached"
)

// Reason words why a registry request failed. It never treats a failure as
// an answer: every error maps to a reason, an unknown one to "could not be
// reached".
func Reason(err error) string {
	if err == nil {
		return ""
	}
	var se *httpx.StatusError
	if errors.As(err, &se) {
		switch {
		case se.RateLimited():
			return ReasonRateLimited
		case se.Status == http.StatusUnauthorized || se.Status == http.StatusForbidden:
			return ReasonCredentials
		case se.Status == http.StatusNotFound:
			return ReasonNotFound
		}
		return ReasonUnreachable
	}
	if errors.Is(err, ErrAuthentication) {
		return ReasonCredentials
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReasonTimeout
	}
	return ReasonUnreachable
}
