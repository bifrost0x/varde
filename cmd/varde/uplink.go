// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	catalogdata "github.com/bifrost0x/varde/catalog"
	"github.com/bifrost0x/varde/internal/catalog"
	"github.com/bifrost0x/varde/internal/feed"
)

// uplinkFeed is the feed as the uplink manager uses it.
type uplinkFeed struct {
	src         *feed.Source
	local       fs.FS
	development bool
	// hasPackage: the installation reads the data package when the uplink
	// is off.
	hasPackage bool
}

func (u *uplinkFeed) VerifyLicense(doc []byte, now time.Time) (*feed.License, error) {
	return u.src.Client.VerifyLicense(doc, now)
}

func (u *uplinkFeed) Update(ctx context.Context) error {
	_, err := u.src.Client.Update(ctx)
	return err
}

func (u *uplinkFeed) LoadActive(ctx context.Context) error { return u.src.Client.LoadActive(ctx) }

// Leave returns to the built-in catalog plus local entries. With the data
// package to return to, nothing is removed: the next check installs the
// package over whatever is installed, and until then the verified data of
// the uplink stays in use rather than nothing.
func (u *uplinkFeed) Leave(ctx context.Context) error {
	if u.hasPackage {
		return nil
	}
	base, err := catalog.Load(catalogdata.FS(), u.local)
	if err != nil {
		return fmt.Errorf("load catalog: %w", err)
	}
	return u.src.Leave(ctx, base)
}

func (u *uplinkFeed) Development() bool { return u.development }
