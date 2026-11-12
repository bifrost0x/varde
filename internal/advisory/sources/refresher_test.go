// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"log/slog"
	"testing"

	"github.com/bifrost0x/varde/internal/catalog"
)

type fakeSource struct {
	name string
	err  error
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Refresh(context.Context, []*catalog.App) (Result, error) {
	return Result{}, f.err
}

// The pages say that results still arrive until one run got through every
// source: before the first run, while one is wanted or under way, and after
// one that a source cut short.
func TestRefresherStatus(t *testing.T) {
	src := &fakeSource{name: "github"}
	r := NewRefresher(Refresher{
		Sources: []Source{src}, Log: slog.New(slog.DiscardHandler),
		Apps: func(context.Context) ([]*catalog.App, error) { return nil, nil },
	})
	if st := r.Status(); !st.CatchingUp() || st.Running || st.Wanted {
		t.Fatalf("before the first run: %+v", st)
	}
	r.Trigger()
	if st := r.Status(); !st.Wanted {
		t.Fatalf("after a trigger: %+v", st)
	}
	src.err = ErrRateLimited
	r.RunOnce(t.Context())
	if st := r.Status(); !st.CatchingUp() || !st.Limited || st.Wanted || st.Running || !st.Completed.IsZero() {
		t.Fatalf("after a run a source cut short: %+v", st)
	}
	src.err = nil
	r.RunOnce(t.Context())
	if st := r.Status(); st.CatchingUp() || st.Limited || st.Completed.IsZero() {
		t.Fatalf("after a full run: %+v", st)
	}
	// New apps make the data incomplete again until the next run.
	r.Trigger()
	if st := r.Status(); !st.CatchingUp() {
		t.Fatalf("after a trigger on complete data: %+v", st)
	}
}
