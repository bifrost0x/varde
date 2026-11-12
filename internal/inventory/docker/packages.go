// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bifrost0x/varde/internal/distro"
	"github.com/bifrost0x/varde/internal/inventory"
	"github.com/bifrost0x/varde/internal/pkgdb"
)

// PackageStore keeps what the package databases of images say.
type PackageStore interface {
	ImagePackagesRead(ctx context.Context) (map[string]inventory.ImagePackages, error)
	RecordImagePackages(ctx context.Context, p inventory.ImagePackages) error
}

const (
	// An image ID names immutable content; a weekly read catches packages
	// changed inside a container.
	packagesRefresh = 7 * 24 * time.Hour
	// ReaderFormat is the version of what ReadImagePackages records. Raise
	// it whenever the reader learns to read more (a field, a database, a
	// language), so records of the older reader are read again at once
	// rather than serving incomplete data for a week after an update.
	// 1: source packages and source versions, rpm databases, status.d, Go
	// build information, npm lock files.
	// 2: the Go programs in /usr/local/bin.
	// 3: Python, PHP, Ruby, .NET and Java packages; Rust programs built
	// with cargo-auditable.
	ReaderFormat  = 3
	packagesRetry = 24 * time.Hour
	// packagesPerList bounds the reads of one sync, so a host with many
	// new images is covered over a few syncs instead of one long one.
	packagesPerList = 8
)

// PackageReader reads the operating system and package databases of the
// images in use, one container per image, through the Docker archive
// endpoint. It reads the fixed files in PackageFiles and nothing else
// (ADR 0026).
type PackageReader struct {
	Store PackageStore
	// Enabled is read before every round; nil means enabled.
	Enabled func() bool
	// Changed is called after new packages were recorded.
	Changed func(ctx context.Context)
	Log     *slog.Logger
	Now     func() time.Time
}

// Read reads the images of summaries that are due, at most packagesPerList.
// Failures are recorded per image and do not fail the sync.
// workDir gives the working directory of an image's configuration.
func (r *PackageReader) Read(ctx context.Context, client *Client, summaries []ContainerSummary, config func(imageID string) ImageConfig) {
	if r == nil || r.Store == nil || (r.Enabled != nil && !r.Enabled()) {
		return
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	known, err := r.Store.ImagePackagesRead(ctx)
	if err != nil {
		r.log().Warn("image packages not loaded", "err", err)
		return
	}
	// Candidates per image, running ones first: the archive endpoint reads
	// stopped containers too, but a running one is the current state.
	sorted := append([]ContainerSummary(nil), summaries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].State == "running" && sorted[j].State != "running" })
	byImage := map[string][]ContainerSummary{}
	var images []string
	for _, s := range sorted {
		if !validID(s.ID) || !validImageID(s.ImageID) {
			continue
		}
		if _, ok := byImage[s.ImageID]; !ok {
			images = append(images, s.ImageID)
		}
		byImage[s.ImageID] = append(byImage[s.ImageID], s)
	}
	recorded, reads := 0, 0
	for _, image := range images {
		if k, ok := known[image]; ok && !due(k, now()) {
			continue
		}
		if reads == packagesPerList || ctx.Err() != nil {
			break
		}
		reads++
		var cfg ImageConfig
		if config != nil {
			cfg = config(image)
		}
		var p inventory.ImagePackages
		var err error
		if s, ok := cleanContainer(ctx, client, byImage[image], cfg); ok {
			p, err = ReadImagePackages(ctx, client, s.ID, cfg)
		} else {
			// The record stands for every container of the image, on every
			// host: it is read only from a container whose package files
			// are the image's own, so one container cannot speak for all.
			err = errChangedEverywhere
		}
		p.ImageID, p.Read, p.Format = image, now(), ReaderFormat
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.Error = err.Error()
			r.log().Info("image packages not read", "image", image[:19], "err", err)
		}
		if err := r.Store.RecordImagePackages(ctx, p); err != nil {
			r.log().Warn("image packages not recorded", "err", err)
			return
		}
		if p.Error != "" && !errors.Is(err, errChangedEverywhere) && !errors.Is(err, ErrNoPackageDatabase) {
			// A refusal (a socket proxy without archive access) applies to
			// every container; the next sync tries again.
			break
		}
		if p.Error != "" {
			continue
		}
		recorded++
	}
	if recorded > 0 && r.Changed != nil {
		r.Changed(ctx)
	}
}

// candidatesPerImage bounds the change lists asked per image.
const candidatesPerImage = 3

var errChangedEverywhere = errors.New("the package files were changed in every container checked; nothing read")

// cleanContainer returns a container of the image whose version evidence
// files are unchanged against the image, checked through its change list.
// A container whose list cannot be read does not count as clean.
func cleanContainer(ctx context.Context, client *Client, cands []ContainerSummary, cfg ImageConfig) (ContainerSummary, bool) {
	for i, s := range cands {
		if i == candidatesPerImage || ctx.Err() != nil {
			break
		}
		changes, err := client.Changes(ctx, s.ID)
		if err != nil {
			continue
		}
		if len(evidenceChanges(changes, cfg)) == 0 {
			return s, true
		}
	}
	return ContainerSummary{}, false
}

func (r *PackageReader) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

// ReadImagePackages reads the packages of one container.
func ReadImagePackages(ctx context.Context, client *Client, containerID string, cfg ImageConfig) (inventory.ImagePackages, error) {
	return ReadPackages(ctx, ContainerSource(client, containerID), cfg)
}

// ReadPackages reads os-release, the package databases, the app
// manifest and npm lock file in the image's working directory or its
// parent, and the Go build information of the program the image runs.
// Missing files are normal (distroless and scratch images have none); the
// result is then empty.
func ReadPackages(ctx context.Context, src FileSource, cfg ImageConfig) (inventory.ImagePackages, error) {
	workDir := cfg.WorkingDir
	var out inventory.ImagePackages
	var p pkgdb.Parser
	for _, f := range PackageFiles {
		b, err := src.ReadFile(ctx, f)
		if errors.Is(err, ErrNoFile) {
			continue
		}
		if err != nil {
			return inventory.ImagePackages{}, err
		}
		switch {
		case f == "/etc/os-release" || f == "/usr/lib/os-release":
			if out.Distro == "" {
				o := pkgdb.ParseOSRelease(b)
				out.Distro, out.OS = o.Distro(), o.String()
			}
		case slices.Contains(pkgdb.RPMDBFiles, f):
			// An unreadable or older-format database leaves the image
			// without rpm packages; the other files still count.
			_ = p.RPM(b)
		default:
			p.Feed(b)
		}
	}
	out.Packages = p.Packages(out.Distro)
	eco, manager, known := distro.Ecosystem(out.Distro)
	if known && manager == "dpkg" && !hasManager(out.Packages, "dpkg") {
		// Distroless images keep one file per package in status.d, without
		// a Status field: everything listed there is installed.
		files, err := src.ReadStatusDir(ctx)
		if err != nil && !errors.Is(err, ErrNoFile) {
			return inventory.ImagePackages{}, err
		}
		var sp pkgdb.Parser
		for _, b := range files {
			if !bytes.Contains(b, []byte("\nStatus: ")) && !bytes.HasPrefix(b, []byte("Status: ")) {
				// The stanza's own end: the parser resets the status at
				// each Package line.
				b = append(bytes.TrimRight(b, "\n"), []byte("\nStatus: install ok installed\n")...)
			}
			sp.Feed(b)
		}
		out.Packages = append(out.Packages, sp.Packages(out.Distro)...)
	}
	var missing error
	if known && !hasManager(out.Packages, manager) {
		// The image says which release it is but has no package database
		// Varde reads (rpm before 4.16 uses Berkeley DB or NDB): it is not
		// clean, it is unread.
		missing = fmt.Errorf("%w: %s (%s) has no %s database Varde reads", ErrNoPackageDatabase, out.OS, eco, manager)
	}
	for _, f := range manifestPaths(workDir) {
		b, err := src.ReadFile(ctx, f)
		if errors.Is(err, ErrNoFile) {
			continue
		}
		if err != nil {
			return inventory.ImagePackages{}, err
		}
		if m, ok := pkgdb.ParseNPMManifest(b); ok {
			m.Path = f
			// First: a bounded list must never lose the app's own manifest.
			out.Packages = append([]inventory.Package{m}, out.Packages...)
		}
		// The dependencies the app was installed with.
		lock := path.Join(path.Dir(f), pkgdb.LockFile)
		lb, err := src.ReadFile(ctx, lock)
		switch {
		case errors.Is(err, ErrNoFile):
		case err != nil:
			return inventory.ImagePackages{}, err
		default:
			for _, d := range pkgdb.ParseNPMLock(lb) {
				d.Path = lock
				out.Packages = append(out.Packages, d)
			}
		}
	}
	done := map[string]bool{}
	for _, f := range binaryPaths(cfg) {
		bi, err := src.ReadGoBuildInfo(ctx, f)
		if errors.Is(err, ErrNoFile) || errors.Is(err, pkgdb.ErrNotGo) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return inventory.ImagePackages{}, ctx.Err()
			}
			// A program too large or too slow to read leaves the image
			// without its Go modules, not without its packages.
			continue
		}
		for _, d := range bi.Packages {
			d.Path = f
			out.Packages = append(out.Packages, d)
		}
		done[f] = true
		break
	}
	// The other Go programs the image adds, such as gosu.
	progs, err := src.ReadGoPrograms(ctx)
	switch {
	case err == nil:
		for _, p := range progs {
			if done[p.Path] {
				continue
			}
			for _, d := range append(p.Info.Packages, p.Crates...) {
				d.Path = p.Path
				out.Packages = append(out.Packages, d)
			}
		}
	case ctx.Err() != nil:
		return inventory.ImagePackages{}, ctx.Err()
	}
	// Python, PHP, Ruby, .NET and Java packages the image's apps install.
	lang, err := src.ReadLanguagePackages(ctx, workDir)
	switch {
	case err == nil:
		out.Packages = append(out.Packages, lang.Packages...)
		out.Partial = lang.Partial
	case ctx.Err() != nil:
		return inventory.ImagePackages{}, ctx.Err()
	default:
		// Without them the image's other packages still count; the read
		// is incomplete.
		out.Packages = append(out.Packages, lang.Packages...)
		out.Partial = true
	}
	return out, missing
}

// ErrNoPackageDatabase marks an image whose release is known but whose
// package database Varde cannot read; its record says so instead of
// counting the image as clean.
var ErrNoPackageDatabase = errors.New("no readable package database")

func hasManager(pkgs []inventory.Package, manager string) bool {
	for _, p := range pkgs {
		if p.Manager == manager && p.Path == "" {
			return true
		}
	}
	return false
}

// maxBinaries bounds the programs read per image.
const maxBinaries = 4

// binaryPaths are the programs an image runs, from its entrypoint and
// command: an absolute path as given, a bare name in the usual binary
// directories. Shell scripts and shells are skipped; a wrapper such as tini
// is read and is no Go program, so the command after it is tried next.
func binaryPaths(cfg ImageConfig) []string {
	var out []string
	add := func(p string) {
		if cleanAbs(p) && !slices.Contains(out, p) && len(out) < maxBinaries {
			out = append(out, p)
		}
	}
	for _, args := range [][]string{cfg.Entrypoint, cfg.Cmd} {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			base := path.Base(a)
			if strings.HasSuffix(a, ".sh") || base == "sh" || base == "bash" || base == "ash" || base == "env" {
				break
			}
			if strings.HasPrefix(a, "/") {
				add(path.Clean(a))
			} else if !strings.ContainsAny(a, "/ $") && a != "" {
				for _, dir := range []string{"/usr/local/bin", "/usr/bin", "/bin", "/app"} {
					add(dir + "/" + a)
				}
			}
			// Only the program itself, not its arguments.
			if base != "tini" && base != "dumb-init" && base != "tini-static" {
				break
			}
		}
	}
	return out
}

// manifestPaths are the package.json files of an image's working directory
// and its parent ("/app/backend" runs code of "/app"). The root and an
// unset working directory are skipped: a manifest there belongs to no app
// in particular.
func manifestPaths(workDir string) []string {
	if workDir == "" || !path.IsAbs(workDir) {
		return nil
	}
	var out []string
	for dir := path.Clean(workDir); dir != "/" && len(out) < 2; dir = path.Dir(dir) {
		out = append(out, path.Join(dir, ManifestFile))
	}
	return out
}

// validImageID accepts "sha256:<64 hex>", the form Docker reports.
func validImageID(id string) bool {
	const prefix = "sha256:"
	if len(id) != len(prefix)+64 || id[:len(prefix)] != prefix {
		return false
	}
	for _, c := range id[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// due reports whether an image read before is read again: a week after a
// successful read, a day after a failed one, and at once when an older
// reader wrote the record.
func due(k inventory.ImagePackages, now time.Time) bool {
	if k.Format < ReaderFormat {
		return true
	}
	wait := packagesRefresh
	if k.Error != "" {
		wait = packagesRetry
	}
	return now.Sub(k.Read) >= wait
}
