// SPDX-License-Identifier: Apache-2.0

package pkgbuild

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The publish step replaces the branch "data" with one commit that holds
// the package and the builder's store, and touches nothing else.
func TestPublishScript(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "publish-data.sh"))
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(t.TempDir(), "remote.git")
	git(t, "", "init", "-q", "--bare", "-b", "main", remote)
	clone := filepath.Join(t.TempDir(), "clone")
	git(t, "", "clone", "-q", remote, clone)
	writeFile(t, filepath.Join(clone, "README.md"), "source\n")
	writeFile(t, filepath.Join(clone, ".gitignore"), "*.db\nwork/\n")
	git(t, clone, "add", "-A")
	git(t, clone, "commit", "-q", "-m", "source")
	git(t, clone, "push", "-q", "origin", "HEAD:main")
	mainBefore := git(t, remote, "rev-parse", "main")

	work := filepath.Join(clone, "work")
	publish := func(sequence, blob string) (string, error) {
		writeFile(t, filepath.Join(work, "feed", "v1", "manifest.json"), `{"sequence":`+sequence+`}`)
		writeFile(t, filepath.Join(work, "feed", "v1", "manifest.json.sig"), "sig")
		writeFile(t, filepath.Join(work, "feed", "v1", "root.json"), "root")
		writeFile(t, filepath.Join(work, "feed", "v1", "blobs", "sha256", blob), "blob")
		writeFile(t, filepath.Join(work, "feed", "stats.json"), "{\n  \"sequence\": "+sequence+",\n  \"advisories\": 1\n}\n")
		writeFile(t, filepath.Join(work, "feed", "stats.json.sig"), "sig")
		writeFile(t, filepath.Join(work, "cache", "builder.db"), "db "+sequence)
		writeFile(t, filepath.Join(work, "cache", "builder.db.sig"), "sig")
		writeFile(t, filepath.Join(work, "cache", "scratch.tmp"), "not to be published")
		// The list of generated entries is optional: the first build has none.
		if sequence != "100" {
			writeFile(t, filepath.Join(work, "catalog", "generated.json"), "{}\n")
			writeFile(t, filepath.Join(work, "catalog", "generated.md"), "# Generated catalog entries\n")
		}
		cmd := exec.Command("bash", script, work)
		cmd.Dir = clone
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, build := range []struct{ sequence, blob string }{{"100", "aaaa"}, {"200", "bbbb"}} {
		if out, err := publish(build.sequence, build.blob); err != nil {
			t.Fatalf("publish %s: %v\n%s", build.sequence, err, out)
		}
		if n := git(t, remote, "rev-list", "--count", "data"); n != "1" {
			t.Fatalf("branch data has %s commits after package %s, want 1", n, build.sequence)
		}
		if msg := git(t, remote, "log", "-1", "--format=%s", "data"); msg != "data: package "+build.sequence {
			t.Fatalf("commit message %q", msg)
		}
	}
	files := git(t, remote, "ls-tree", "-r", "--name-only", "data")
	want := "cache/builder.db.gz\ncache/builder.db.sig\ncatalog/generated.json\ncatalog/generated.md\nfeed/stats.json\nfeed/stats.json.sig\nfeed/v1/blobs/sha256/aaaa\nfeed/v1/blobs/sha256/bbbb\nfeed/v1/manifest.json\nfeed/v1/manifest.json.sig\nfeed/v1/root.json"
	if files != want {
		t.Fatalf("published files:\n%s\nwant:\n%s", files, want)
	}
	// The store is published compressed: advisory text quotes credentials,
	// and plain text on a branch raises secret-scanning alerts.
	unpack := exec.Command("sh", "-c", "git show data:cache/builder.db.gz | gzip -dc")
	unpack.Dir = remote
	if got, err := unpack.Output(); err != nil || string(got) != "db 200" {
		t.Fatalf("published store = %q, %v", got, err)
	}
	if after := git(t, remote, "rev-parse", "main"); after != mainBefore {
		t.Fatal("main was touched")
	}
	if status := git(t, clone, "status", "--porcelain", "--untracked-files=no"); status != "" {
		t.Fatalf("the checkout's index was changed: %s", status)
	}

	// A list that is not a plain file is not published.
	md := filepath.Join(work, "catalog", "generated.md")
	if err := os.Remove(md); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", md); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, work)
	cmd.Dir = clone
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "not a plain file") {
		t.Fatalf("symlinked list: %v\n%s", err, out)
	}
	if err := os.Remove(md); err != nil {
		t.Fatal(err)
	}

	// An incomplete build is not published, and neither is anything over main.
	if err := os.Remove(filepath.Join(work, "feed", "v1", "manifest.json.sig")); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("bash", script, work)
	cmd.Dir = clone
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "nothing published") {
		t.Fatalf("incomplete build: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(work, "feed", "v1", "manifest.json.sig"), "sig")
	cmd = exec.Command("bash", script, work)
	cmd.Dir = clone
	cmd.Env = append(os.Environ(), "PUBLISH_BRANCH=main")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "refusing to publish over main") {
		t.Fatalf("publish over main: %v\n%s", err, out)
	}
	if after := git(t, remote, "rev-parse", "main"); after != mainBefore {
		t.Fatal("main was overwritten")
	}
}

// The daily workflow stays idle until the key ceremony, runs with write
// access to the repository contents only, and uses no action beyond the
// two pinned ones the index workflow already uses and the pinned upload of
// the list of generated entries.
func TestDataWorkflow(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	text := read("data.yml")
	var wf struct {
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			If          string            `yaml:"if"`
			Environment string            `yaml:"environment"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(text), &wf); err != nil {
		t.Fatal(err)
	}
	if len(wf.Permissions) != 0 {
		t.Errorf("workflow permissions = %v, want none at the top", wf.Permissions)
	}
	job, ok := wf.Jobs["build"]
	if !ok || len(wf.Jobs) != 1 {
		t.Fatalf("jobs = %v", wf.Jobs)
	}
	if job.If != "vars.DATA_PACKAGE_ENABLED == 'true' && github.ref == 'refs/heads/main'" {
		t.Errorf("the job is not gated by DATA_PACKAGE_ENABLED and the branch main: %q", job.If)
	}
	// What comes from the published branch is checked before it is used.
	for _, want := range []string{`$1 != "100644"`, `2)`, `builder.db.sig`, `builder.db.gz`, `store_limit`} {
		if !strings.Contains(text, want) {
			t.Errorf("the workflow lacks %q", want)
		}
	}
	if job.Environment != "data-package" {
		t.Errorf("environment = %q", job.Environment)
	}
	if len(job.Permissions) != 1 || job.Permissions["contents"] != "write" {
		t.Errorf("job permissions = %v, want contents: write only", job.Permissions)
	}
	pinned := map[string]bool{"actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9": true}
	for _, m := range regexp.MustCompile(`uses: (\S+@[0-9a-f]{40})`).FindAllStringSubmatch(read("index.yml"), -1) {
		pinned[m[1]] = true
	}
	secretSteps := 0
	for _, s := range job.Steps {
		if s.Uses != "" && !pinned[s.Uses] {
			t.Errorf("action %q is not one of the pinned actions of index.yml", s.Uses)
		}
		for name := range s.Env {
			if strings.HasPrefix(name, "VARDE_DOCKERHUB_") && !strings.Contains(s.Run, "cmd/packagebuilder") {
				t.Errorf("the Docker Hub token is handed to something else than the builder: %q", s.Run)
			}
		}
		if _, ok := s.Env["VARDE_FEED_KEY"]; ok {
			secretSteps++
			if !strings.Contains(s.Run, "cmd/packagebuilder") || strings.Contains(s.Run, "VARDE_FEED_KEY") {
				t.Errorf("the key is handed to something else than the builder, or named in the script: %q", s.Run)
			}
		}
	}
	if secretSteps != 1 {
		t.Errorf("%d steps receive the feed key, want 1", secretSteps)
	}
	// The feed key and the optional read-only Docker Hub login, nothing else.
	secrets := regexp.MustCompile(`secrets\.([A-Z_]+)`).FindAllStringSubmatch(text, -1)
	if len(secrets) != 3 {
		t.Errorf("the workflow names %d secrets, want 3", len(secrets))
	}
	for _, m := range secrets {
		if m[1] != "VARDE_FEED_KEY" && m[1] != "VARDE_DOCKERHUB_USER" && m[1] != "VARDE_DOCKERHUB_TOKEN" {
			t.Errorf("the workflow names the secret %s", m[1])
		}
	}
	for _, want := range []string{"retention-days: 90", "work/catalog/generated.json", "work/catalog/generated.md"} {
		if !strings.Contains(text, want) {
			t.Errorf("the artifact step lacks %q", want)
		}
	}
}
