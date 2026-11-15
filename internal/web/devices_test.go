// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/varde/internal/discovery"
	"github.com/bifrost0x/varde/internal/inventory"
)

// deviceHarness signs in, allows 192.168.1.0/24 and stores the device.
func deviceHarness(t *testing.T, d discovery.Device) *harness {
	t.Helper()
	h, _ := deviceHarnessCSRF(t, d)
	return h
}

func deviceHarnessCSRF(t *testing.T, d discovery.Device) (*harness, string) {
	t.Helper()
	h := newHarness(t, withNetwork(t))
	csrf := h.signIn(t)
	if resp, _ := h.do(t, "POST", "/connections/scope", url.Values{"csrf": {csrf}, "networks": {"192.168.1.0/24"}}, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save scope: %d", resp.StatusCode)
	}
	if err := h.store.RecordDevices(t.Context(), []discovery.Device{d}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	return h, csrf
}

func stated(name, value string) discovery.Field {
	return discovery.Field{Name: name, Value: value, Trust: discovery.TrustStated}
}

func TestSystemPageShowsStatedFields(t *testing.T) {
	h := deviceHarness(t, discovery.Device{Address: "192.168.1.20", Kind: discovery.KindNAS, Label: "NAS", Services: []discovery.Service{{Port: 49000, Proto: discovery.ProtoHTTP,
		Fields: []discovery.Field{stated(discovery.FieldManufacturer, "UGREEN"), stated(discovery.FieldModel, "DXP4800"), stated(discovery.FieldFirmware, "1.2.3"),
			stated(discovery.FieldDisplayName, "Living room NAS")}}}})
	resp, body := h.do(t, "GET", "/systems/device:192.168.1.20", nil, nil)
	body = html.UnescapeString(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"What the device states", "UGREEN", "DXP4800", "firmware", "Names (not used to identify it)", "Living room NAS",
		"Its identity follows its address.", "Varde sends nothing by itself"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "Help recognise") {
		t.Error("help offered for a device at firmware level")
	}
}

func TestSystemPageUnknownDeviceOffersHelp(t *testing.T) {
	h := deviceHarness(t, discovery.Device{Address: "192.168.1.30", Hostname: "widgetbox", Kind: discovery.KindOther, Services: []discovery.Service{{Port: 80, Proto: discovery.ProtoHTTP,
		Fields: []discovery.Field{stated(discovery.FieldHTTPTitle, "Acme admin")}}}})
	_, body := h.do(t, "GET", "/systems/device:192.168.1.30", nil, nil)
	body = html.UnescapeString(body)
	for _, want := range []string{"Help recognise this device", "/issues/new?", "template=device.yml", `target="_blank" rel="noopener"`,
		"Download its evidence", "/systems/device:192.168.1.30/evidence.json"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	m := regexp.MustCompile(`href="([^"]*issues/new\?[^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no issue link")
	}
	u, err := url.Parse(m[1])
	if err != nil {
		t.Fatal(err)
	}
	full := strings.ToLower(u.String() + " " + u.RawQuery + " " + u.Query().Encode())
	for k, vs := range u.Query() {
		full += " " + strings.ToLower(k+" "+strings.Join(vs, " "))
	}
	for _, leak := range []string{"192.168.1.30", "widgetbox"} {
		if strings.Contains(full, leak) {
			t.Errorf("issue link carries %q", leak)
		}
	}
}

func TestEvidenceDownload(t *testing.T) {
	h := deviceHarness(t, discovery.Device{Address: "192.168.1.30", Hostname: "widgetbox", Kind: discovery.KindOther, Services: []discovery.Service{{Port: 80, Proto: discovery.ProtoHTTP,
		Fields: []discovery.Field{stated(discovery.FieldHTTPTitle, "Acme admin"), stated(discovery.FieldSerial, "SN123456")}}}})
	resp, body := h.do(t, "GET", "/systems/device:192.168.1.30/evidence.json", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Disposition"); got != `attachment; filename="device-evidence.json"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q", got)
	}
	if !strings.Contains(body, "Acme admin") {
		t.Errorf("bundle lacks the title: %s", body)
	}
	for _, leak := range []string{"192.168.1.30", "widgetbox", "SN123456"} {
		if strings.Contains(body, leak) {
			t.Errorf("bundle leaks %q", leak)
		}
	}
	if resp, _ := h.do(t, "GET", "/systems/device:192.168.1.99/evidence.json", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown machine: %d", resp.StatusCode)
	}
}

func TestEvidenceNeedsSignIn(t *testing.T) {
	h, csrf := deviceHarnessCSRF(t, discovery.Device{Address: "192.168.1.30", Kind: discovery.KindOther, Services: []discovery.Service{{Port: 80, Proto: discovery.ProtoHTTP,
		Fields: []discovery.Field{stated(discovery.FieldHTTPTitle, "Acme admin")}}}})
	h.do(t, "POST", "/logout", url.Values{"csrf": {csrf}}, nil)
	resp, body := h.do(t, "GET", "/systems/device:192.168.1.30/evidence.json", nil, nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Errorf("anonymous request answered %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if strings.Contains(body, "Acme admin") || strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Error("anonymous request got the bundle")
	}
}

func TestOldDeviceRendersAsBefore(t *testing.T) {
	h := deviceHarness(t, discovery.Device{Address: "192.168.1.40", Kind: discovery.KindNAS, Label: "Synology DSM", Services: []discovery.Service{{Port: 5000, Proto: discovery.ProtoHTTP, Product: "Synology DSM"}}})
	resp, body := h.do(t, "GET", "/systems/device:192.168.1.40", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "What the device states") || !strings.Contains(body, ">class<") {
		t.Errorf("old device page:\n%s", body)
	}
}

func TestSystemsListShowsLevel(t *testing.T) {
	h := newHarness(t)
	h.signIn(t)
	addFinding(t, h, "c1", "P1")
	_, body := h.do(t, "GET", "/systems", nil, nil)
	if row := rowOf(t, body, "nas"); !strings.Contains(row, ">software<") {
		t.Errorf("row lacks the level: %s", row)
	}
}

func TestPanelShowsMachineLevel(t *testing.T) {
	h := deviceHarness(t, discovery.Device{Address: "192.168.1.50", Kind: discovery.KindOther, Services: []discovery.Service{{Port: 80, Proto: discovery.ProtoHTTP,
		Fields: []discovery.Field{stated(discovery.FieldHTTPTitle, "Acme admin")}}}})
	if err := h.store.UpsertHost(t.Context(), inventory.Host{ID: "agent-9", Name: "box", Kind: inventory.HostDocker, Source: inventory.SourceAgent,
		Addresses: []string{"192.168.1.50"}, LastContact: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_, list := h.do(t, "GET", "/systems", nil, nil)
	m := regexp.MustCompile(`href="(/systems/[^"]+)">box</a>`).FindStringSubmatch(list)
	if m == nil {
		t.Fatal("host not listed")
	}
	_, body := h.do(t, "GET", m[1], nil, nil)
	if !strings.Contains(body, "What the device states") || !strings.Contains(body, ">software<") || !strings.Contains(body, "Acme admin") {
		t.Errorf("panel: %s", body)
	}
	if strings.Contains(body, "Help recognise this device") {
		t.Error("help offered for a machine at software level")
	}
}

// The panel shows the bundle before anything is sent, byte for byte what
// the download and the issue link carry, and never the raw fields.
func TestSystemPageShowsTheEvidence(t *testing.T) {
	h := deviceHarness(t, discovery.Device{Address: "192.168.1.30", Hostname: "widgetbox", Kind: discovery.KindOther, Services: []discovery.Service{{Port: 80, Proto: discovery.ProtoHTTP,
		Fields: []discovery.Field{stated(discovery.FieldModel, "WX-9000"), stated(discovery.FieldSerial, "SN123456")}}}})
	_, page := h.do(t, "GET", "/systems/device:192.168.1.30", nil, nil)
	m := regexp.MustCompile(`(?s)<details class="evidence-preview" open><summary>The evidence, exactly as it would be sent</summary><pre[^>]*>(.*?)</pre></details>`).FindStringSubmatchIndex(page)
	if m == nil {
		t.Fatalf("no evidence preview:\n%s", page)
	}
	shown := html.UnescapeString(page[m[2]:m[3]])
	if !strings.Contains(shown, `"WX-9000"`) {
		t.Errorf("preview lacks the model: %s", shown)
	}
	for _, leak := range []string{"192.168.1.30", "widgetbox", "SN123456"} {
		if strings.Contains(shown, leak) {
			t.Errorf("preview shows %q", leak)
		}
	}
	_, file := h.do(t, "GET", "/systems/device:192.168.1.30/evidence.json", nil, nil)
	if strings.TrimSpace(file) != strings.TrimSpace(shown) {
		t.Errorf("preview differs from the download:\n%s\n---\n%s", shown, file)
	}
	link := regexp.MustCompile(`href="([^"]*issues/new\?[^"]*)"`).FindStringSubmatch(page)
	if link == nil {
		t.Fatal("no issue link")
	}
	u, err := url.Parse(html.UnescapeString(link[1]))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("evidence"); got != strings.TrimSpace(shown) {
		t.Errorf("issue body differs from the preview:\n%s", got)
	}
	if actions := strings.Index(page, "Help recognise this device"); actions < m[0] {
		t.Error("preview not above the actions")
	}
	if !strings.Contains(page, "Varde sends nothing by itself. Look at the evidence before you share it.") {
		t.Error("page lacks the sentence on sending")
	}
}

// A device only the scan knows is reached from its row on the network page,
// which shows how far it is identified.
func TestNetworkRowLinksScanOnlyDevice(t *testing.T) {
	h := deviceHarness(t, discovery.Device{Address: "192.168.1.60", Kind: discovery.KindOther, Services: []discovery.Service{{Proto: discovery.ProtoARP,
		Fields: []discovery.Field{stated(discovery.FieldMAC, "00:11:32:aa:bb:cc")}}}})
	_, body := h.do(t, "GET", "/connections", nil, nil)
	row := regexp.MustCompile(`(?s)<tr>\s*<td data-label="Address">.*?192\.168\.1\.60.*?</tr>`).FindString(body)
	if row == "" {
		t.Fatalf("no row for the device:\n%s", body)
	}
	if !strings.Contains(row, `href="/systems/device:192.168.1.60"`) {
		t.Errorf("row does not link to the device page: %s", row)
	}
	if !strings.Contains(row, ">anchored<") {
		t.Errorf("row lacks the level: %s", row)
	}
	if resp, _ := h.do(t, "GET", "/systems/device:192.168.1.60", nil, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("device page: %d", resp.StatusCode)
	}
}
