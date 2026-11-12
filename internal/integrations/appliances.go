// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Appliance kinds: systems whose own API reports their operating system
// or firmware version, which the catalog checks against advisories like a
// package (ADR 0036).
const (
	KindSynology      = "synology"
	KindQNAP          = "qnap"
	KindTrueNAS       = "truenas"
	KindUnraid        = "unraid"
	KindHomeAssistant = "homeassistant"
)

// ApplianceSystem is what an appliance reports about itself. Package is
// the firmware package the catalog knows it by, Version its version in a
// form the catalog compares.
type ApplianceSystem struct {
	Name    string `json:"name,omitempty"`
	Product string `json:"product"`
	Model   string `json:"model,omitempty"`
	Package string `json:"package"`
	Version string `json:"version"`
	// Raw is the version as the appliance writes it ("DSM 7.2.1-69057
	// Update 5"), for display.
	Raw string `json:"raw"`
}

// versionText bounds and checks a version field from a device.
var versionText = regexp.MustCompile(`^[A-Za-z0-9 ._+\-]{1,96}$`)

func cleanVersion(s string) (string, bool) {
	s = strings.TrimSpace(s)
	return s, versionText.MatchString(s)
}

// readAppliance reads the system of an appliance integration.
func readAppliance(ctx context.Context, kind string, c *serviceClient) (*ApplianceSystem, error) {
	switch kind {
	case KindSynology:
		return synologySystem(ctx, c)
	case KindQNAP:
		return qnapSystem(ctx, c)
	case KindTrueNAS:
		return truenasSystem(ctx, c)
	case KindUnraid:
		return unraidSystem(ctx, c)
	case KindHomeAssistant:
		return homeAssistantSystem(ctx, c)
	}
	return nil, fmt.Errorf("unknown appliance kind %q", kind)
}

// dsmVersion turns "DSM 7.2.1-69057 Update 5" into 7.2.1.69057.5: the
// build and the update number order the releases of one version.
var dsmVersion = regexp.MustCompile(`^(?:DSM\s+)?(\d+\.\d+(?:\.\d+)?)-(\d+)(?:\s+Update\s+(\d+))?$`)

// synologySystem signs in to DSM's Web API with a user's password, reads
// SYNO.DSM.Info and signs out again. Every DSM user may read it; the
// session ends with the read.
func synologySystem(ctx context.Context, c *serviceClient) (*ApplianceSystem, error) {
	form := url.Values{"api": {"SYNO.API.Auth"}, "version": {"6"}, "method": {"login"}, "account": {c.user}, "passwd": {c.secret},
		"session": {"Varde"}, "format": {"sid"}}
	hdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	b, _, err := c.do(ctx, http.MethodPost, "/webapi/entry.cgi", []byte(form.Encode()), hdr)
	if err != nil {
		return nil, err
	}
	var login struct {
		Success bool `json:"success"`
		Data    struct {
			SID string `json:"sid"`
		} `json:"data"`
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &login); err != nil {
		return nil, fmt.Errorf("unexpected DSM sign-in answer: %w", err)
	}
	if !login.Success || login.Data.SID == "" {
		if login.Error.Code == 403 || login.Error.Code == 406 {
			return nil, errors.New("DSM asks for a second factor: use a user without two-factor sign-in for Varde")
		}
		return nil, fmt.Errorf("DSM refused the sign-in (code %d): check user and password", login.Error.Code)
	}
	sid := login.Data.SID
	defer func() {
		logout := url.Values{"api": {"SYNO.API.Auth"}, "version": {"6"}, "method": {"logout"}, "session": {"Varde"}, "_sid": {sid}}
		_, _, _ = c.do(context.WithoutCancel(ctx), http.MethodPost, "/webapi/entry.cgi", []byte(logout.Encode()), hdr)
	}()
	q := url.Values{"api": {"SYNO.DSM.Info"}, "version": {"2"}, "method": {"getinfo"}, "_sid": {sid}}
	b, _, err = c.do(ctx, http.MethodPost, "/webapi/entry.cgi", []byte(q.Encode()), hdr)
	if err != nil {
		return nil, err
	}
	var info struct {
		Success bool `json:"success"`
		Data    struct {
			Model         string `json:"model"`
			VersionString string `json:"version_string"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &info); err != nil || !info.Success {
		return nil, errors.New("DSM did not report its version")
	}
	raw, ok := cleanVersion(info.Data.VersionString)
	m := dsmVersion.FindStringSubmatch(raw)
	if !ok || m == nil {
		return nil, fmt.Errorf("unexpected DSM version %q", truncateRunes(info.Data.VersionString, 64))
	}
	v := m[1] + "." + m[2]
	if m[3] != "" {
		v += "." + m[3]
	}
	model, _ := cleanVersion(info.Data.Model)
	return &ApplianceSystem{Product: "Synology DSM", Model: model, Package: "synology-dsm", Version: v, Raw: raw}, nil
}

// qnapSystem reads the firmware QNAP's sign-in page reports without
// signing in (/cgi-bin/authLogin.cgi). No credential is sent.
func qnapSystem(ctx context.Context, c *serviceClient) (*ApplianceSystem, error) {
	b, _, err := c.do(ctx, http.MethodGet, "/cgi-bin/authLogin.cgi", nil, nil)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Model    string `xml:"model>displayModelName"`
		Hostname string `xml:"hostname"`
		Firmware struct {
			Version string `xml:"version"`
			Number  string `xml:"number"`
			Build   string `xml:"build"`
		} `xml:"firmware"`
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("unexpected QNAP answer: %w", err)
	}
	ver, ok := cleanVersion(doc.Firmware.Version)
	num, okN := cleanVersion(doc.Firmware.Number)
	if !ok || !okN || !qnapPart.MatchString(ver) || !digits.MatchString(num) {
		return nil, errors.New("QNAP did not report its firmware")
	}
	product, pkg := "QNAP QTS", "qnap-qts"
	if major := strings.SplitN(ver, ".", 2)[0]; major == "h4" || major == "h5" || strings.HasPrefix(ver, "h") {
		// QuTS hero names its versions h5.1.4.
		product, pkg, ver = "QNAP QuTS hero", "qnap-quts-hero", strings.TrimPrefix(ver, "h")
	}
	raw := ver + "." + num
	if build, ok := cleanVersion(doc.Firmware.Build); ok && digits.MatchString(build) {
		raw += " build " + build
	}
	name, _ := cleanVersion(doc.Hostname)
	model, _ := cleanVersion(doc.Model)
	return &ApplianceSystem{Name: name, Product: product, Model: model, Package: pkg, Version: ver + "." + num, Raw: raw}, nil
}

var (
	qnapPart = regexp.MustCompile(`^h?\d+\.\d+\.\d+$`)
	digits   = regexp.MustCompile(`^\d{1,10}$`)
	// truenasVersion reads "TrueNAS-SCALE-24.10.1", "TrueNAS-25.04.0" and
	// "TrueNAS-13.0-U6.2" (CORE).
	truenasVersion = regexp.MustCompile(`^TrueNAS-(?:(SCALE|CORE)-)?(\d+\.\d+(?:\.\d+)*)(?:-U(\d+)(?:\.(\d+))?)?$`)
)

// truenasSystem reads /api/v2.0/system/version with an API key; a key of
// a user with a read-only role suffices.
func truenasSystem(ctx context.Context, c *serviceClient) (*ApplianceSystem, error) {
	b, _, err := c.do(ctx, http.MethodGet, "/api/v2.0/system/version", nil, map[string]string{"Authorization": "Bearer " + c.secret, "Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("unexpected TrueNAS answer: %w", err)
	}
	raw, ok := cleanVersion(s)
	m := truenasVersion.FindStringSubmatch(raw)
	if !ok || m == nil {
		return nil, fmt.Errorf("unexpected TrueNAS version %q", truncateRunes(s, 64))
	}
	v := m[2]
	if m[3] != "" {
		// CORE 13.0-U6.2 is 13.0.6.2.
		v += "." + m[3]
		if m[4] != "" {
			v += "." + m[4]
		}
	}
	product, pkg := "TrueNAS", "truenas"
	if m[1] == "CORE" || m[3] != "" {
		// CORE names its updates "-U6.2"; SCALE and Community Edition
		// never do.
		product, pkg = "TrueNAS CORE", "truenas-core"
	}
	return &ApplianceSystem{Product: product, Package: pkg, Version: v, Raw: raw}, nil
}

var unraidVersion = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-(?:rc|beta)\.?\d+)?$`)

// unraidSystem asks the Unraid API (Unraid 7.2 and later, or the Connect
// plugin) for the release with an API key that has read access to info.
func unraidSystem(ctx context.Context, c *serviceClient) (*ApplianceSystem, error) {
	q, _ := json.Marshal(map[string]string{"query": "{ info { versions { core { unraid } } os { hostname } } }"})
	b, _, err := c.do(ctx, http.MethodPost, "/graphql", q, map[string]string{"x-api-key": c.secret, "Content-Type": "application/json", "Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	var ans struct {
		Data struct {
			Info struct {
				Versions struct {
					Core struct {
						Unraid string `json:"unraid"`
					} `json:"core"`
				} `json:"versions"`
				OS struct {
					Hostname string `json:"hostname"`
				} `json:"os"`
			} `json:"info"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(b, &ans); err != nil {
		return nil, fmt.Errorf("unexpected Unraid answer: %w", err)
	}
	if len(ans.Errors) > 0 {
		return nil, fmt.Errorf("the Unraid API refused: %s", truncateRunes(ans.Errors[0].Message, 120))
	}
	raw, ok := cleanVersion(ans.Data.Info.Versions.Core.Unraid)
	if !ok || !unraidVersion.MatchString(raw) {
		return nil, errors.New("no release in the Unraid answer")
	}
	name, _ := cleanVersion(ans.Data.Info.OS.Hostname)
	return &ApplianceSystem{Name: name, Product: "Unraid", Package: "unraid", Version: raw, Raw: raw}, nil
}

var haVersion = regexp.MustCompile(`^\d{4}\.\d{1,2}\.\d{1,3}$`)

// homeAssistantSystem reads the Core version from /api/config with a
// long-lived access token; a token of a user without admin rights
// suffices. For Home Assistant OS installations, whose Core runs in a
// container Varde cannot see.
func homeAssistantSystem(ctx context.Context, c *serviceClient) (*ApplianceSystem, error) {
	b, _, err := c.do(ctx, http.MethodGet, "/api/config", nil, map[string]string{"Authorization": "Bearer " + c.secret, "Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Version      string `json:"version"`
		LocationName string `json:"location_name"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("unexpected Home Assistant answer: %w", err)
	}
	raw, ok := cleanVersion(cfg.Version)
	if !ok || !haVersion.MatchString(raw) {
		return nil, errors.New("no release version in the Home Assistant answer")
	}
	name, _ := cleanVersion(cfg.LocationName)
	return &ApplianceSystem{Name: name, Product: "Home Assistant", Package: "home-assistant-core", Version: raw, Raw: raw}, nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// fritzOS reads FRITZ!OS from the TR-064 software version: "164.07.57"
// is model 164 with FRITZ!OS 7.57; lab builds append "-111234".
var fritzOS = regexp.MustCompile(`^\d{1,4}\.(\d{1,2})\.(\d{1,2})(?:-\d{1,10})?$`)

// fritzSystem reads model and FRITZ!OS version through TR-064 DeviceInfo.
func fritzSystem(ctx context.Context, c *serviceClient) (*ApplianceSystem, error) {
	v, err := c.tr064(ctx, fritzDeviceInfo, "/upnp/control/deviceinfo", "GetInfo", "")
	if err != nil {
		return nil, err
	}
	raw, ok := cleanVersion(v["NewSoftwareVersion"])
	m := fritzOS.FindStringSubmatch(raw)
	if !ok || m == nil {
		return nil, fmt.Errorf("unexpected FRITZ!OS version %q", truncateRunes(v["NewSoftwareVersion"], 32))
	}
	major := strings.TrimLeft(m[1], "0")
	if major == "" {
		major = "0"
	}
	ver := major + "." + m[2]
	model, _ := cleanVersion(v["NewModelName"])
	return &ApplianceSystem{Product: "FRITZ!OS", Model: model, Package: "fritzos", Version: ver, Raw: "FRITZ!OS " + ver}, nil
}
