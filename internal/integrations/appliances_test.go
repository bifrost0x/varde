// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// DSM: sign in, read the version, sign out; the version becomes dotted
// numbers with build and update, and the session is closed.
func TestSynologySystem(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(b))
		mu.Lock()
		calls = append(calls, q.Get("method"))
		mu.Unlock()
		if r.URL.Path != "/webapi/entry.cgi" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		switch q.Get("method") {
		case "login":
			if q.Get("account") != "varde" || q.Get("passwd") != "pw" {
				_, _ = io.WriteString(w, `{"success":false,"error":{"code":400}}`)
				return
			}
			_, _ = io.WriteString(w, `{"success":true,"data":{"sid":"S1"}}`)
		case "getinfo":
			if q.Get("_sid") != "S1" {
				_, _ = io.WriteString(w, `{"success":false}`)
				return
			}
			_, _ = io.WriteString(w, `{"success":true,"data":{"model":"DS920+","version_string":"DSM 7.2.1-69057 Update 5"}}`)
		case "logout":
			_, _ = io.WriteString(w, `{"success":true}`)
		}
	})
	sys, err := readAppliance(t.Context(), KindSynology, serviceFor(t, KindSynology, h, "varde", "pw"))
	if err != nil {
		t.Fatal(err)
	}
	if sys.Package != "synology-dsm" || sys.Version != "7.2.1.69057.5" || sys.Model != "DS920+" || sys.Raw != "DSM 7.2.1-69057 Update 5" {
		t.Errorf("system %+v", sys)
	}
	if strings.Join(calls, ",") != "login,getinfo,logout" {
		t.Errorf("calls %v, want sign-in, read and sign-out", calls)
	}
	if _, err := readAppliance(t.Context(), KindSynology, serviceFor(t, KindSynology, h, "varde", "wrong")); err == nil {
		t.Error("a refused sign-in read a version")
	}
}

func TestQNAPSystem(t *testing.T) {
	for body, want := range map[string]string{
		`<?xml version="1.0" encoding="UTF-8" ?><QDocRoot version="1.0"><model><displayModelName><![CDATA[TS-453D]]></displayModelName></model><firmware><version><![CDATA[5.1.4]]></version><number><![CDATA[2596]]></number><build><![CDATA[20231128]]></build></firmware><hostname><![CDATA[nas]]></hostname></QDocRoot>`: "qnap-qts 5.1.4.2596",
		`<QDocRoot><firmware><version>h5.1.4</version><number>2596</number><build>20231128</build></firmware></QDocRoot>`: "qnap-quts-hero 5.1.4.2596",
		`<QDocRoot><firmware><version>5.1.4; rm</version><number>2596</number></firmware></QDocRoot>`:                     "",
		`not xml`: "",
	} {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/cgi-bin/authLogin.cgi" || r.Header.Get("Authorization") != "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, body)
		})
		sys, err := readAppliance(t.Context(), KindQNAP, serviceFor(t, KindQNAP, h, "", ""))
		got := ""
		if err == nil {
			got = sys.Package + " " + sys.Version
		}
		if got != want {
			t.Errorf("%.40s: %q (%v), want %q", body, got, err, want)
		}
	}
}

func TestTrueNASSystem(t *testing.T) {
	for answer, want := range map[string]string{
		`"TrueNAS-SCALE-24.10.1"`: "truenas 24.10.1",
		`"TrueNAS-25.04.0"`:       "truenas 25.04.0",
		`"TrueNAS-13.0-U6.2"`:     "truenas-core 13.0.6.2",
		`"FreeNAS-11.3"`:          "",
	} {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v2.0/system/version" || r.Header.Get("Authorization") != "Bearer key" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, answer)
		})
		sys, err := readAppliance(t.Context(), KindTrueNAS, serviceFor(t, KindTrueNAS, h, "", "key"))
		got := ""
		if err == nil {
			got = sys.Package + " " + sys.Version
		}
		if got != want {
			t.Errorf("%s: %q (%v), want %q", answer, got, err, want)
		}
	}
}

func TestUnraidSystem(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" || r.Header.Get("x-api-key") != "key" {
			_, _ = io.WriteString(w, `{"errors":[{"message":"Forbidden"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"info":{"versions":{"core":{"unraid":"7.1.4"}},"os":{"hostname":"tower"}}}}`)
	})
	sys, err := readAppliance(t.Context(), KindUnraid, serviceFor(t, KindUnraid, h, "", "key"))
	if err != nil || sys.Version != "7.1.4" || sys.Name != "tower" {
		t.Fatalf("system %+v %v", sys, err)
	}
	if _, err := readAppliance(t.Context(), KindUnraid, serviceFor(t, KindUnraid, h, "", "bad")); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("API error not reported: %v", err)
	}
}

func TestHomeAssistantSystem(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/config" || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"version":"2025.1.2","location_name":"Home"}`)
	})
	sys, err := readAppliance(t.Context(), KindHomeAssistant, serviceFor(t, KindHomeAssistant, h, "", "tok"))
	if err != nil || sys.Package != "home-assistant-core" || sys.Version != "2025.1.2" {
		t.Fatalf("system %+v %v", sys, err)
	}
}

// Every service kind, the appliances included, is read on the service
// schedule; they used to be read once at setup only.
func TestServiceKindsScheduled(t *testing.T) {
	m := &Manager{}
	for kind := range ServiceKinds {
		if m.Interval(kind) != serviceInterval {
			t.Errorf("%s has interval %v", kind, m.Interval(kind))
		}
	}
}

// The Fritz!Box reports model and FRITZ!OS through TR-064 DeviceInfo; a
// box that refuses it still gives its host list.
func TestFritzSystem(t *testing.T) {
	for allowed, want := range map[bool]string{true: "fritzos 7.57", false: ""} {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var out string
			switch {
			case r.URL.Path == "/upnp/control/deviceinfo" && strings.Contains(string(body), "GetInfo"):
				if !allowed {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				out = `<NewModelName>FRITZ!Box 7590</NewModelName><NewSoftwareVersion>154.07.57</NewSoftwareVersion>`
			case strings.Contains(string(body), "GetHostNumberOfEntries"):
				out = `<NewHostNumberOfEntries>0</NewHostNumberOfEntries>`
			}
			_, _ = io.WriteString(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:R xmlns:u="x">`+out+`</u:R></s:Body></s:Envelope>`)
		})
		st, err := readService(t.Context(), KindFritzBox, serviceFor(t, KindFritzBox, h, "u", "p"))
		if err != nil {
			t.Fatalf("allowed %v: %v", allowed, err)
		}
		got := ""
		if st.System != nil {
			got = st.System.Package + " " + st.System.Version
			if st.System.Model != "FRITZ!Box 7590" {
				t.Errorf("model %q", st.System.Model)
			}
		}
		if got != want {
			t.Errorf("allowed %v: %q, want %q", allowed, got, want)
		}
	}
}
