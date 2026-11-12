// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"fmt"
	"math"
	"strings"
)

// CVSS3BaseScore computes the CVSS v3.0/v3.1 base score from a vector
// string such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
// Specification: https://www.first.org/cvss/v3.1/specification-document.
func CVSS3BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("malformed metric %q", p)
		}
		if _, dup := m[k]; dup {
			return 0, fmt.Errorf("duplicate metric %q", k)
		}
		m[k] = v
	}
	weight := func(metric string, table map[string]float64) (float64, error) {
		w, ok := table[m[metric]]
		if !ok {
			return 0, fmt.Errorf("invalid %s value %q", metric, m[metric])
		}
		return w, nil
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("invalid S value %q", scope)
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	var ws [7]float64
	var err error
	for i, x := range []struct {
		metric string
		table  map[string]float64
	}{
		{"AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}},
		{"AC", map[string]float64{"L": 0.77, "H": 0.44}},
		{"PR", pr},
		{"UI", map[string]float64{"N": 0.85, "R": 0.62}},
		{"C", cia}, {"I", cia}, {"A", cia},
	} {
		if ws[i], err = weight(x.metric, x.table); err != nil {
			return 0, err
		}
	}
	av, ac, prw, ui, c, i, a := ws[0], ws[1], ws[2], ws[3], ws[4], ws[5], ws[6]

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * av * ac * prw * ui
	if impact <= 0 {
		return 0, nil
	}
	if scope == "U" {
		return roundUp(math.Min(impact+exploitability, 10)), nil
	}
	return roundUp(math.Min(1.08*(impact+exploitability), 10)), nil
}

// roundUp implements the specification's Roundup function, which avoids
// floating point artefacts.
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return (math.Floor(float64(n)/10000) + 1) / 10
}
