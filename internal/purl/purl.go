// SPDX-License-Identifier: Apache-2.0

// Package purl builds package URLs (https://github.com/package-url/purl-spec)
// for the components Varde identifies: container images and native
// packages. Only building is needed; Varde never parses foreign PURLs.
package purl

import (
	"net/url"
	"sort"
	"strings"
)

// escape percent-encodes a PURL component. Per the spec, ':' stays
// unencoded only in the scheme separator, so it is encoded here.
func escape(s string) string {
	e := url.PathEscape(s)
	return strings.ReplaceAll(e, ":", "%3A")
}

// Build assembles pkg:type/namespace/name@version?qualifiers. Empty parts
// are left out; qualifiers are sorted by key as the spec requires.
func Build(typ, namespace, name, version string, qualifiers map[string]string) string {
	if typ == "" || name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(strings.ToLower(typ))
	b.WriteByte('/')
	if namespace != "" {
		for _, seg := range strings.Split(namespace, "/") {
			if seg == "" {
				continue
			}
			b.WriteString(escape(seg))
			b.WriteByte('/')
		}
	}
	b.WriteString(escape(name))
	if version != "" {
		b.WriteByte('@')
		b.WriteString(escape(version))
	}
	keys := make([]string, 0, len(qualifiers))
	for k, v := range qualifiers {
		if v != "" {
			keys = append(keys, strings.ToLower(k))
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(qualifiers[k]))
	}
	return b.String()
}

// Docker returns the PURL of an image: repository is normalised with the
// registry ("docker.io/library/nginx"), version a digest or a tag.
func Docker(repository, version string) string {
	registry, path, ok := strings.Cut(repository, "/")
	if !ok {
		return ""
	}
	namespace, name := "", path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		namespace, name = path[:i], path[i+1:]
	}
	q := map[string]string{}
	if registry != "docker.io" {
		q["repository_url"] = registry
	} else if namespace == "library" {
		// Official Docker Hub images have no namespace in the spec's
		// examples ("pkg:docker/cassandra@latest").
		namespace = ""
	}
	return Build("docker", namespace, name, version, q)
}

// Package returns the PURL of a native package. manager is dpkg, rpm or
// apk; distro is the os-release ID and VERSION_ID ("debian-13").
func Package(manager, distro, name, version string) string {
	typ := map[string]string{"dpkg": "deb", "rpm": "rpm", "apk": "apk"}[manager]
	if typ == "" {
		return ""
	}
	namespace, _, _ := strings.Cut(distro, "-")
	return Build(typ, namespace, name, version, map[string]string{"distro": distro})
}
