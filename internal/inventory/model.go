// SPDX-License-Identifier: Apache-2.0

// Package inventory defines what Varde knows about hosts and the workloads
// running on them, and the collectors that observe them.
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
)

// HostKind classifies a host.
type HostKind string

// Host kinds.
const (
	HostDocker       HostKind = "docker-host"
	HostProxmoxGuest HostKind = "proxmox-guest"
	HostBareMetal    HostKind = "bare-metal"
	HostAppliance    HostKind = "appliance"
	// HostLinux is a Linux system read over SSH (a VM, an LXC container or
	// a server).
	HostLinux HostKind = "linux"
	// HostDevice is an address Varde knows only from the network.
	HostDevice HostKind = "device"
)

// HostSource records how a host became known.
type HostSource string

// Host sources.
const (
	SourceLocal   HostSource = "local"
	SourceAgent   HostSource = "agent"
	SourceProxmox HostSource = "proxmox"
	SourceManual  HostSource = "manual"
	// SourceSSH is a Docker host read through the Docker Engine API over
	// SSH, without an agent.
	SourceSSH HostSource = "ssh"
	// SourceSSHInventory is a host whose native packages and services are
	// read over SSH with a restricted key.
	SourceSSHInventory HostSource = "ssh-inventory"
	// SourceEndpoint is an address where an app reported its version.
	SourceEndpoint HostSource = "endpoint"
	// SourceNodeInventory is an LXC container whose packages were read
	// through its Proxmox node.
	SourceNodeInventory HostSource = "node-inventory"
	// SourceLease is a device a router or DHCP server knows, with MAC and
	// name.
	SourceLease HostSource = "lease"
	// SourceAppliance is an appliance (NAS, Home Assistant OS) that
	// reported its own operating system or firmware version.
	SourceAppliance HostSource = "appliance"
)

// LocalHostID is the fixed ID of the Docker host the server runs on.
const LocalHostID = "local"

// Host is a machine or guest that runs workloads.
type Host struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Kind         HostKind   `json:"kind"`
	Source       HostSource `json:"source"`
	AgentVersion string     `json:"agent_version,omitempty"`
	OS           string     `json:"os,omitempty"`
	Arch         string     `json:"arch,omitempty"`
	Addresses    []string   `json:"addresses,omitempty"`
	LastContact  time.Time  `json:"last_contact"`
	CreatedAt    time.Time  `json:"created_at"`
	// State is active, stale (an agent stopped reporting) or revoked.
	State HostState `json:"state"`
	// CertExpires is the expiry of an agent's pinned client certificate.
	CertExpires *time.Time `json:"cert_expires,omitempty"`
	// ReportInterval is the interval an agent announced.
	ReportInterval time.Duration `json:"-"`
	// IntegrationID names the integration that reports the host, empty for
	// the local host, agents and manual hosts.
	IntegrationID string `json:"integration_id,omitempty"`
	// Detail is a short status from the reporting platform, for example
	// "running on node pve1".
	Detail string `json:"detail,omitempty"`
	// MACs and MachineID are identity keys: they tie records of different
	// sources to one machine even without a shared address (ADR 0023).
	MACs      []string `json:"macs,omitempty"`
	MachineID string   `json:"machine_id,omitempty"`
	// ParentID is the host record this one runs on: a Proxmox guest's
	// node. Empty when unknown.
	ParentID string `json:"parent_id,omitempty"`
}

// HostState is the liveness state of a host.
type HostState string

// Host states.
const (
	HostActive  HostState = "active"
	HostStale   HostState = "stale"
	HostRevoked HostState = "revoked"
)

// Kind classifies a workload.
type Kind string

// Workload kinds.
const (
	KindContainer Kind = "container"
	KindPackage   Kind = "package"
	KindService   Kind = "service"
	KindManual    Kind = "manual"
	// KindEndpoint is an app whose version Varde read from the app's own
	// version endpoint over the network.
	KindEndpoint Kind = "endpoint"
)

// Exposure is the estimated reachability of a workload.
type Exposure string

// Exposure levels.
const (
	ExposurePublic   Exposure = "public"
	ExposureLAN      Exposure = "lan"
	ExposureInternal Exposure = "internal"
	ExposureUnknown  Exposure = "unknown"
)

// Valid reports whether e is a known exposure level.
func (e Exposure) Valid() bool {
	switch e {
	case ExposurePublic, ExposureLAN, ExposureInternal, ExposureUnknown:
		return true
	}
	return false
}

// Workload is one running thing that can carry an app. Exactly one of the
// kind-specific fields is set, matching Kind.
type Workload struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	Kind      Kind   `json:"kind"`
	RuntimeID string `json:"runtime_id"`
	Name      string `json:"name"`
	State     string `json:"state,omitempty"`

	Container *Container `json:"container,omitempty"`
	Package   *Package   `json:"package,omitempty"`
	Service   *Service   `json:"service,omitempty"`
	Manual    *Manual    `json:"manual,omitempty"`
	Endpoint  *Endpoint  `json:"endpoint,omitempty"`

	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	RemovedAt *time.Time `json:"removed_at,omitempty"`
}

// Container holds container-specific inventory data.
type Container struct {
	// ImageRef is the reference the container was created from, as given by
	// the user (e.g. "ghcr.io/immich-app/immich-server:v1.120.0").
	ImageRef string `json:"image_ref"`
	// ImageID is the local image ID (config digest).
	ImageID string `json:"image_id"`
	// RepoDigests are the registry digests of the local image.
	RepoDigests []string          `json:"repo_digests,omitempty"`
	ImageLabels map[string]string `json:"image_labels,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Ports       []Port            `json:"ports,omitempty"`
	Networks    []Network         `json:"networks,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	// Runtime are the settings that decide what the container can do on
	// its host (ADR 0034); nil when unknown.
	Runtime        *Runtime `json:"runtime,omitempty"`
	ComposeProject string   `json:"compose_project,omitempty"`
	// ResolvedTag is the version tag the registry gives the running digest
	// (see internal/registry); set by the analysis, not stored.
	ResolvedTag    string `json:"-"`
	ComposeService string `json:"compose_service,omitempty"`
	// Distro and Packages are the operating system and package database
	// of the image, read from a running container (see ImagePackages);
	// set by the analysis, not stored with the workload.
	Distro   string    `json:"-"`
	Packages []Package `json:"-"`
	// PulledImageID is the local image the container's tag points to now,
	// when it differs from the image the container runs: a newer image was
	// pulled but the container not recreated.
	PulledImageID string `json:"pulled_image_id,omitempty"`
	// ChangedFiles are files with version evidence (package databases, the
	// app's manifest) changed inside the container; the image's evidence
	// from them does not describe this container.
	ChangedFiles []string `json:"changed_files,omitempty"`
}

// ImagePackages is what the package databases of one image say, read from
// a container that runs it. An image ID names immutable content, so one
// read serves every container of the image on every host.
type ImagePackages struct {
	ImageID string `json:"image_id"`
	// Distro is "<ID>-<VERSION_ID>" from os-release ("debian-13"), OS the
	// readable name; both empty for images without os-release.
	Distro   string    `json:"distro,omitempty"`
	OS       string    `json:"os,omitempty"`
	Packages []Package `json:"packages,omitempty"`
	Read     time.Time `json:"read"`
	// Error says why the read failed; failed reads are retried sooner.
	Error string `json:"error,omitempty"`
	// Format is the version of the reader that wrote the record; a record
	// of an older reader is read again at once (docker.ReaderFormat).
	Format int `json:"format,omitempty"`
	// Partial marks a read that stopped at a size or time bound: what it
	// found is checked, but it is not the image's complete package list.
	Partial bool `json:"partial,omitempty"`
}

// MaxImagePackages bounds the packages of one image's package list that
// comes from outside Varde (an agent, the data package).
const MaxImagePackages = 20000

var distroPattern = regexp.MustCompile(`^[a-z0-9._-]{0,64}$`)

// CheckImagePackages checks the release fields and the packages of an
// image's package list that comes from outside Varde's trust zone (an
// agent's report, the data package): bounded lengths, a distribution in
// the form "debian-12", and no package that claims to be the system's.
func CheckImagePackages(distro, os string, pkgs []Package) error {
	if !distroPattern.MatchString(distro) || len(os) > 128 {
		return errors.New("invalid release fields")
	}
	if len(pkgs) > MaxImagePackages {
		return errors.New("too many packages")
	}
	for _, pkg := range pkgs {
		if len(pkg.Name) > 256 || len(pkg.Version) > 128 || len(pkg.SourceVersion) > 128 || len(pkg.Manager) > 16 || len(pkg.Source) > 256 || len(pkg.Distro) > 64 || len(pkg.Path) > 512 || pkg.System {
			return errors.New("an invalid package")
		}
	}
	return nil
}

// Port is a container port, optionally published on the host.
type Port struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort uint16 `json:"private_port"`
	PublicPort  uint16 `json:"public_port,omitempty"`
	Protocol    string `json:"protocol"`
}

// Runtime are a container's settings that decide whether taking it over
// gives the host: privileged mode, added capabilities, the host's network
// or process namespace, and the user it runs as.
type Runtime struct {
	Privileged  bool     `json:"privileged,omitempty"`
	CapAdd      []string `json:"cap_add,omitempty"`
	NetworkMode string   `json:"network_mode,omitempty"`
	PidMode     string   `json:"pid_mode,omitempty"`
	User        string   `json:"user,omitempty"`
	Devices     int      `json:"devices,omitempty"`
}

// Mount is a volume or bind mount of a container. A bind of the Docker
// socket, for example, gives the container control over the host.
type Mount struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"rw"`
}

// Network is a container's attachment to a Docker network.
type Network struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address,omitempty"`
}

// Listener is a socket a host listens on, from /proc/net: the service may be
// reachable at Address:Port. Address 0.0.0.0 or :: means every interface,
// 127.0.0.1 or ::1 only the host itself (ADR 0034).
type Listener struct {
	Proto   string `json:"proto"` // tcp or udp
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Local reports whether only the host itself can reach the listener.
func (l Listener) Local() bool {
	return strings.HasPrefix(l.Address, "127.") || l.Address == "::1"
}

// Package is a natively installed package, read over SSH or by an agent.
type Package struct {
	Manager string `json:"manager"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Distro is the os-release ID and VERSION_ID of the system the package
	// is installed on ("debian-13"), when known.
	Distro string `json:"distro,omitempty"`
	// Source is the source package it was built from ("openssl" for
	// libssl3), when the package database says; distribution security data
	// names source packages.
	Source string `json:"source,omitempty"`
	// SourceVersion is the source package's version where it differs from
	// the binary's ("3.0.11-1" for a binNMU "3.0.11-1+b1"); security data
	// names source versions.
	SourceVersion string `json:"source_version,omitempty"`
	// Path is the manifest the package was read from, for an app's own
	// manifest (manager npm: "/app/package.json"); empty for packages of a
	// package database.
	Path string `json:"path,omitempty"`
	// System marks an operating system package: a source package of the
	// host, checked against its distribution's security data (ADR 0032).
	// It is part of the system, not an app, and is listed with the
	// system's packages only.
	System bool `json:"system,omitempty"`
}

// Service is a systemd unit, read over SSH or by an agent.
type Service struct {
	Unit       string `json:"unit"`
	Executable string `json:"executable,omitempty"`
	Version    string `json:"version,omitempty"`
	Enabled    bool   `json:"enabled"`
	Active     bool   `json:"active"`
}

// Endpoint is an app that reported its version at a documented endpoint.
// The app is set only when the response proved it comes from that app.
type Endpoint struct {
	URL     string `json:"url"`
	AppID   string `json:"app_id"`
	Version string `json:"version"`
}

// Manual is a user-maintained entry for something Varde cannot observe.
type Manual struct {
	AppID    string   `json:"app_id"`
	Version  string   `json:"version"`
	Exposure Exposure `json:"exposure"`
	Note     string   `json:"note,omitempty"`
}

// WorkloadID derives the stable workload ID from its natural key.
func WorkloadID(hostID string, kind Kind, runtimeID string) string {
	h := sha256.Sum256([]byte(hostID + "\x00" + string(kind) + "\x00" + runtimeID))
	return hex.EncodeToString(h[:12])
}

// HostInfo describes the host a collector observes.
type HostInfo struct {
	Name string
	OS   string
	Arch string
}

// Snapshot is the complete set of workloads of one kind on one host.
type Snapshot struct {
	Host      HostInfo
	Workloads []Workload
}

// Changes summarises the effect of applying a snapshot.
type Changes struct {
	Added   int
	Changed int
	Removed int
}

// Any reports whether anything changed.
func (c Changes) Any() bool { return c.Added+c.Changed+c.Removed > 0 }

// Event signals that the observed inventory may have changed.
type Event struct {
	Reason string
}

// Collector observes one kind of workload on one host. Implementations are
// read-only.
type Collector interface {
	// Kind is the workload kind this collector reports.
	Kind() Kind
	// List returns the complete current snapshot.
	List(ctx context.Context) (Snapshot, error)
	// Watch emits change signals until ctx is cancelled, then closes the
	// channel. Implementations reconnect on their own.
	Watch(ctx context.Context) <-chan Event
}
