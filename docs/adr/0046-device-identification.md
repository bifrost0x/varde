# 0046 Every device is identified from what it states, resolved by data, and learned once for everyone

Status: Accepted (stage 1 in progress)

## Context
A UGREEN NAS put on the network and scanned was not recognised. That is not a missing case; it is
how recognition works today. `internal/discovery` reads what answers on 20 fixed ports and on mDNS,
SSDP and SNMP, and collapses all of it into one label: `productFromHTTP` and `knownProducts` match
substrings ("synology", "qnap", "fritz!box") in page titles and banners, everything else becomes
"Web service" or "Device (port N open)". The structured answers the readers already receive (the
UPnP description's manufacturer, model, model number, serial number and UDN, the mDNS TXT records,
SNMP's `sysObjectID`) are thrown away. A device only the scan found has no identity of its own: it is
an address, so a changed lease makes it a new device, and it gets no stable asset (ADR 0023).
Every new product needs a line of Go code and a release.

Containers and the systems Varde reads with integrations or agents are already identified by
exact keys: a container by its host, its ID and its image digest, looked up in the first-party
index (ADR 0038); a host by `host:`, `mac:` and `mid:` keys tied to a stable asset ID. ADR 0038 set
the rule for devices too ("identified by what their firmware states, never by names a user can
set") and planned "self-description readers" as its stage 3. This decision is that stage, and the
way it is kept growing without code.

What a user needs for every device, container and system: a name to recognise it by, an identity
that stays the same, the manufacturer and model, the firmware or operating system version, and
what software runs on it. That last part is what makes vulnerability matching possible at all.

## Goals, non-goals, anti-goals
- **Goals.** Every asset Varde sees has a stable identity and is listed. For every asset Varde says
  how far it is identified, on what evidence, and the one step that would identify it further.
  Recognising a new product is a change of data, not of code, and reaches every installation with
  the daily data package. The recognition rate is measured and cannot silently fall.
- **Non-goals.** Changes to advisory matching or priorities before stage 5. Logging in to devices by default.
  Recognising devices that answer nothing at all (they stay "seen", with the reason).
- **Anti-goals.** A product named from a substring or a user-set name (host name, UPnP friendly
  name, mDNS instance name, SNMP `sysName`) presented as identified. Any data leaving the
  installation without the user seeing and sending it. Per-vendor Go code in the installation.

## Decision

### 1. Observations instead of labels
Readers no longer reduce an answer to a label. Each answer becomes an observation: a list of
typed fields with their source and how they were stated.

| Field | Examples of sources |
|---|---|
| `manufacturer`, `model`, `model_number` | UPnP description, mDNS TXT (`md`, `model`, `usb_MFG`, `usb_MDL`, `ty`), SNMP ENTITY-MIB, documented info endpoints |
| `firmware`, `os`, `os_version`, `hw_version` | UPnP description and its vendor extensions, mDNS TXT (`fw`, `version`), SNMP `sysDescr` and ENTITY-MIB, info endpoints, SSH banner |
| `serial`, `uuid`, `mac` | UPnP `serialNumber` and `UDN`, SNMP ENTITY-MIB, mDNS TXT (`mac`, `id`), ARP where Varde runs on the segment |
| `vendor_oid` | SNMP `sysObjectID` (IANA enterprise number) |
| `tls`, `ssh_hostkey` | certificate subject, issuer and fingerprint, SSH host key fingerprint |
| `http` | title, `Server` header, favicon hash, redirect target |
| `display_name` | host name, friendly name, instance name, `sysName`: display only, never identity or product |

Each field carries its trust: `stated` (the device says so in a structured field), `derived` (read
from free text such as a banner or title, or matched from a hint) or `user` (set under the
device). Only `stated` fields, or a rule of the device index, identify a product.

The readers are the existing ones, made to keep what they read, plus: mDNS TXT records, SNMP
ENTITY-MIB (with the community already configured), the TLS certificate of every HTTPS port, the
SSH host key, and the HTTP favicon. All stay unauthenticated, read-only and bounded as today.

### 2. Identity anchors for every asset
An asset is tied to the strongest keys it gives: `mac:`, `uuid:` (UPnP UDN), `serial:<manufacturer>/<serial>`,
`ssh:<host key fingerprint>`, `cert:<fingerprint>` (only for a certificate the device made for
itself), plus the existing `host:` and `mid:`. Scan-only devices get stable asset IDs like hosts
(ADR 0023): two observations with a shared strong key are one asset; an address alone never ties
observations of different scans together. Within one moment, a scanned device and a host an
integration or agent reports at the same address are still one machine, as today (ADR 0021). A
key seen at two addresses in the same scan is no anchor (factory-shared certificates and host
keys). The asset ID is added beside the existing IDs: `device:<address>` stays valid in the API
and the pages, so nothing that links to a device breaks. A device without any strong key is listed as "seen at
<address>" and says that its identity follows its address.

### 3. Resolution by a device index, as data
A new blob `devices` in the data package (ADR 0039) holds rules that map observation keys to
products. A rule is data:
- **match:** exact keys (`upnp:<manufacturer>|<model>`, `mdns:<service type>|<model>`,
  `snmp:<oid prefix>`, `oui:<prefix>`, `cert-issuer:<organisation>`, `favicon:<hash>`, `port:<n>`
  combined with others), all of which must hold;
- **product:** manufacturer, model family, device class (NAS, router, printer, camera, ...), the
  firmware or OS product it runs, and its catalog or index entry where one exists;
- **version:** where the firmware version is read: an observation field, or a documented
  unauthenticated endpoint with a JSON pointer or a pattern (the form `discovery.VersionEndpoint`
  already has for apps);
- **ports:** extra ports to probe on a device that matched a weaker key (a vendor's management
  port), in a second pass after the first resolution. A rule names at most 4 ports, the whole
  index at most 64; the installation refuses a blob beyond these bounds, so signed data can never
  turn the scan into a port sweep. The first pass keeps the default ports.

The installation has one generic resolver: it evaluates the rules on the observations, takes the
most specific rule that matches, and records which rule identified the asset. It never guesses
from a key no rule names. A vendor's management port is probed without a release, through the
second pass of the rules that name it.

**Baseline in the binary.** Like the image index, the rules are also embedded in every release
(the builder writes both), so an installation without a data package recognises at least what it
recognises today. The data package's rules replace the embedded ones when they are newer.

Rules from `derived` keys (favicon, title, certificate issuer, port) may name a device class, a
manufacturer and a product, never a firmware version: that needs a `stated` field or an endpoint.
A product named this way is shown as recognised from its web interface, not as stated.

**Software products on the network** (Proxmox VE and Backup Server, Portainer, Home Assistant,
Pi-hole, AdGuard Home, an open Docker API) become rules of the same index: they are what answers
at an address, and today's `Kind` values, on which onboarding and the connect steps rely, are set
from the rule's product. `Kind` stays a field of its own beside the device class.

The rules are built and signed centrally, like the image index: by a builder in this repository
from reviewed rule files (`index/devices/*.yaml`), and later from vendor sources (firmware release
pages, update servers) that name models and current firmware. Today's `knownProducts` move into it
as the first rules.

### 4. Identification levels, honestly shown
Every asset (device, host, VM, container) has a level, the evidence for it and the next step:

| Level | Means | Typical next step |
|---|---|---|
| seen | it answered at an address | none possible, or run Varde on the segment (MAC) |
| anchored | stable identity | add a source that states more |
| class | what kind of device it is | submit its evidence (section 5) |
| model | manufacturer and model | submit its evidence, or connect it |
| firmware | firmware or OS version | connect it to read its software |
| software | what runs on it (apps, containers, packages) | none |

Containers are "software" when their image is resolved and "firmware" or below by the existing
rules; hosts read by integrations or agents reach "software". The overview counts assets by level;
the measure Varde aims at is 100 % at "anchored" and a next step on every asset below "software".

### 5. Learned once, for everyone
An asset below "model" offers **Help recognise this device**. Varde builds an evidence bundle from
its observations and shows the bundle in full before anything happens. The bundle holds only
fields that describe the product: manufacturer, model, firmware, service types, SNMP OID, the
certificate issuer, favicon hash, open ports, the first half of the MAC (the OUI). It never holds
addresses, display names, serial numbers, UUIDs, full MACs, host key or certificate fingerprints.
The user sends it themselves: a prefilled issue in the project's repository (template `device`),
or a file to attach. Varde sends nothing on its own.

The maintainer turns a bundle into a rule file, the builder signs it into the next data package,
and every installation with that device recognises it from then on. A bundle is also a test case:
it goes into the evaluation corpus with its ground truth.

### 6. Measured
`internal/eval` gets device cases: recorded observations of real devices with their ground truth
(manufacturer, model, firmware, level). It reports device precision (no wrong product, no wrong
version) and recall per level; the gate file holds the baseline, and a change that lowers it fails
CI. Precision is the hard bar: a wrong identification is worse than a lower level.

## Stages
1. **Observe and measure.** Readers keep structured observations; mDNS TXT, ENTITY-MIB, TLS,
   SSH host key and favicon readers; trust per field; the evidence bundle and its export; the
   level per asset on the pages; device cases in the evaluation. Nothing is recognised better yet,
   but every device shows what it states, and the UGREEN NAS gives the first bundle.
2. **Resolve by data.** The `devices` blob, the rule files, the generic resolver, data-driven
   ports and version endpoints; `knownProducts` and `productFromHTTP` replaced by rules; stable
   anchors and assets for scan-only devices.
3. **Learn.** The submission flow (issue template, prefilled issue), the builder path from bundle
   to rule to corpus case, the rate of assets by level in the overview.
4. **More anchors.** Where Varde cannot see MACs (Docker's NAT), router integrations that list
   clients with their MACs (FRITZ!Box TR-064, UniFi), read-only.
5. **Firmware into matching.** A device at "firmware" becomes a system with a firmware package
   (ADR 0038 stage 3), whose catalog or index entry is matched against advisories. A version the
   device states without authentication counts as `reported` (ADR 0023): its findings are to
   check yourself and never notify; only a version read through an integration can be
   `confirmed`. Until this stage, model and firmware are shown, not matched.

## Alternatives
- **A larger fingerprint database** (banners, favicons, page titles), the way existing scanners
  work: fast coverage, but it guesses, rarely yields a firmware version and was rejected in ADR
  0038. Kept only as `derived` hints that name a class or a manufacturer.
- **Self-description and index without the learning loop:** precise, but every unknown product
  waits until the maintainer finds it. The loop is what ends the case-by-case work.
- **Automatic submission (telemetry):** would learn fastest; against the project's rule that
  nothing leaves an installation unseen.
- **Logging in to devices to read their version:** exact, but needs credentials; it stays the
  "connect it" step of the integrations.

## Consequences
- The device list says for each device what it is as far as it states it, and what would tell
  more; nothing is called identified on a substring.
- Recognising a new device needs a rule file and a data package, not a release.
- The scan probes the ports the rules name in addition to the default ones; the number stays
  bounded by the index and is listed under Settings.
- Without running on the LAN segment and without a router integration, scan-only devices behind
  Docker's NAT are anchored only when they state a UDN, serial, host key or own certificate.
- Stored devices gain observations (migration); devices stored before keep their label and are
  observed again with the next scan.
