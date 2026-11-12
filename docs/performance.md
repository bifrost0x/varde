# Performance

Measured against the project's performance budget. Re-measure when the data model, the
pipeline or the feed format changes.

## Setup

- Image `varde/varde:dev` built from this repository (distroless static, 30.3 MB), Docker Desktop
  on Windows 11, AMD Ryzen 7 9800X3D. A Raspberry Pi is several times slower per core; the margins
  below are large enough for that.
- Container started read-only with all capabilities dropped and `/data` on tmpfs.
- Feed mode with a development feed exported from a real installation (`cmd/feedbuilder
  -from-db`): full seed catalog, 626 advisories, 1769 KEV entries.
- 100 workloads: manual entries spread over every catalog app at version 1.0.0, so most of them
  match many advisories (945 findings: 3 P1, 864 P2, 78 P3, 6 unverified). This is a worst case for
  the pipeline; a typical homelab has a small fraction of that.

Memory is the container's memory usage as reported by `docker stats` (resident memory of the single
process, without page cache), sampled repeatedly.

## Results

| Budget | Target | Measured |
|---|---|---|
| Idle memory, 100 workloads, full catalog | < 40 MB | 31–33 MiB |
| Peak memory during feed install | < 150 MB | about 23 MiB (sampled once per second; short spikes may be missed) |
| CPU when idle | near zero | 0.00 % over 15 s; inventory is event-driven, refreshes run on timers |
| Startup to ready | < 1 s | 10 ms from process start to listening; 540 ms from `docker run` to `/readyz` 200, including container creation |
| Analysis pass, 100 workloads | < 5 s | 33 ms in the container; 47 ms per pass in `BenchmarkRun100` (60 catalog workloads × 30 advisories each) |
| Analysis pass, 10 hosts with 400 system packages each | < 5 s | 91 ms per pass in `BenchmarkRunSystemPackages` (40 packages with 5 distribution records each); a first package check of a host with 86 packages took 233 osv.dev requests and 11 s |
| Daily network in feed mode | < 5 MB | The complete feed above is 246 KB compressed; an update fetches the manifest (a few KB, conditional GET) plus only the changed shards |
| Direct mode network | bounded by apps present | One conditional request per repository and refresh interval (6 h); 304 responses carry no body |
| SQLite size after a year | < 50 MB | Estimate: 3.1 MB after a day on a real installation (25 workloads, about 600 advisories). Growth is bounded by retention (notification log 30 days, resolved findings 90 days, removed workloads 90 days, finding history two years); advisories scale with the apps present, not with time. The audit log grows by a few hundred bytes per action. |

## Benchmarks

```sh
go test -run x -bench . ./internal/pipeline ./internal/version ./internal/match
```

| Benchmark | Time | Allocations |
|---|---|---|
| `BenchmarkCompare` (version comparison) | 30 ns | 0 |
| `BenchmarkParseSemVer` | 600 ns | 6 |
| `BenchmarkMatch` (one app, 300 advisories) | 0.4 ms | 5750 |
| `BenchmarkRun100` (full pass, see above) | 47 ms | 207k |
| `BenchmarkRunSystemPackages` (full pass, see above) | 91 ms | 471k |

Version comparison, the hot path of matching, does not allocate. Matching allocates per advisory
for evidence and range evaluation; at homelab scale that is not worth optimising.
