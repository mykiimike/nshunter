<div align="center">

<pre>
╔═══════════════════════════════════════════════════╗
║                                                   ║
║                     NSHUNTER                      ║
║              ─ DNSSEC ZONE RECON ─                ║
║                                                   ║
║  NSEC · NSEC3 · AXFR · Registries · Brute-force   ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
</pre>

[![Go Version](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)](#requirements)

<br/>

</div>

**Author:** Michael VERGOZ

A Go tool that assesses how much of your DNS zone content is discoverable through DNSSEC side-channels. It probes NSEC/NSEC3 walking exposure, zone transfers (AXFR), and passive name leakage (Certificate Transparency, MX/TXT records), then produces a risk report stored locally for tracking over time.

> DNS exposure intelligence for authorized zones.

## What it does

| Capability | Description |
|------------|-------------|
| **NS resolution** | Discover NS via a public resolver (`8.8.8.8`), then resolve NS hostnames to IP addresses — avoids failures when the local resolver (`[::1]`) does not respond. |
| **DNSSEC** | TCP queries (UDP fallback): DNSKEY, NSEC3PARAM, NSEC / NSEC3 proofs. |
| **NSEC** | Walk the NSEC chain to enumerate names; *black lies* detection. Configurable limit (`--max-walk`). |
| **NSEC3** | Concurrent random probes against zone nameservers; hash collection; corpus *cracking* with the same `NSEC3Hash` primitive as `benchmark` — **multi-core** (`runtime.NumCPU`) when the corpus has ≥512 labels. |
| **AXFR** | Zone transfer attempt against each NS (reported if allowed). |
| **Without DNSSEC** | Zone metadata: SOA, NS, MX, TXT records (SPF, domain verifications, `_dmarc`), coarse DNS provider detection. |
| **Registries** | Passive certificate discovery: [crt.sh](https://crt.sh) (always), optional [Cert Spotter](https://sslmate.com/certspotter/api/) (SSLMate CT API — good for continuous monitoring) and optional [Censys](https://search.censys.io/) certificate search (API credentials — broader index, useful before pivoting to host / infra views in Censys). |
| **Storage** | Pebble (NSEC3 hash cache) + SQLite (reports). |
| **CLI** | `analyze`, `benchmark` (CPU or `--gpu` Metal on macOS), `report` (JSON / Markdown). |

The default corpus contains thousands of generated labels (common words, numeric patterns, combinations). Supply your own list with `--corpus`.

`benchmark` (CPU) measures raw **NSEC3 SHA-1 throughput** for that primitive; `analyze` uses it during cracking so tuning `GOMAXPROCS` or CPU load affects enumeration speed. The Metal `benchmark --gpu` path is **not** wired into `analyze` yet (optional future work).

## Requirements

- Go ≥ 1.22
- macOS recommended for `benchmark --gpu` (Metal)
- Network access to the target zone’s servers and, for passive registries, to `crt.sh` and (if configured) `api.certspotter.com` / `search.censys.io`

## Installation

```bash
cd nshunter
go build -o nshunter ./
```

Self-contained binary (Go dependencies only).

### Debian package (.deb)

On **Debian or Ubuntu** (needs `dpkg-buildpackage`):

```bash
sudo apt install build-essential debhelper devscripts golang-go
chmod +x debian/rules   # first clone only, if not executable
dpkg-buildpackage -us -uc -b
```

Artifacts appear in the **parent directory** of the repo: `nshunter_<version>_<arch>.deb`, plus `.changes` and `.buildinfo`.

Adjust **`debian/changelog`**, **`debian/control`** (Maintainer / version) before publishing. The package installs `/usr/bin/nshunter` and `/usr/share/doc/nshunter/README.md`.

On **macOS**, build the `.deb` inside a Linux container or VM (Debian packaging expects a GNU/Linux toolchain).

## Quick start

```bash
./nshunter analyze --domain=example.com
./nshunter report --format=markdown --domain=example.com
```

## Usage

General help:

```bash
./nshunter --help
./nshunter <command> --help
```

Global option:

| Option | Default | Description |
|--------|---------|-------------|
| `--data-dir` | `~/.nshunter` | Override data directory for Pebble/SQLite storage |

### Analyze a zone

```bash
./nshunter analyze --domain=example.com
```

Options (`analyze`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--domain` | *(required)* | Domain or zone name to audit |
| `--corpus` | *(built-in corpus)* | Text file, one label per line (`www`, `api`, …) |
| `--max-walk` | `10000` | Max query budget for NSEC / NSEC3 walk (`0` = unlimited) |
| `--max-budget` | `2^32` | Max hash attempts per NSEC3 hole |
| `--no-axfr` | `false` | Disable AXFR transfer attempt |
| `--no-nsec` | `false` | Disable NSEC chain walk analysis |
| `--no-nsec3` | `false` | Disable NSEC3 walk/cracking analysis |
| `--no-registry` | `false` | Disable passive certificate registry scans (`crt.sh` plus optional Cert Spotter / Censys; see [Registry sources](#registry-sources)) |
| `--no-meta-hosts` | `false` | Do not merge in-zone NS/MX hostnames into enumerated names |
| `--brute-subdomains` | `false` | Actively brute-force candidate subdomains via DNS A/AAAA lookups |
| `--bruteforce-len` | `0` | Exhaustive NSEC3 brute force max label length (`0` disables; typical `5-6`) |
| `--bruteforce-timeout` | *(off)* | Time budget for NSEC3 brute force (`60s`, `15m`, `2h`, `1d`); when set, this overrides `--bruteforce-len` |

#### Registry sources

`analyze` always queries **crt.sh** (unless `--no-registry`). You can enrich results with:

| Source | Role | Configuration |
|--------|------|----------------|
| **crt.sh** | Public CT log mirror; default source. | No API key. |
| **Cert Spotter** (SSLMate) | CT search API tuned for monitoring and polling new issuances. | Optional: set `CERTSPOTTER_API_KEY` ([SSLMate API keys](https://sslmate.com/account/api_keys)). Without a key, a small unauthenticated quota is used. |
| **Censys** | Certificate search over Censys’ index (overlap with CT but different coverage; use the Censys console for host / service pivoting). | Optional: set `CENSYS_API_ID` and `CENSYS_API_SECRET` ([Search API](https://search.censys.io/account/api)). |

Names from all enabled sources are deduplicated and merged into the same enumeration used for the risk report. The CLI shows per-source counts after collection.

### Benchmark

```bash
./nshunter benchmark          # NSEC3 SHA-1 throughput on CPU
./nshunter benchmark --gpu    # same workload on the Apple GPU (Metal; macOS + CGO only)
```

Options (`benchmark`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--gpu` | `false` | Use Metal GPU acceleration (macOS + CGO) |

`--gpu` compiles the embedded `metal/kernel.metal` compute shader at runtime, runs 1M NSEC3 digests, and checks the first 50 results against the CPU implementation. On non-macOS hosts or with `CGO_ENABLED=0`, use the CPU benchmark instead.

### Report

```bash
./nshunter report --format=json
./nshunter report --format=markdown --domain=example.com
```

Options (`report`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--format` | `json` | Output format: `json` or `markdown` |
| `--domain` | *(empty)* | Domain to report on; when empty, prints latest report |

### Export

```bash
./nshunter export
./nshunter export --domain=example.com --output=reports-example-com.json
```

Options (`export`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--domain` | *(empty)* | Filter exported reports by domain |
| `--output` | *(stdout)* | Output file path for JSON dump |

> [!TIP]
> Use `./nshunter export --output=reports.json` to snapshot your full local history.

## Sample JSON output

```json
{
  "zone": "example.com",
  "analyzed_at": "2026-04-06T18:10:00Z",
  "dnssec_type": "NSEC3",
  "nsec3_params": {
    "hash_algorithm": 1,
    "iterations": 0,
    "salt_hex": "",
    "opt_out": true
  },
  "axfr": {
    "allowed": false,
    "record_count": 0,
    "name_count": 0
  },
  "zone_info": {
    "provider": "XXX",
    "ns": ["ns1.example.net", "ns2.example.net"],
    "mx": ["mail.example.com"],
    "txt_hints": ["SPF include: _spf.google.com", "DMARC policy: reject"]
  },
  "enumeration_sources": {
    "nsec": 0,
    "nsec3_cracked": 12,
    "axfr": 0,
    "ct_logs": 48,
    "bruteforce": 0
  },
  "metrics": {
    "coverage_percent": 2.7,
    "coverage_definition": "fraction of observed NSEC3 hashes cracked from corpus",
    "corpus_label_count": 29202,
    "matched_labels": 12
  },
  "risk": {
    "level": "MEDIUM",
    "rationale": [
      "5000 queries, 446 unique hashes collected",
      "12/446 hashes cracked from corpus (29202 labels tested)",
      "AXFR refused by all nameservers",
      "iterations=0 (RFC 9276 compliant, but hash computation remains cheap)",
      "NSEC3 opt-out enabled — only signed delegations appear in hash chain"
    ]
  },
  "enumerated_names": ["www.example.com", "api.example.com", "mail.example.com"]
}
```

The `axfr`, `zone_info`, and `enumeration_sources` fields are populated when collection allows (e.g. DNSSEC mode, CT data availability, and enabled probes).

## Risk scoring (summary)

The engine combines several signals; levels are `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`.

| Situation | Typical outcome |
|-----------|-----------------|
| No DNSSEC | **HIGH** — no authentication chain for the zone |
| AXFR allowed | **CRITICAL** — full zone can be copied |
| NSEC (full enumeration) | **HIGH** |
| NSEC *black lies* | **LOW** — anti-walking countermeasure |
| NSEC3 — high corpus match vs observed hashes | **HIGH** / **MEDIUM** depending on percentage |
| NSEC3 — `iterations=0` per RFC 9276 | reflected in rationale (not automatically wrong for very large zones) |
| NSEC3 opt-out | noted in report (chain limited to signed delegations) |

Exact rules evolve with the code; trust the report `rationale` fields.

## Tests

```bash
go test ./... -count=1
```

Includes RFC 5155 (NSEC3) vectors, Pebble, and SQLite tests.

> [!NOTE]
> GPU benchmarking (`--gpu`) requires macOS with CGO enabled and Metal available.

## Legal and usage notice

**Use nshunter only on domains you own or for which you have written authorization to test.**

The tool sends real DNS queries to authoritative servers: NSEC / NSEC3 walking (up to `--max-walk` budget), AXFR attempts, and metadata queries. Passive registry calls hit **crt.sh** and optionally **Cert Spotter** / **Censys** HTTPS APIs — keep volume and rate reasonable; services may return `429` / `503` or rate-limit API keys.

This is **not** a large-scale Internet scanning tool.

## Acknowledgments

This project builds on the research and tooling of several people who explored DNSSEC zone enumeration:

- **Aris Adamantiadis** — His SSTIC 2024 talk *"dig .com AXFR +dnssec : Lister l'Internet grâce à DNSSEC"* and the GPU-accelerated [Malifar](https://github.com/arisada/malifar) tool were a direct inspiration for this project. ([presentation](https://www.sstic.org/2024/presentation/dig_com_axfr_dnssec__lister_linternet_grce__dnssec/), [blog post](https://blog.0xbadc0de.be/archives/507))
- **D. J. Bernstein** — The original [nsec3walker](https://dnscurve.org/nsec3walker.html) tool demonstrated practical NSEC3 hash collection and offline cracking.
- **anonion0** — [nsec3map](https://github.com/anonion0/nsec3map), a widely used open-source NSEC/NSEC3 zone enumeration tool.
- **Sharon Goldberg, Moni Naor, Dimitrios Papadopoulos, Leonid Reyzin, Sachin Vasant, Asaf Ziv** — Their work on [NSEC5](https://eprint.iacr.org/2014/582.pdf) formally proved that zone enumeration is inherent to current DNSSEC designs, and proposed a VRF-based alternative.
- **Black Lies"** — Documentation on [DNSSEC "black lies"](https://blog.cloudflare.com/black-lies/), the countermeasure against NSEC zone walking that nshunter detects.

## References

- [RFC 5155 — NSEC3](https://datatracker.ietf.org/doc/html/rfc5155)
- [RFC 9276 — NSEC3 parameters (iterations, salt)](https://datatracker.ietf.org/doc/html/rfc9276)
- [RFC 4034 — DNSSEC resource records](https://datatracker.ietf.org/doc/html/rfc4034)
- Black Lies — [DNSSEC "black lies"](https://blog.cloudflare.com/black-lies/)

## License

MIT — see [LICENSE](LICENSE).
