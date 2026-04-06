// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

type NSEC3Params struct {
	Algorithm  uint8
	Flags      uint8
	Iterations uint16
	SaltHex    string
}

type NSEC3Record struct {
	HashedOwner string
	NextHashed  string
	Types       []uint16
	Zone        string
}

type NSECRecord struct {
	Owner     string
	NextOwner string
	Types     []uint16
}

type AXFRResult struct {
	Allowed     bool
	Nameserver  string
	RecordCount int
	Names       []string
	Records     []AXFRRecord
}

type AXFRRecord struct {
	Name  string
	Type  string
	TTL   uint32
	Value string
}

type DNSSECResult struct {
	Domain          string
	HasDNSSEC       bool
	BlackLies       bool
	NSEC3Params     *NSEC3Params
	NSEC3Records    []NSEC3Record
	NSEC3Walk       *NSEC3WalkResult
	NSECRecords     []NSECRecord
	EnumeratedNames []string
	AXFR            *AXFRResult
	CTNames         []string // merged subdomains from passive certificate registries
	Registry        *RegistryBreakdown
	BruteNames      []string // subdomains confirmed via DNS bruteforce
	Metadata        *ZoneMetadata
	DNSKEYCount     int
	RRSIGCount      int
}

type ZoneMetadata struct {
	SOA       string   `json:"soa,omitempty"`
	MXRecords []string `json:"mx,omitempty"`
	TXTHints  []string `json:"txt_hints,omitempty"` // SPF includes, DMARC, etc.
	NSRecords []string `json:"ns,omitempty"`
	Provider  string   `json:"provider,omitempty"` // detected hosting (Cloudflare, Akamai, etc.)
}

// CollectOptions controls which enumeration approaches are executed.
type CollectOptions struct {
	DisableAXFR      bool
	DisableNSEC      bool
	DisableNSEC3     bool
	DisableRegistry  bool // Certificate Transparency registry (e.g. crt.sh)
	DisableMetaHosts bool // do not merge in-zone NS/MX into EnumeratedNames
}
