package types

type RecordType string

const (
	TypeA      RecordType = "A"
	TypeAAAA   RecordType = "AAAA"
	TypeMX     RecordType = "MX"
	TypeNS     RecordType = "NS"
	TypeSOA    RecordType = "SOA"
	TypeCNAME  RecordType = "CNAME"
	TypeTXT    RecordType = "TXT"
	TypeSRV    RecordType = "SRV"
	TypePTR    RecordType = "PTR"
	TypeCAA    RecordType = "CAA"
	TypeDNSKEY RecordType = "DNSKEY"
	TypeRRSIG  RecordType = "RRSIG"
	TypeNSEC   RecordType = "NSEC"
	TypeNSEC3  RecordType = "NSEC3"
	TypeDS     RecordType = "DS"
	TypeNAPTR  RecordType = "NAPTR"
	TypeSPF    RecordType = "SPF"
	TypeHTTPS  RecordType = "HTTPS"
	TypeSVCB   RecordType = "SVCB"
	TypeLOC    RecordType = "LOC"
	TypeCERT   RecordType = "CERT"
	TypeSSHFP  RecordType = "SSHFP"
	TypeURI    RecordType = "URI"
	TypeAPL    RecordType = "APL"
	TypeDNAME  RecordType = "DNAME"
)

type ARecord struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl"`
}

type AAAARecord struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl"`
}
type NSRecord struct {
	NS  string `json:"ns"`
	TTL uint32 `json:"ttl"`
}

type TXTRecord struct {
	Text string `json:"text"`
	TTL  uint32 `json:"ttl"`
}

type SRVRecord struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
	TTL      uint32 `json:"ttl"`
}

type MXRecord struct {
	Priority uint16 `json:"priority"`
	Host     string `json:"host"`
	TTL      uint32 `json:"ttl"`
}

type PTRRecord struct {
	Ptr string `json:"ptr"`
	TTL uint32 `json:"ttl"`
}

type SOARecord struct {
	Ns      string `json:"ns"`
	Mbox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
	TTL     uint32 `json:"ttl"`
}

type CNAMERecord struct {
	Target string `json:"target"`
	TTL    uint32 `json:"ttl"`
}

type DNAMERecord struct {
	Target string `json:"target"`
	TTL    uint32 `json:"ttl"`
}

type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type DNSKEYRecord struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"public_key"`
	TTL       uint32 `json:"ttl"`
}

type RRSIGRecord struct {
	Name        string `json:"name"`         // <-- not wire, just internal
	TypeCovered string `json:"type_covered"` // e.g., "A", "NS", etc.
	Algorithm   uint8  `json:"algorithm"`
	Labels      uint8  `json:"labels"`
	OrigTTL     uint32 `json:"original_ttl"`
	Expiration  uint32 `json:"expiration"` // Unix timestamp
	Inception   uint32 `json:"inception"`  // Unix timestamp
	KeyTag      uint16 `json:"key_tag"`
	SignerName  string `json:"signer_name"` // FQDN of signer
	Signature   string `json:"signature"`   // Base64-encoded
	TTL         uint32 `json:"ttl"`
}

type NSECRecord struct {
	NextDomain string   `json:"next_domain"`
	Types      []string `json:"types"` // ["A", "NS", "SOA"...]
	TTL        uint32   `json:"ttl"`
}

type NSEC3Record struct {
	HashAlg    uint8    `json:"hash_algorithm"` // Usually 1 (SHA-1)
	Flags      uint8    `json:"flags"`          // Opt-out bit
	Iterations uint16   `json:"iterations"`     // Hash iterations
	Salt       string   `json:"salt"`           // Hex-encoded
	NextHashed string   `json:"next_hashed"`    // Base32-encoded
	Types      []string `json:"types"`          // e.g., ["A", "NS"]
	TTL        uint32   `json:"ttl"`
}

type DSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"` //hex
	TTL        uint32 `json:"ttl"`
}

type NAPTRRecord struct {
	Order       uint16 `json:"order"`
	Preference  uint16 `json:"preference"`
	Flags       string `json:"flags"`
	Service     string `json:"service"`
	Regexp      string `json:"regexp"`
	Replacement string `json:"replacement"`
	TTL         uint32 `json:"ttl"`
}

type SPFRecord struct {
	Text string `json:"text"`
	TTL  uint32 `json:"ttl"`
}

type HTTPSRecord struct {
	Priority uint16            `json:"priority"`
	Target   string            `json:"target"`
	Params   map[string]string `json:"params"`
	TTL      uint32            `json:"ttl"`
}

type SVCBRecord struct {
	Priority uint16            `json:"priority"`
	Target   string            `json:"target"`
	Params   map[string]string `json:"params"`
	TTL      uint32            `json:"ttl"`
}

type LOCRecord struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Altitude  float64 `json:"altitude"`
	Size      float64 `json:"size"`
	TTL       uint32  `json:"ttl"`
}

type CERTRecord struct {
	Type      uint16 `json:"type"`
	KeyTag    uint16 `json:"key_tag"`
	Algorithm uint8  `json:"algorithm"`
	Cert      string `json:"cert"`
	TTL       uint32 `json:"ttl"`
}

type SSHFPRecord struct {
	Algorithm       uint8  `json:"algorithm"`        // 1=RSA, 2=DSA, 3=ECDSA, 4=ED25519
	FingerprintType uint8  `json:"fingerprint_type"` // 1=SHA-1, 2=SHA-256
	Fingerprint     string `json:"fingerprint"`      // hex
	TTL             uint32 `json:"ttl"`
}

type URIRecord struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Target   string `json:"target"`
	TTL      uint32 `json:"ttl"`
}

type APLRecord struct {
	AddressFamily uint16 `json:"address_family"` // 1=IPv4, 2=IPv6
	Prefix        string `json:"prefix"`         // ex: 192.0.2.0/24?
	Negation      bool   `json:"negation"`       // true = ! prefix
	TTL           uint32 `json:"ttl"`
}

type ZoneData struct {
	A      map[string][]ARecord      `json:"a,omitempty"`
	AAAA   map[string][]AAAARecord   `json:"aaaa,omitempty"`
	MX     map[string][]MXRecord     `json:"mx,omitempty"`
	SOA    *SOARecord                `json:"soa,omitempty"` // Only one per zone
	CNAME  map[string]CNAMERecord    `json:"cname,omitempty"`
	NS     map[string][]NSRecord     `json:"ns,omitempty"`
	SRV    map[string][]SRVRecord    `json:"srv,omitempty"`
	TXT    map[string][]TXTRecord    `json:"txt,omitempty"`
	PTR    map[string][]PTRRecord    `json:"ptr,omitempty"`
	CAA    map[string][]CAARecord    `json:"caa,omitempty"`
	DNSKEY map[string][]DNSKEYRecord `json:"dnskey,omitempty"`
	RRSIG  map[string][]*RRSIGRecord `json:"rrsig,omitempty"`
	NSEC   map[string]NSECRecord     `json:"nsec,omitempty"`  // one per name
	NSEC3  map[string]NSEC3Record    `json:"nsec3,omitempty"` // one per name
	DS     map[string][]DSRecord     `json:"ds,omitempty"`
	NAPTR  map[string][]NAPTRRecord  `json:"naptr,omitempty"`
	SPF    map[string]SPFRecord      `json:"spf,omitempty"`
	HTTPS  map[string][]HTTPSRecord  `json:"https,omitempty"`
	SVCB   map[string][]SVCBRecord   `json:"svcb,omitempty"`
	LOC    map[string][]LOCRecord    `json:"loc,omitempty"`
	CERT   map[string][]CERTRecord   `json:"cert,omitempty"`
	SSHFP  map[string][]SSHFPRecord  `json:"sshfp,omitempty"`
	URI    map[string][]URIRecord    `json:"uri,omitempty"`
	APL    map[string][]APLRecord    `json:"apl,omitempty"`
	DNAME  map[string]DNAMERecord    `json:"dname,omitempty"`
}

type StoredKey struct {
	KeyTag     uint16 `json:"key_tag"`     // Needed for DS and RRSIG
	Zone       string `json:"zone"`        // Used for signer name, key publishing
	Algorithm  string `json:"algorithm"`   // "ECDSAP256", "RSASHA256", etc.
	Flags      uint16 `json:"flags"`       // 256 = ZSK, 257 = KSK
	PrivatePEM string `json:"private_pem"` // PEM-encoded EC/RSA key
	PublicKey  string `json:"public_key"`  // Optional: base64 DNSKEY string
}
