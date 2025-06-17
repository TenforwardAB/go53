package types

type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeMX    RecordType = "MX"
	TypeNS    RecordType = "NS"
	TypeSOA   RecordType = "SOA"
	TypeCNAME RecordType = "CNAME"
	TypeTXT   RecordType = "TXT"
	TypeSRV   RecordType = "SRV"
	TypePTR   RecordType = "PTR"
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

type ZoneData struct {
	A     map[string]ARecord     `json:"a,omitempty"`
	AAAA  map[string]AAAARecord  `json:"aaaa,omitempty"`
	MX    map[string]MXRecord    `json:"mx,omitempty"`
	SOA   map[string]SOARecord   `json:"soa,omitempty"`
	CNAME map[string]CNAMERecord `json:"cname,omitempty"`
	NS    map[string]NSRecord    `json:"ns,omitempty"`
	SRV   map[string]SRVRecord   `json:"srv,omitempty"`
	TXT   map[string]TXTRecord   `json:"txt,omitempty"`
	PTR   map[string]PTRRecord   `json:"ptr,omitempty"`
}
