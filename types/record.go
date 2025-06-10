package types

type RecordType string

const (
	TypeA    RecordType = "A"
	TypeAAAA RecordType = "AAAA"
	TypeMX   RecordType = "MX"
	TypeNS   RecordType = "NS"
	TypeSOA  RecordType = "SOA"
)

type ARecord struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	TTL  uint32 `json:"ttl"`
}

type AAAARecord struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	TTL  uint32 `json:"ttl"`
}

type MXRecord struct {
	Name     string `json:"name"`
	Priority uint16 `json:"priority"`
	Server   string `json:"server"`
	TTL      uint32 `json:"ttl"`
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

type ZoneData struct {
	A    map[string]ARecord    `json:"a,omitempty"`
	AAAA map[string]AAAARecord `json:"aaaa,omitempty"`
	MX   map[string]MXRecord   `json:"mx,omitempty"`
	SOA  map[string]SOARecord  `json:"soa,omitempty"`
}
