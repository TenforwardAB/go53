package types

type RecordType string

const (
	TypeA    RecordType = "A"
	TypeAAAA RecordType = "AAAA"
	TypeMX   RecordType = "MX"
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

type ZoneData struct {
	A    map[string]ARecord    `json:"a,omitempty"`
	AAAA map[string]AAAARecord `json:"aaaa,omitempty"`
	MX   map[string]MXRecord   `json:"mx,omitempty"`
}
