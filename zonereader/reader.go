package zonereader

import "github.com/miekg/dns"

var LookupRecordFunc func(rrtype uint16, name string) ([]dns.RR, bool)

func LookupRecord(rrtype uint16, name string) ([]dns.RR, bool) {
	if LookupRecordFunc == nil {
		return nil, false
	}
	return LookupRecordFunc(rrtype, name)
}
