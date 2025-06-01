package zone

import (
	"github.com/miekg/dns"
	"go53/zone/types"
)

// A
func AddARecord(name, ip string) {
	types.AddA(name, ip)
}
func LookupA(name string) *dns.A {
	return types.LookupA(name)
}
func DeleteARecord(name string) {
	types.DeleteA(name)
}

// AAAA
func AddAAAARecord(name, ip string) {
	types.AddAAAA(name, ip)
}
func LookupAAAA(name string) *dns.AAAA {
	return types.LookupAAAA(name)
}
func DeleteAAAARecord(name string) {
	types.DeleteAAAA(name)
}

// MX
func AddMXRecord(name string, preference uint16, mx string) {
	types.AddMX(name, preference, mx)
}
func LookupMX(name string) []*dns.MX {
	return types.LookupMX(name)
}
func DeleteMXRecord(name string) {
	types.DeleteMX(name)
}

// TXT
func AddTXTRecord(name string, txts ...string) {
	types.AddTXT(name, txts...)
}
func LookupTXT(name string) []*dns.TXT {
	return types.LookupTXT(name)
}
func DeleteTXTRecord(name string) {
	types.DeleteTXT(name)
}

// CNAME
func AddCNAMERecord(name, target string) {
	types.AddCNAME(name, target)
}
func LookupCNAME(name string) *dns.CNAME {
	return types.LookupCNAME(name)
}
func DeleteCNAMERecord(name string) {
	types.DeleteCNAME(name)
}

// DNAME
func AddDNAMERecord(name, target string) {
	types.AddDNAME(name, target)
}

func LookupDNAME(name string) *dns.DNAME {
	return types.LookupDNAME(name)
}

func DeleteDNAMERecord(name string) {
	types.DeleteDNAME(name)
}

// PTR
func AddPTRRecord(name, ptr string) {
	types.AddPTR(name, ptr)
}
func LookupPTR(name string) *dns.PTR {
	return types.LookupPTR(name)
}
func DeletePTRRecord(name string) {
	types.DeletePTR(name)
}

// NS
func AddNSRecord(name, ns string) {
	types.AddNS(name, ns)
}
func LookupNS(name string) []*dns.NS {
	return types.LookupNS(name)
}
func DeleteNSRecord(name string) {
	types.DeleteNS(name)
}

// SOA
func AddSOARecord(name, ns, mbox string, serial, refresh, retry, expire, minttl uint32) {
	types.AddSOA(name, ns, mbox, serial, refresh, retry, expire, minttl)
}
func LookupSOA(name string) *dns.SOA {
	return types.LookupSOA(name)
}
func DeleteSOARecord(name string) {
	types.DeleteSOA(name)
}
