package zone

import (
	"github.com/miekg/dns"
	"go53/types"
	"go53/zone/rtypes"
)

// A
func AddARecord(zone, name, ip string) {
	rtypes.AddA(zone, name, ip, nil)
}
func LookupA(name string) (*dns.A, bool) {
	return rtypes.LookupA(name)
}
func DeleteARecord(name string) {
	rtypes.DeleteA(name)
}

// AAAA
func AddAAAARecord(zone, name, ip string) {
	rtypes.AddAAAA(zone, name, ip, nil)
}
func LookupAAAA(name string) (*dns.AAAA, bool) {
	return rtypes.LookupAAAA(name)
}
func DeleteAAAARecord(name string) {
	rtypes.DeleteAAAA(name)
}

// MX
func AddMXRecord(zone, name string, records []types.MXRecord) {
	rtypes.AddMX(zone, name, records)
}
func LookupMX(name string) ([]*dns.MX, bool) {
	return rtypes.LookupMX(name)
}
func DeleteMXRecord(name string) {
	rtypes.DeleteMX(name)
}

//// TXT
//func AddTXTRecord(name string, txts ...string) {
//	rtypes.AddTXT(name, txts...)
//}
//func LookupTXT(name string) []*dns.TXT {
//	return rtypes.LookupTXT(name)
//}
//func DeleteTXTRecord(name string) {
//	rtypes.DeleteTXT(name)
//}
//
//// CNAME
//func AddCNAMERecord(name, target string) {
//	rtypes.AddCNAME(name, target)
//}
//func LookupCNAME(name string) *dns.CNAME {
//	return rtypes.LookupCNAME(name)
//}
//func DeleteCNAMERecord(name string) {
//	rtypes.DeleteCNAME(name)
//}
//
//// DNAME
//func AddDNAMERecord(name, target string) {
//	rtypes.AddDNAME(name, target)
//}
//
//func LookupDNAME(name string) *dns.DNAME {
//	return rtypes.LookupDNAME(name)
//}
//
//func DeleteDNAMERecord(name string) {
//	rtypes.DeleteDNAME(name)
//}
//
//// PTR
//func AddPTRRecord(name, ptr string) {
//	rtypes.AddPTR(name, ptr)
//}
//func LookupPTR(name string) *dns.PTR {
//	return rtypes.LookupPTR(name)
//}
//func DeletePTRRecord(name string) {
//	rtypes.DeletePTR(name)
//}
//
//// NS
//func AddNSRecord(name, ns string) {
//	rtypes.AddNS(name, ns)
//}
//func LookupNS(name string) []*dns.NS {
//	return rtypes.LookupNS(name)
//}
//func DeleteNSRecord(name string) {
//	rtypes.DeleteNS(name)
//}
//
//// SOA
//func AddSOARecord(name, ns, mbox string, serial, refresh, retry, expire, minttl uint32) {
//	rtypes.AddSOA(name, ns, mbox, serial, refresh, retry, expire, minttl)
//}
//func LookupSOA(name string) *dns.SOA {
//	return rtypes.LookupSOA(name)
//}
//func DeleteSOARecord(name string) {
//	rtypes.DeleteSOA(name)
//}
