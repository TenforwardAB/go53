package dns

import (
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/config"
	"go53/dns/dnsutils"
	"go53/internal"
	"go53/security"
	"go53/zone"
	"log"
	"net"
	"strconv"
	"strings"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.Println("Incomming DNS request")
	live := config.AppConfig.GetLive()
	opt := r.IsEdns0()
	wantsDNSSEC := config.AppConfig.GetLive().DNSSECEnabled && opt != nil && opt.Do()

	if r.Opcode == dns.OpcodeNotify && (live.Mode == "secondary" || live.Dev.DualMode) {
		remoteIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
		if err != nil {
			log.Println("Invalid remote address:", w.RemoteAddr())
			return
		}

		if !strings.HasPrefix(remoteIP, live.Primary.Ip) {
			log.Println("Refusing NOTIFY from unknown IP:", remoteIP)
			return
		}

		tsig := r.IsTsig()
		enforceTSIG := live.EnforceTSIG

		switch {
		case tsig != nil:
			// TSIG is present — must be validated regardless of config is (RFC 2845  §4.6)
			if _, ok := security.GetTSIGKey(tsig.Hdr.Name); !ok {
				log.Printf("TSIG key not recognized: %s — rejecting", tsig.Hdr.Name)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}
			if w.TsigStatus() != nil {
				log.Printf("TSIG validation failed: %v", w.TsigStatus())
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}
			log.Printf("TSIG validated. Key: %s", tsig.Hdr.Name)

		case tsig == nil && enforceTSIG:
			// TSIG is required but not present — reject per RFC 2845 §4.5
			log.Println("TSIG required but not present — rejecting")
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return

		case tsig == nil && !enforceTSIG:
			// TSIG is not  required — continue (RFC 2845  §4.5)
			log.Println("TSIG not present, but not required — continuing")
		}

		dnsutils.HandleNotify(w, r)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = false

	if r.Opcode != dns.OpcodeQuery {
		m.SetRcode(r, dns.RcodeNotImplemented)
		m.Authoritative = false
		writeResponse(w, r, m)
		return
	}

	if opt != nil && opt.Version() != 0 {
		m.SetRcode(r, dns.RcodeBadVers)
		m.Authoritative = false
		writeResponse(w, r, m)
		return
	}

	if len(r.Question) != 1 {
		log.Printf("Refusing DNS request with QDCOUNT=%d; only one question is supported", len(r.Question))
		m.SetRcode(r, dns.RcodeFormatError)
		m.Authoritative = false
		dnsutils.ApplyNSID(m, r)
		_ = w.WriteMsg(m)
		return
	}

	m.Authoritative = true

	for _, q := range r.Question {
		var answered bool
		answered = false
		log.Println("Type is :", q.Qtype)

		if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeTXT && strings.ToLower(q.Name) == "version.bind." {
			version := live.Version
			if version != "" {
				txt := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassCHAOS,
						Ttl:    0,
					},
					Txt: []string{version},
				}
				m.Answer = append(m.Answer, txt)
				answered = true
				continue
			}
		}

		if q.Qclass != dns.ClassINET {
			m.SetRcode(r, dns.RcodeNotImplemented)
			m.Authoritative = false
			answered = true
		}

		if answered {
			continue
		}

		if _, ok := zone.AuthoritativeZoneForName(q.Name); !ok {
			applyUnknownZonePolicy(m, r, live)
			answered = true
		}

		if answered {
			continue
		}

		if delegation, ns, ok := zone.DelegationFor(q.Name); ok && shouldReturnReferral(q, delegation) {
			m.Authoritative = false
			m.Ns = append(m.Ns, ns...)
			m.Extra = append(m.Extra, glueRecords(ns)...)
			answered = true
		}

		if answered {
			if wantsDNSSEC {
				slog.Crazy("Using DNSSEC")
				m.Answer = appendRRSIGs(m.Answer)
				m.Ns = appendRRSIGs(m.Ns)
			}
			continue
		}

		switch q.Qtype {
		case dns.TypeANY:
			applyANYPolicy(m, q, live)
			answered = true

		case dns.TypeDNSKEY:
			zoneApex, _ := internal.SanitizeFQDN(q.Name) //TODO: manage error
			if rec, ok := zone.LookupRecord(dns.TypeDNSKEY, zoneApex); ok {
				log.Println("DNSKEY record found:", rec)
				m.Answer = append(m.Answer, rec...)
				answered = true
			} else {
				log.Println("DNSKEY record NOT FOUND OR ERROR:")
			}

		case dns.TypeCNAME, dns.TypeDNAME, dns.TypeNS:
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				m.Answer = append(m.Answer, rec...)
				answered = true
			}

		case dns.TypeAXFR, dns.TypeIXFR:
			if !live.AllowAXFR {
				log.Println("AXFR/IXFR disabled by configuration")
				m.SetRcode(r, dns.RcodeRefused)
				writeResponse(w, r, m)
				return
			}

			if !transferClientAllowed(w.RemoteAddr().String(), live.AllowTransfer) {
				log.Printf("AXFR/IXFR refused for unauthorized client %s", w.RemoteAddr().String())
				m.SetRcode(r, dns.RcodeRefused)
				writeResponse(w, r, m)
				return
			}

			// RFC 2845 §4.5: If TSIG is present, it MUST be validated. If not present, only require it if EnforceTSIG is true.
			tsig := r.IsTsig()
			enforceTSIG := config.AppConfig.GetLive().EnforceTSIG

			switch {
			case tsig != nil:
				// TSIG present: validate it
				if _, ok := security.GetTSIGKey(tsig.Hdr.Name); !ok {
					log.Printf("TSIG key not recognized: %s — rejecting", tsig.Hdr.Name)
					m.SetRcode(r, dns.RcodeRefused)
					writeResponse(w, r, m)
					return
				}
				if w.TsigStatus() != nil {
					log.Printf("TSIG validation failed: %v", w.TsigStatus())
					m.SetRcode(r, dns.RcodeRefused)
					writeResponse(w, r, m)
					return
				}
				log.Printf("TSIG validated for AXFR/IXFR. Key: %s", tsig.Hdr.Name)

			case tsig == nil && enforceTSIG:
				// TSIG required but missing
				log.Println("AXFR/IXFR request is not TSIG-signed — rejecting due to EnforceTSIG")
				m.SetRcode(r, dns.RcodeRefused)
				writeResponse(w, r, m)
				return

			case tsig == nil && !enforceTSIG:
				// TSIG not present and not required
				log.Println("AXFR/IXFR without TSIG — accepted due to EnforceTSIG=false")
			}

			// Delegate to ServeDNS
			dnsutils.ServeDNS(w, r)
			return

		default:
			result := resolveAnswerChain(q.Name, q.Qtype, wantsDNSSEC)
			if len(result.Answer) > 0 {
				m.Answer = append(m.Answer, result.Answer...)
				m.Ns = append(m.Ns, result.Authority...)
				if result.Rcode != dns.RcodeSuccess {
					m.Rcode = result.Rcode
				}
				answered = true
			}
		}

		if !answered {
			if rec, authority, ok := lookupWildcard(q.Qtype, q.Name, wantsDNSSEC); ok {
				m.Answer = append(m.Answer, rec...)
				m.Ns = append(m.Ns, authority...)
				answered = true
			}
		}

		if !answered {
			nameFound := nameExists(q.Name)
			nxdomain := !nameFound && !zone.WildcardExists(q.Name)
			if nxdomain {
				m.Rcode = dns.RcodeNameError
			}
			if soaRec, ok := lookupApexSOA(q.Name); ok {
				m.Ns = append(m.Ns, soaRec...)
			}
			if wantsDNSSEC {
				m.Ns = append(m.Ns, denialRecords(q.Name, q.Qtype, nxdomain)...)
			}
		}

		if wantsDNSSEC {
			slog.Crazy("Using DNSSEC")
			m.Answer = appendRRSIGs(m.Answer)
			m.Ns = appendRRSIGs(m.Ns)
		}
	}

	dnsutils.ApplyNSID(m, r)
	writeResponse(w, r, m)
}

func writeResponse(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) {
	finalizeResponse(req, resp, responseIsTCP(w))
	_ = w.WriteMsg(resp)
}

func finalizeResponse(req *dns.Msg, resp *dns.Msg, tcp bool) {
	if req == nil || resp == nil {
		return
	}
	resp.RecursionAvailable = false
	live := config.AppConfig.GetLive()
	reqOpt := req.IsEdns0()
	if live.EnableEDNS && reqOpt != nil && resp.IsEdns0() == nil {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		size := reqOpt.UDPSize()
		if live.MaxUDPSize > 0 && (size == 0 || size > uint16(live.MaxUDPSize)) {
			size = uint16(live.MaxUDPSize)
		}
		if size == 0 {
			size = 512
		}
		opt.SetUDPSize(size)
		if reqOpt.Do() {
			opt.SetDo()
		}
		resp.Extra = append(resp.Extra, opt)
	}
	if opt := resp.IsEdns0(); opt != nil && live.MaxUDPSize > 0 && opt.UDPSize() > uint16(live.MaxUDPSize) {
		opt.SetUDPSize(uint16(live.MaxUDPSize))
	}
	if tcp {
		return
	}
	maxSize := 512
	if opt := resp.IsEdns0(); opt != nil {
		maxSize = int(opt.UDPSize())
	}
	if live.MaxUDPSize > 0 && maxSize > live.MaxUDPSize {
		maxSize = live.MaxUDPSize
	}
	if maxSize > 0 {
		resp.Truncate(maxSize)
	}
}

func responseIsTCP(w dns.ResponseWriter) bool {
	switch w.RemoteAddr().(type) {
	case *net.TCPAddr:
		return true
	default:
		return false
	}
}

func applyUnknownZonePolicy(resp *dns.Msg, req *dns.Msg, live config.LiveConfig) {
	if strings.EqualFold(live.UnknownZonePolicy, "nxdomain") {
		resp.SetRcode(req, dns.RcodeNameError)
		resp.Authoritative = false
		return
	}
	resp.SetRcode(req, dns.RcodeRefused)
	resp.Authoritative = false
}

func applyANYPolicy(resp *dns.Msg, q dns.Question, live config.LiveConfig) {
	if strings.EqualFold(live.AnyQueryPolicy, "refuse") {
		resp.Rcode = dns.RcodeRefused
		resp.Authoritative = false
		return
	}
	resp.Answer = append(resp.Answer, &dns.HINFO{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeHINFO,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Cpu: "RFC8482",
		Os:  "ANY-" + strconv.Itoa(int(dns.TypeANY)),
	})
}

func appendRRSIGs(section []dns.RR) []dns.RR {
	seen := make(map[string]bool)
	synthesizedDNAMECNAME := synthesizedDNAMECNAMEs(section)
	for _, rr := range section {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			seen[rr.String()] = true
		}
	}

	covered := make(map[string]bool)
	for _, rr := range section {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		key := strings.ToLower(rrsig.Hdr.Name) + "|" + dns.TypeToString[rrsig.TypeCovered]
		covered[key] = true
	}

	rrsets := make(map[string][]dns.RR)
	for _, rr := range section {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		hdr := rr.Header()
		if hdr.Rrtype == dns.TypeCNAME && synthesizedDNAMECNAME[strings.ToLower(hdr.Name)] {
			continue
		}
		key := strings.ToLower(hdr.Name) + "|" + dns.TypeToString[hdr.Rrtype]
		if covered[key] {
			continue
		}
		rrsets[key] = append(rrsets[key], rr)
	}

	for _, rrset := range rrsets {
		rrsigRecords, err := zone.EnsureSignedRRSet(rrset)
		if err != nil {
			slog.Warn("DNSSEC query-time signing failed: %v", err)
			continue
		}
		for _, sig := range rrsigRecords {
			rrsig, ok := sig.(*dns.RRSIG)
			if !ok {
				continue
			}
			key := rrsig.String()
			if seen[key] {
				continue
			}
			section = append(section, rrsig)
			seen[key] = true
		}
	}

	return section
}

type answerChainResult struct {
	Answer    []dns.RR
	Authority []dns.RR
	Rcode     int
}

func resolveAnswerChain(qname string, qtype uint16, wantsDNSSEC bool) answerChainResult {
	const maxAliasDepth = 8
	result := answerChainResult{Rcode: dns.RcodeSuccess}
	current := dns.Fqdn(qname)
	seen := make(map[string]bool)

	for depth := 0; depth < maxAliasDepth; depth++ {
		key := strings.ToLower(current)
		if seen[key] {
			slog.Warn("alias loop while resolving %s %s", qname, dns.TypeToString[qtype])
			return result
		}
		seen[key] = true

		if rec, ok := zone.LookupRecord(qtype, current); ok {
			result.Answer = append(result.Answer, rec...)
			return result
		}

		if rec, authority, ok := lookupWildcard(qtype, current, wantsDNSSEC); ok {
			result.Answer = append(result.Answer, rec...)
			result.Authority = append(result.Authority, authority...)
			return result
		}

		if cnameRec, ok := zone.LookupRecord(dns.TypeCNAME, current); ok {
			result.Answer = append(result.Answer, cnameRec...)
			cname, ok := firstCNAME(cnameRec)
			if !ok {
				return result
			}
			current = dns.Fqdn(cname.Target)
			continue
		}

		if dnameRec, synthesized, ok := lookupDNAMERewrite(current); ok {
			result.Answer = append(result.Answer, dnameRec...)
			result.Answer = append(result.Answer, synthesized)
			current = dns.Fqdn(synthesized.Target)
			continue
		}

		if len(result.Answer) > 0 && authoritativeForName(current) {
			nxdomain := !nameExists(current) && !zone.WildcardExists(current)
			if nxdomain {
				result.Rcode = dns.RcodeNameError
			}
			if soaRec, ok := lookupApexSOA(current); ok {
				result.Authority = append(result.Authority, soaRec...)
			}
			if wantsDNSSEC {
				result.Authority = append(result.Authority, denialRecords(current, qtype, nxdomain)...)
			}
		}
		return result
	}

	slog.Warn("alias chain too deep while resolving %s %s", qname, dns.TypeToString[qtype])
	return result
}

func firstCNAME(rrs []dns.RR) (*dns.CNAME, bool) {
	for _, rr := range rrs {
		cname, ok := rr.(*dns.CNAME)
		if ok {
			return cname, true
		}
	}
	return nil, false
}

func lookupDNAMERewrite(qname string) ([]dns.RR, *dns.CNAME, bool) {
	owner, dnameRec, ok := closestDNAME(qname)
	if !ok {
		return nil, nil, false
	}
	dname, ok := firstDNAME(dnameRec)
	if !ok {
		return nil, nil, false
	}
	target, ok := dnameRewriteTarget(qname, owner, dname.Target)
	if !ok {
		return nil, nil, false
	}
	return dnameRec, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(qname),
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    dname.Hdr.Ttl,
		},
		Target: target,
	}, true
}

func closestDNAME(qname string) (string, []dns.RR, bool) {
	trimmed := strings.TrimSuffix(strings.ToLower(qname), ".")
	labels := strings.Split(trimmed, ".")
	for i := 1; i < len(labels)-1; i++ {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		if rec, ok := zone.LookupRecord(dns.TypeDNAME, candidate); ok {
			return candidate, rec, true
		}
	}
	return "", nil, false
}

func firstDNAME(rrs []dns.RR) (*dns.DNAME, bool) {
	for _, rr := range rrs {
		dname, ok := rr.(*dns.DNAME)
		if ok {
			return dname, true
		}
	}
	return nil, false
}

func dnameRewriteTarget(qname, owner, target string) (string, bool) {
	qname = strings.TrimSuffix(dns.Fqdn(qname), ".")
	owner = strings.TrimSuffix(dns.Fqdn(owner), ".")
	target = strings.TrimSuffix(dns.Fqdn(target), ".")
	qLower := strings.ToLower(qname)
	ownerLower := strings.ToLower(owner)
	if qLower == ownerLower || !strings.HasSuffix(qLower, "."+ownerLower) {
		return "", false
	}
	prefix := qname[:len(qname)-len(owner)-1]
	if prefix == "" {
		return dns.Fqdn(target), true
	}
	return dns.Fqdn(prefix + "." + target), true
}

func synthesizedDNAMECNAMEs(section []dns.RR) map[string]bool {
	out := make(map[string]bool)
	var dnames []*dns.DNAME
	for _, rr := range section {
		if dname, ok := rr.(*dns.DNAME); ok {
			dnames = append(dnames, dname)
		}
	}
	if len(dnames) == 0 {
		return out
	}
	for _, rr := range section {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		for _, dname := range dnames {
			if _, ok := dnameRewriteTarget(cname.Hdr.Name, dname.Hdr.Name, dname.Target); ok {
				out[strings.ToLower(cname.Hdr.Name)] = true
				break
			}
		}
	}
	return out
}

func authoritativeForName(name string) bool {
	_, ok := lookupApexSOA(name)
	return ok
}

func shouldReturnReferral(q dns.Question, delegation string) bool {
	if strings.EqualFold(q.Name, delegation) && q.Qtype == dns.TypeDS {
		return false
	}
	return true
}

func glueRecords(nsRecords []dns.RR) []dns.RR {
	var out []dns.RR
	seen := make(map[string]bool)
	for _, rr := range nsRecords {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		if !inBailiwickGlue(ns.Ns, ns.Hdr.Name) {
			continue
		}
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			records, ok := zone.LookupRecord(rrtype, ns.Ns)
			if !ok {
				continue
			}
			for _, glue := range records {
				key := glue.String()
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, glue)
			}
		}
	}
	return out
}

func inBailiwickGlue(target, delegation string) bool {
	target = strings.ToLower(dns.Fqdn(target))
	delegation = strings.ToLower(dns.Fqdn(delegation))
	return target == delegation || strings.HasSuffix(target, "."+delegation)
}

func lookupWildcard(rrtype uint16, qname string, wantsDNSSEC bool) ([]dns.RR, []dns.RR, bool) {
	if nameExists(qname) {
		return nil, nil, false
	}
	wildcard, ok := zone.WildcardName(qname)
	if !ok {
		return nil, nil, false
	}

	if rec, ok := zone.LookupRecord(rrtype, wildcard); ok {
		return synthesizeWildcard(qname, rec, wantsDNSSEC), wildcardDenialAuthority(qname, rrtype, wantsDNSSEC), true
	}
	if rrtype != dns.TypeCNAME {
		if rec, ok := zone.LookupRecord(dns.TypeCNAME, wildcard); ok {
			return synthesizeWildcard(qname, rec, wantsDNSSEC), wildcardDenialAuthority(qname, rrtype, wantsDNSSEC), true
		}
	}
	return nil, nil, false
}

func wildcardDenialAuthority(qname string, rrtype uint16, wantsDNSSEC bool) []dns.RR {
	if !wantsDNSSEC {
		return nil
	}
	return denialRecords(qname, rrtype, false)
}

func synthesizeWildcard(qname string, wildcardRRSet []dns.RR, wantsDNSSEC bool) []dns.RR {
	var out []dns.RR
	for _, rr := range wildcardRRSet {
		copied := dns.Copy(rr)
		copied.Header().Name = dns.Fqdn(qname)
		out = append(out, copied)
	}

	if !wantsDNSSEC {
		return out
	}
	rrsigRecords, err := zone.EnsureSignedRRSet(wildcardRRSet)
	if err != nil {
		slog.Warn("DNSSEC wildcard signing failed: %v", err)
		return out
	}
	for _, sig := range rrsigRecords {
		rrsig, ok := dns.Copy(sig).(*dns.RRSIG)
		if !ok {
			continue
		}
		rrsig.Hdr.Name = dns.Fqdn(qname)
		out = append(out, rrsig)
	}
	return out
}

func lookupApexSOA(name string) ([]dns.RR, bool) {
	apex, ok := zone.AuthoritativeZoneForName(name)
	if !ok {
		return nil, false
	}
	return zone.LookupRecord(dns.TypeSOA, apex)
}

func denialRecords(name string, qtype uint16, nxdomain bool) []dns.RR {
	return zone.DenialProofs(name, qtype, nxdomain)
}

func nameExists(name string) bool {
	return zone.NameExists(name)
}

func transferClientAllowed(remoteAddr string, allowTransfer string) bool {
	allowTransfer = strings.TrimSpace(allowTransfer)
	if allowTransfer == "" {
		return true
	}

	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}
	remote := net.ParseIP(remoteIP)
	if remote == nil {
		return false
	}

	for _, entry := range strings.Split(allowTransfer, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if ip := net.ParseIP(entry); ip != nil {
			if ip.Equal(remote) {
				return true
			}
			continue
		}

		if ip, _, err := net.SplitHostPort(entry); err == nil {
			if parsed := net.ParseIP(ip); parsed != nil && parsed.Equal(remote) {
				return true
			}
		}
	}

	return false
}
