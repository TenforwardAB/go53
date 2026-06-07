// This file is part of the go53 project.
//
// This file is licensed under the European Union Public License (EUPL) v1.2.
// You may only use this work in compliance with the License.
// You may obtain a copy of the License at:
//
//	https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed "as is",
// without any warranty or conditions of any kind.
//
// Copyleft (c) 2025 - Tenforward AB. All rights reserved.
//
// Created on 6/6/26 by andrek <andre(-at-)sess.se>
//
// This file: edns.go is part of the go53 authoritative DNS server.
package dnsutils

import (
	"encoding/hex"

	"github.com/miekg/dns"
	"go53/config"
)

// ApplyNSID adds an EDNS0 NSID (Name Server Identifier, option code 3, RFC 5001)
// option to the response message when the client requested it.
//
// Per RFC 5001 the server only includes NSID data when the client signalled
// interest by sending an (empty) NSID option in its query. This helper therefore
// stays silent unless every condition is met:
//
//  1. EDNS is enabled in the live configuration.
//  2. The request carried an OPT record.
//  3. The request OPT contained an NSID option (code 3).
//  4. A non-empty NSID string is configured.
//
// The configured NSID is plain text in the configuration but miekg/dns expects
// the EDNS0_NSID.Nsid field to be hex-encoded, so the value is hex-encoded here
// (e.g. "node-a" -> "6e6f64652d61").
//
// Parameters:
//   - resp: The response *dns.Msg that will be sent to the client.
//   - req:  The incoming *dns.Msg from the client.
func ApplyNSID(resp *dns.Msg, req *dns.Msg) {
	if resp == nil || req == nil {
		return
	}

	live := config.AppConfig.GetLive()
	if !live.EnableEDNS {
		return
	}
	if live.NSID == "" {
		return
	}

	reqOpt := req.IsEdns0()
	if reqOpt == nil || !requestWantsNSID(reqOpt) {
		return
	}

	nsidOption := &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
		Nsid: hex.EncodeToString([]byte(live.NSID)),
	}

	opt := responseOPT(resp, reqOpt)
	opt.Option = append(opt.Option, nsidOption)
}

// requestWantsNSID reports whether the client's OPT record carried an NSID
// option, which is how a resolver opts in to receiving the server identifier.
func requestWantsNSID(opt *dns.OPT) bool {
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_NSID); ok {
			return true
		}
	}
	return false
}

// responseOPT returns the OPT record on the response, creating one if needed.
// When created it mirrors the requester's advertised UDP buffer size and DO bit
// so existing EDNS behaviour is preserved.
func responseOPT(resp *dns.Msg, reqOpt *dns.OPT) *dns.OPT {
	if opt := resp.IsEdns0(); opt != nil {
		return opt
	}

	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(reqOpt.UDPSize())
	if reqOpt.Do() {
		opt.SetDo()
	}
	resp.Extra = append(resp.Extra, opt)
	return opt
}
