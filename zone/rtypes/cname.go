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
// Created on 6/3/25 by andrek <andre(-at-)sess.se>
//
// This file: cname.go is part of the go53 authoritative DNS server.
package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type CNAMERecord struct{}

func (CNAMERecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("CNAMERecord expects value to be a JSON object, got %T", value)
	}

	rawTarget, ok := m["target"]
	if !ok {
		return fmt.Errorf("CNAMERecord expects field 'target'")
	}
	target, ok := rawTarget.(string)
	if !ok {
		return fmt.Errorf("CNAMERecord: field 'target' must be a string, got %T", rawTarget)
	}

	sanitizedTarget, err := internal.SanitizeFQDN(target)
	if err != nil {
		return fmt.Errorf("CNAMERecord: invalid target FQDN %q", target)
	}

	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	if exists, other := internal.HasOtherRecords(memStore, sanitizedZone, name, dns.TypeCNAME, GetRegistry()); exists {
		return fmt.Errorf("CNAME: other record of type %d exists", other)
	}

	rec := types.CNAMERecord{
		Target: sanitizedTarget,
		TTL:    TTL,
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeCNAME), name, rec)
}

func (CNAMERecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, false
	}
	if memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeCNAME), name)
	if !ok {
		return nil, false
	}

	var rec types.CNAMERecord
	switch v := val.(type) {
	case types.CNAMERecord:
		rec = v
	case map[string]interface{}:
		rec = types.CNAMERecord{}
		if tgt, ok := v["target"].(string); ok {
			rec.Target = tgt
		}
		if t, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(t)
		}
	default:
		return nil, false
	}

	if rec.Target == "" {
		return nil, false
	}

	return []dns.RR{
		&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Target: rec.Target,
		},
	}, true
}

func (CNAMERecord) Delete(host string, value interface{}) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	// oavsett value, det finns bara en möjlig CNAME-post per namn
	return memStore.DeleteRecord(sanitizedZone, string(types.TypeCNAME), name)
}

func (CNAMERecord) Type() uint16 {
	return dns.TypeCNAME
}

func init() {
	Register(CNAMERecord{})
}
