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
// Created on 6/24/25 by andrek <andre(-at-)sess.se>
//
// This file: spf.go is part of the go53 authoritative DNS server.

package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type SPFRecord struct{}

func (SPFRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("SPFRecord expects value to be a JSON object, got %T", value)
	}

	rawText, ok := m["text"]
	if !ok {
		return fmt.Errorf("SPFRecord expects field 'text'")
	}
	text, ok := rawText.(string)
	if !ok {
		return fmt.Errorf("SPFRecord: field 'text' must be a string, got %T", rawText)
	}

	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	rec := types.SPFRecord{
		Text: text,
		TTL:  TTL,
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeSPF), name, rec)
}

func (SPFRecord) Lookup(host string) ([]dns.RR, bool) {
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

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeSPF), name)
	if !ok {
		return nil, false
	}

	var rec types.SPFRecord
	switch v := val.(type) {
	case types.SPFRecord:
		rec = v
	case map[string]interface{}:
		rec = types.SPFRecord{}
		if txt, ok := v["text"].(string); ok {
			rec.Text = txt
		}
		if t, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(t)
		}
	default:
		return nil, false
	}

	if rec.Text == "" {
		return nil, false
	}

	return []dns.RR{
		&dns.SPF{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeSPF,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Txt: []string{rec.Text},
		},
	}, true
}

func (SPFRecord) Delete(host string, value interface{}) error {
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

	// Only one SPF per name allowed
	return memStore.DeleteRecord(sanitizedZone, string(types.TypeSPF), name)
}

func (SPFRecord) Type() uint16 {
	return dns.TypeSPF
}

func init() {
	Register(SPFRecord{})
}
