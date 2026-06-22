// Package dns
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
// This file: ratelimit_test.go is part of the go53 authoritative DNS server.
package dns

import (
	"strconv"
	"testing"
	"time"
)

func TestClientLimiter(t *testing.T) {
	now := time.Unix(0, 0)

	t.Run("qps<=0 always allows", func(t *testing.T) {
		l := &clientLimiter{clients: map[string]*bucket{}}
		for i := 0; i < 1000; i++ {
			if !l.allow("1.2.3.4", 0, now) {
				t.Fatal("qps=0 should never throttle")
			}
		}
	})

	t.Run("burst then throttle", func(t *testing.T) {
		l := &clientLimiter{clients: map[string]*bucket{}}
		const qps = 5
		for i := 0; i < qps; i++ {
			if !l.allow("1.2.3.4", qps, now) {
				t.Fatalf("request %d within burst should be allowed", i)
			}
		}
		if l.allow("1.2.3.4", qps, now) {
			t.Fatal("request beyond burst should be throttled")
		}
	})

	t.Run("refills over time", func(t *testing.T) {
		l := &clientLimiter{clients: map[string]*bucket{}}
		const qps = 5
		for i := 0; i < qps; i++ {
			l.allow("1.2.3.4", qps, now)
		}
		if l.allow("1.2.3.4", qps, now) {
			t.Fatal("bucket should be empty")
		}
		// One second later a full burst is available again.
		later := now.Add(time.Second)
		if !l.allow("1.2.3.4", qps, later) {
			t.Fatal("bucket should have refilled after 1s")
		}
	})

	t.Run("clients are independent", func(t *testing.T) {
		l := &clientLimiter{clients: map[string]*bucket{}}
		const qps = 1
		if !l.allow("1.1.1.1", qps, now) {
			t.Fatal("first client first request should pass")
		}
		if !l.allow("2.2.2.2", qps, now) {
			t.Fatal("second client should not be affected by the first")
		}
	})

	t.Run("caps tracked clients and fails open beyond the cap", func(t *testing.T) {
		l := &clientLimiter{clients: map[string]*bucket{}}
		// Fill the map to capacity with distinct IPs.
		for i := 0; i < maxClients; i++ {
			l.allow("filler-"+strconv.Itoa(i), 1, now)
		}
		if len(l.clients) != maxClients {
			t.Fatalf("expected %d tracked clients, got %d", maxClients, len(l.clients))
		}
		// A brand-new IP is allowed but not tracked (memory stays bounded).
		if !l.allow("9.9.9.9", 1, now) {
			t.Fatal("new IP beyond cap should fail open (be allowed)")
		}
		if len(l.clients) != maxClients {
			t.Fatalf("map must not grow past cap, got %d", len(l.clients))
		}
	})

	t.Run("sweep reclaims idle buckets", func(t *testing.T) {
		l := &clientLimiter{clients: map[string]*bucket{}}
		l.allow("1.2.3.4", 5, now)
		l.sweep(now.Add(11*time.Minute), 10*time.Minute)
		if len(l.clients) != 0 {
			t.Fatalf("idle bucket should have been swept, have %d", len(l.clients))
		}
	})
}
