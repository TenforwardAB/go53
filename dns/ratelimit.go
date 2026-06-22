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
// This file: ratelimit.go is part of the go53 authoritative DNS server.
package dns

import (
	"sync"
	"time"
)

// clientLimiter is a tiny per-source-IP token bucket used to cap query rate.
// Each client refills at qps tokens per second up to a burst of qps, so a
// client may send up to qps queries per second (with a one-second burst)
// before being throttled. Idle buckets are reclaimed by sweep so memory stays
// bounded under spoofed-source floods.
type clientLimiter struct {
	mu      sync.Mutex
	clients map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// maxClients caps how many distinct source IPs we track at once. It bounds
// memory so a spoofed-source UDP flood cannot grow the map without limit and
// turn the limiter itself into a DoS vector. When the cap is reached, new IPs
// are not tracked and are allowed through (fail-open): single-packet spoofed
// sources would never have been throttled anyway, while already-tracked real
// clients keep being limited correctly.
const maxClients = 100_000

var limiter = &clientLimiter{clients: make(map[string]*bucket)}

// allow reports whether a query from ip may proceed given qps. qps <= 0
// disables limiting (always allowed).
func (l *clientLimiter) allow(ip string, qps int, now time.Time) bool {
	if qps <= 0 {
		return true
	}
	rate := float64(qps)

	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.clients[ip]
	if b == nil {
		// Cap tracked clients so a spoofed-source flood cannot exhaust memory.
		// New IPs beyond the cap are allowed without being tracked.
		if len(l.clients) >= maxClients {
			return true
		}
		b = &bucket{tokens: rate, last: now}
		l.clients[ip] = b
	}

	// Refill proportionally to elapsed time, capped at the burst size.
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > rate {
		b.tokens = rate
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets untouched for longer than idle, bounding map growth.
func (l *clientLimiter) sweep(now time.Time, idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.clients {
		if now.Sub(b.last) > idle {
			delete(l.clients, ip)
		}
	}
}

// startLimiterCleanup periodically reclaims idle client buckets. It runs for
// the lifetime of the process and is started once from the DNS server setup.
func startLimiterCleanup() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		limiter.sweep(time.Now(), 10*time.Minute)
	}
}
