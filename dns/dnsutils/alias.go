package dnsutils

import (
	"context"
	"log/slog"
	mrand "math/rand"
	"net"
	"sort"
	"time"

	"go53/config"
	"go53/distributed"
	"go53/types"
	"go53/zone/rtypes"
)

const (
	aliasSweepInterval   = 60 * time.Second
	aliasResolveTimeout  = 3 * time.Second
	aliasFreshnessWindow = 2 * aliasSweepInterval
)

var aliasLookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

var aliasNow = time.Now

func StartAliasFlattener(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(mrand.Int63n(int64(aliasSweepInterval)))):
		}
		FlattenAliases(ctx)
		ticker := time.NewTicker(aliasSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				FlattenAliases(ctx)
			}
		}
	}()
}

func FlattenAliases(ctx context.Context) {
	if config.AppConfig.GetLive().Mode == "secondary" {
		return
	}
	store := rtypes.GetMemStore()
	if store == nil {
		return
	}
	for _, zoneName := range store.ZoneNamesSnapshot() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		flattenZoneAliases(ctx, zoneName)
	}
}

func flattenZoneAliases(ctx context.Context, zoneName string) {
	store := rtypes.GetMemStore()
	snap := store.ZoneRecordsSnapshot(zoneName)
	aliases := snap[string(types.TypeALIAS)]

	changed := false
	for name := range aliases {
		rec, ok := rtypes.GetALIAS(zoneName, name)
		if !ok {
			continue
		}
		if reconcileAliasFamily(ctx, zoneName, name, string(types.TypeA), "ip4", rec, snap) {
			changed = true
		}
		if reconcileAliasFamily(ctx, zoneName, name, string(types.TypeAAAA), "ip6", rec, snap) {
			changed = true
		}
	}

	if cleanupOrphanedFlattened(zoneName, snap, aliases) {
		changed = true
	}

	if changed {
		if err := UpdateSOASerial(zoneName); err != nil {
			slog.Warn("alias flatten: SOA serial update failed for %s: %v", zoneName, err)
		}
		publishStoredRecord(zoneName, string(types.TypeSOA), "@")
		go ScheduleNotify(zoneName)
	}
}

func reconcileAliasFamily(ctx context.Context, zoneName, name, rtype, network string, rec types.ALIASRecord, snap map[string]map[string]any) bool {
	rctx, cancel := context.WithTimeout(ctx, aliasResolveTimeout)
	ips, err := aliasLookupIP(rctx, network, rec.Target)
	cancel()
	if err != nil {
		return false
	}

	desired := make([]string, 0, len(ips))
	seen := map[string]bool{}
	for _, ip := range ips {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			desired = append(desired, s)
		}
	}
	sort.Strings(desired)

	current := currentFlattenedState(snap, rtype, name)
	if equalStringSlices(desired, current.ips) && current.marked && (len(desired) == 0 || current.ttl == rec.TTL) {
		return false
	}
	if current.marked && len(current.ips) > 0 && aliasNow().Unix()-current.resolvedAt < int64(aliasFreshnessWindow/time.Second) {
		return false
	}

	store := rtypes.GetMemStore()
	if len(desired) == 0 {
		if len(current.ips) == 0 {
			return false
		}
		if err := store.DeleteRecord(zoneName, rtype, name); err != nil {
			slog.Warn("alias flatten: delete %s %s.%s failed: %v", rtype, name, zoneName, err)
			return false
		}
		publishRecordDelete(zoneName, rtype, name)
		return true
	}

	if len(current.ips) > 0 && (!current.marked || current.ttl != rec.TTL) {
		if err := store.DeleteRecord(zoneName, rtype, name); err != nil {
			slog.Warn("alias flatten: replace %s %s.%s failed: %v", rtype, name, zoneName, err)
			return false
		}
	}

	stamp := float64(aliasNow().Unix())
	list := make([]map[string]interface{}, 0, len(desired))
	for _, ip := range desired {
		list = append(list, map[string]interface{}{
			"ip":          ip,
			"ttl":         float64(rec.TTL),
			"alias":       true,
			"resolved_at": stamp,
		})
	}
	if err := store.AddRecord(zoneName, rtype, name, list); err != nil {
		slog.Warn("alias flatten: write %s %s.%s failed: %v", rtype, name, zoneName, err)
		return false
	}
	publishStoredRecord(zoneName, rtype, name)
	return true
}

func cleanupOrphanedFlattened(zoneName string, snap map[string]map[string]any, aliases map[string]any) bool {
	store := rtypes.GetMemStore()
	changed := false
	for _, rtype := range []string{string(types.TypeA), string(types.TypeAAAA)} {
		for name, raw := range snap[rtype] {
			if _, hasAlias := aliases[name]; hasAlias {
				continue
			}
			if !allEntriesAliasMarked(raw) {
				continue
			}
			if err := store.DeleteRecord(zoneName, rtype, name); err != nil {
				slog.Warn("alias flatten: orphan cleanup %s %s.%s failed: %v", rtype, name, zoneName, err)
				continue
			}
			publishRecordDelete(zoneName, rtype, name)
			changed = true
		}
	}
	return changed
}

func publishStoredRecord(zoneName, rtype, name string) {
	if distributed.Default == nil || !distributed.Enabled() {
		return
	}
	store := rtypes.GetMemStore()
	_, _, value, ok := store.GetRecord(zoneName, rtype, name)
	if !ok {
		return
	}
	if err := distributed.Default.PublishUpsert(zoneName, rtype, name, value); err != nil {
		slog.Warn("alias flatten: publish %s %s.%s failed: %v", rtype, name, zoneName, err)
	}
}

func publishRecordDelete(zoneName, rtype, name string) {
	if distributed.Default == nil || !distributed.Enabled() {
		return
	}
	if err := distributed.Default.PublishDelete(zoneName, rtype, name); err != nil {
		slog.Warn("alias flatten: publish delete %s %s.%s failed: %v", rtype, name, zoneName, err)
	}
}

func allEntriesAliasMarked(raw any) bool {
	entries := recordEntries(raw)
	if len(entries) == 0 {
		return false
	}
	for _, item := range entries {
		if marked, _ := item["alias"].(bool); !marked {
			return false
		}
	}
	return true
}

func recordEntries(raw any) []map[string]interface{} {
	switch v := raw.(type) {
	case []map[string]interface{}:
		return v
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(v))
		for _, entry := range v {
			if item, ok := entry.(map[string]interface{}); ok {
				out = append(out, item)
			}
		}
		return out
	default:
		return nil
	}
}

type flattenedState struct {
	ips        []string
	ttl        uint32
	marked     bool
	resolvedAt int64
}

func currentFlattenedState(snap map[string]map[string]any, rtype, name string) flattenedState {
	raw, ok := snap[rtype][name]
	if !ok {
		return flattenedState{marked: true}
	}
	state := flattenedState{marked: true}
	entries := recordEntries(raw)
	if entries == nil {
		switch v := raw.(type) {
		case []types.ARecord:
			for _, r := range v {
				state.ips = append(state.ips, r.IP)
				if state.ttl == 0 {
					state.ttl = r.TTL
				}
			}
			state.marked = false
		case []types.AAAARecord:
			for _, r := range v {
				state.ips = append(state.ips, r.IP)
				if state.ttl == 0 {
					state.ttl = r.TTL
				}
			}
			state.marked = false
		}
	}
	for _, item := range entries {
		ip, _ := item["ip"].(string)
		if ip == "" {
			continue
		}
		state.ips = append(state.ips, ip)
		if state.ttl == 0 {
			state.ttl = ttlFromAny(item["ttl"])
		}
		if m, _ := item["alias"].(bool); !m {
			state.marked = false
		}
		if at, ok := item["resolved_at"].(float64); ok && state.resolvedAt == 0 {
			state.resolvedAt = int64(at)
		}
	}
	sort.Strings(state.ips)
	return state
}

func ttlFromAny(v any) uint32 {
	switch t := v.(type) {
	case float64:
		return uint32(t)
	case uint32:
		return t
	case int:
		return uint32(t)
	default:
		return 0
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
