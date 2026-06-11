package distributed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go53/config"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/types"
	zonepkg "go53/zone"
)

const (
	OperationUpsert = "UPSERT"
	OperationDelete = "DELETE"

	EntityZoneRecord = "zone_record"
	EntityConfig     = "config"
	EntityTSIGKey    = "tsig_key"
	EntityDNSSECKey  = "dnssec_key"

	eventsTable       = "distributed-events"
	vectorTable       = "distributed-vector"
	entityTable       = "distributed-entities"
	invitesTable      = "distributed_invites"
	joinRequestsTable = "distributed_join_requests"
)

type Event struct {
	EventID    string            `json:"event_id"`
	Origin     string            `json:"origin"`
	Seq        uint64            `json:"seq"`
	Entity     string            `json:"entity"`
	EntityType string            `json:"entity_type,omitempty"`
	Zone       string            `json:"zone"`
	RRType     string            `json:"rrtype"`
	Name       string            `json:"name"`
	Operation  string            `json:"operation"`
	Value      json.RawMessage   `json:"value,omitempty"`
	Vector     map[string]uint64 `json:"vector,omitempty"`
	CreatedAt  int64             `json:"created_at"`
	Signature  string            `json:"signature"`
}

type EntityClock struct {
	Origin string            `json:"origin"`
	Seq    uint64            `json:"seq"`
	Vector map[string]uint64 `json:"vector"`
}

type NodeInfo struct {
	NodeID          string `json:"node_id"`
	Mode            string `json:"mode"`
	Transport       string `json:"transport"`
	SyncEndpoint    string `json:"sync_endpoint"`
	PublicKey       string `json:"public_key,omitempty"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	TLSEnabled      bool   `json:"tls_enabled"`
	TLSCertificate  string `json:"tls_certificate,omitempty"`
	TLSFingerprint  string `json:"tls_fingerprint,omitempty"`
	TLSPublicKeyPin string `json:"tls_public_key_pin,omitempty"`
	Version         string `json:"version"`
}

type InviteRecord struct {
	TokenID    string `json:"jti"`
	ClusterID  string `json:"cluster_id"`
	JoinNodeID string `json:"join_node_id"`
	Issuer     string `json:"issuer"`
	Token      string `json:"token"`
	UsageCount int    `json:"usage_count"`
	UsedCount  int    `json:"used_count"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at,omitempty"`
	AutoAccept bool   `json:"auto_accept,omitempty"`
}

type JoinRequest struct {
	Token            string `json:"token"`
	TokenID          string `json:"token_id"`
	JoinNodeID       string `json:"join_node_id"`
	JoinSyncEndpoint string `json:"join_sync_endpoint"`
	JoinPublicKey    string `json:"join_public_key"`
	Proof            string `json:"proof"`
	SubmittedAt      int64  `json:"submitted_at,omitempty"`
}

type Service struct {
	store      *memory.InMemoryZoneStore
	storage    storage.Storage
	client     *http.Client
	mu         sync.Mutex
	peerMu     sync.Mutex
	peerQueues map[string]chan Event
}

var Default *Service

func Init(store *memory.InMemoryZoneStore) *Service {
	timeout := time.Duration(liveConfig().Distributed.PushTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	Default = &Service{
		store:      store,
		storage:    storage.Backend,
		client:     &http.Client{Timeout: timeout},
		peerQueues: make(map[string]chan Event),
	}
	return Default
}

func Start(ctx context.Context) {
	if Default == nil {
		return
	}
	go Default.StartTCPListener(ctx)
	go Default.StartPeerWorkers(ctx)
	interval := time.Duration(liveConfig().Distributed.ResyncIntervalS) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		Default.SyncAllPeers(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				Default.SyncAllPeers(ctx)
			}
		}
	}()
}

func Enabled() bool {
	return enabled()
}

func TCPTransportEnabled() bool {
	return socketTransportEnabled()
}

func TLSTransportEnabled() bool {
	return tlsTransportEnabled()
}

func (s *Service) PublishUpsert(zone, rrtype, name string, value any) error {
	if s == nil || !enabled() {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.publish(Event{
		EntityType: EntityZoneRecord,
		Zone:       zone,
		RRType:     rrtype,
		Name:       name,
		Operation:  OperationUpsert,
		Value:      raw,
	})
}

func (s *Service) PublishDelete(zone, rrtype, name string) error {
	if s == nil || !enabled() {
		return nil
	}
	return s.publish(Event{
		EntityType: EntityZoneRecord,
		Zone:       zone,
		RRType:     rrtype,
		Name:       name,
		Operation:  OperationDelete,
	})
}

// PublishConfig replicates a live-config change to peers. It takes the raw JSON patch
// (only the keys the admin actually set), so presence is preserved end-to-end and
// false/empty values propagate. Node-local distributed keys are stripped so peers
// never overwrite their own identity, private key, or sync listener.
func (s *Service) PublishConfig(raw []byte) error {
	if s == nil || !readyToPublish() {
		return nil
	}
	stripped, hasKeys, err := stripDistributedKey(raw)
	if err != nil {
		return err
	}
	if !hasKeys {
		return nil
	}
	return s.publish(Event{
		EntityType: EntityConfig,
		Name:       "live",
		Operation:  OperationUpsert,
		Value:      stripped,
	})
}

// stripDistributedKey removes node-local distributed keys from a live-config JSON
// patch, returning the re-encoded document and whether any keys remain. Cluster
// membership keys are intentionally retained so joins can replicate safely.
func stripDistributedKey(raw []byte) ([]byte, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false, err
	}
	if rawDist, ok := fields["distributed"]; ok {
		var dist map[string]json.RawMessage
		if err := json.Unmarshal(rawDist, &dist); err != nil {
			return nil, false, err
		}
		for key := range dist {
			if key != "peers" && key != "peer_public_keys" {
				delete(dist, key)
			}
		}
		if len(dist) == 0 {
			delete(fields, "distributed")
		} else {
			encoded, err := json.Marshal(dist)
			if err != nil {
				return nil, false, err
			}
			fields["distributed"] = encoded
		}
	}
	if len(fields) == 0 {
		return nil, false, nil
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func (s *Service) PublishTSIGKey(name string, value any) error {
	if s == nil || !readyToPublish() {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.publish(Event{
		EntityType: EntityTSIGKey,
		Name:       name,
		Operation:  OperationUpsert,
		Value:      raw,
	})
}

func (s *Service) PublishTSIGKeyDelete(name string) error {
	if s == nil || !readyToPublish() {
		return nil
	}
	return s.publish(Event{
		EntityType: EntityTSIGKey,
		Name:       name,
		Operation:  OperationDelete,
	})
}

func (s *Service) PublishDNSSECKey(keyID string, key types.StoredKey) error {
	if s == nil || !readyToPublish() {
		return nil
	}
	raw, err := json.Marshal(key)
	if err != nil {
		return err
	}
	return s.publish(Event{
		EntityType: EntityDNSSECKey,
		Name:       keyID,
		Operation:  OperationUpsert,
		Value:      raw,
	})
}

func (s *Service) PublishDNSSECKeyDelete(keyID string) error {
	if s == nil || !readyToPublish() {
		return nil
	}
	return s.publish(Event{
		EntityType: EntityDNSSECKey,
		Name:       keyID,
		Operation:  OperationDelete,
	})
}

func (s *Service) publish(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	live := liveConfig()
	nodeID := strings.TrimSpace(live.Distributed.NodeID)
	if nodeID == "" {
		return errors.New("distributed node_id is required")
	}
	if _, err := privateKey(live.Distributed.PrivateKey); err != nil {
		return err
	}

	vector, err := s.loadVector()
	if err != nil {
		return err
	}
	seq := vector[nodeID] + 1
	vector[nodeID] = seq

	event.EventID = newEventID()
	event.Origin = nodeID
	event.Seq = seq
	event.Entity = eventEntityKey(event)
	event.Vector = cloneVector(vector)
	event.CreatedAt = time.Now().Unix()
	event.Signature = ""
	sig, err := signEvent(live.Distributed.PrivateKey, event)
	if err != nil {
		return err
	}
	event.Signature = sig

	if err := s.saveEvent(event); err != nil {
		return err
	}
	if err := s.saveVector(vector); err != nil {
		return err
	}
	if err := s.saveEntityClock(event.Entity, entityClockForEvent(event)); err != nil {
		return err
	}

	go s.pushToPeers(context.Background(), event)
	return nil
}

func (s *Service) ReceiveEvent(ctx context.Context, event Event) (bool, error) {
	if s == nil || !enabled() {
		return false, errors.New("distributed mode is disabled")
	}
	if strings.TrimSpace(event.Origin) == "" || event.Seq == 0 || event.EventID == "" {
		return false, errors.New("invalid distributed event identity")
	}
	if event.Origin == liveConfig().Distributed.NodeID {
		return false, nil
	}
	if err := verifyEvent(event); err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	vector, err := s.loadVector()
	if err != nil {
		return false, err
	}
	current := vector[event.Origin]
	if event.Seq <= current {
		return false, nil
	}
	if event.Seq > current+1 {
		return false, fmt.Errorf("missing prior event for origin %s: have %d, got %d", event.Origin, current, event.Seq)
	}

	apply := s.eventWinsLocked(event)
	if apply {
		if err := s.applyEventLocked(ctx, event); err != nil {
			return false, err
		}
		if err := s.saveEntityClock(event.Entity, entityClockForEvent(event)); err != nil {
			return false, err
		}
	}
	if err := s.saveEvent(event); err != nil {
		return false, err
	}
	vector[event.Origin] = event.Seq
	if err := s.saveVector(vector); err != nil {
		return false, err
	}
	return apply, nil
}

func (s *Service) Vector() (map[string]uint64, error) {
	if s == nil {
		return map[string]uint64{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadVector()
}

func (s *Service) Events(origin string, after uint64) ([]Event, error) {
	if s == nil {
		return nil, nil
	}
	table, err := s.storage.LoadTable(eventsTable)
	if err != nil {
		return nil, err
	}
	events := make([]Event, 0)
	for _, raw := range table {
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			continue
		}
		if origin != "" && event.Origin != origin {
			continue
		}
		if event.Seq <= after {
			continue
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Origin == events[j].Origin {
			return events[i].Seq < events[j].Seq
		}
		return events[i].Origin < events[j].Origin
	})
	return events, nil
}

func (s *Service) PublicKey() (string, error) {
	live := liveConfig()
	priv, err := privateKey(live.Distributed.PrivateKey)
	if err != nil {
		return "", err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub), nil
}

func (s *Service) NodeInfo() (NodeInfo, error) {
	live := liveConfig()
	info := NodeInfo{
		NodeID:       strings.TrimSpace(live.Distributed.NodeID),
		Mode:         live.Mode,
		Transport:    distributedTransport(),
		SyncEndpoint: advertisedSyncEndpoint(),
		TLSEnabled:   tlsTransportEnabled(),
		Version:      live.Version,
	}
	if s != nil {
		pub, err := s.PublicKey()
		if err != nil {
			return info, err
		}
		info.PublicKey = pub
		info.Fingerprint = PublicKeyFingerprint(pub)
		if info.TLSEnabled {
			cert, err := localTLSCertificate()
			if err != nil {
				return info, err
			}
			info.TLSCertificate = TLSCertificatePEM(cert)
			info.TLSFingerprint = TLSCertificateFingerprint(cert)
			info.TLSPublicKeyPin = info.Fingerprint
		}
	}
	return info, nil
}

func (s *Service) SyncAllPeers(ctx context.Context) {
	if s == nil || !enabled() {
		return
	}
	for _, peer := range peers() {
		if err := s.syncPeer(ctx, peer); err != nil {
			log.Printf("distributed: sync with %s failed: %v", peer, err)
		}
	}
}

func (s *Service) syncPeer(ctx context.Context, peer string) error {
	peerVector, err := s.fetchPeerVector(ctx, peer)
	if err != nil {
		return err
	}
	localVector, err := s.Vector()
	if err != nil {
		return err
	}
	for origin, peerSeq := range peerVector {
		localSeq := localVector[origin]
		if peerSeq <= localSeq {
			continue
		}
		events, err := s.fetchPeerEvents(ctx, peer, origin, localSeq)
		if err != nil {
			return err
		}
		for _, event := range events {
			if _, err := s.ReceiveEvent(ctx, event); err != nil {
				return err
			}
		}
	}
	return s.repairPeerZones(ctx, peer)
}

func (s *Service) pushToPeers(ctx context.Context, event Event) {
	for _, peer := range peers() {
		s.enqueuePeerEvent(ctx, peer, event)
	}
}

func (s *Service) StartPeerWorkers(ctx context.Context) {
	if s == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !enabled() {
				continue
			}
			for _, peer := range peers() {
				s.ensurePeerWorker(ctx, peer)
			}
		}
	}
}

func (s *Service) enqueuePeerEvent(ctx context.Context, peer string, event Event) {
	q := s.ensurePeerWorker(ctx, peer)
	select {
	case q <- event:
	default:
		go func() {
			select {
			case q <- event:
			case <-ctx.Done():
			}
		}()
	}
}

func (s *Service) ensurePeerWorker(ctx context.Context, peer string) chan Event {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerQueues == nil {
		s.peerQueues = make(map[string]chan Event)
	}
	if q, ok := s.peerQueues[peer]; ok {
		return q
	}
	q := make(chan Event, 1024)
	s.peerQueues[peer] = q
	go s.peerWorker(ctx, peer, q)
	return q
}

func (s *Service) peerWorker(ctx context.Context, peer string, q <-chan Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-q:
			s.deliverPeerEvent(ctx, peer, event)
		}
	}
}

func (s *Service) deliverPeerEvent(ctx context.Context, peer string, event Event) {
	backoff := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if err := s.pushEvent(ctx, peer, event); err != nil {
			log.Printf("distributed: push to %s failed: %v", peer, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
			continue
		}
		return
	}
}

func (s *Service) pushEvent(ctx context.Context, peer string, event Event) error {
	if useSocketTransport(peer) {
		return s.pushEventTCP(ctx, peer, event)
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerURL(peer, "/api/distributed/events"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("peer returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func (s *Service) fetchPeerVector(ctx context.Context, peer string) (map[string]uint64, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerVectorTCP(ctx, peer)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerURL(peer, "/api/distributed/vector"), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer vector returned %s", resp.Status)
	}
	var vector map[string]uint64
	if err := json.NewDecoder(resp.Body).Decode(&vector); err != nil {
		return nil, err
	}
	if vector == nil {
		vector = map[string]uint64{}
	}
	return vector, nil
}

func (s *Service) fetchPeerEvents(ctx context.Context, peer, origin string, after uint64) ([]Event, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerEventsTCP(ctx, peer, origin, after)
	}
	url := peerURL(peer, "/api/distributed/events") + "?origin=" + origin + "&after=" + strconv.FormatUint(after, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer events returned %s", resp.Status)
	}
	var events []Event
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Service) fetchPeerMerkleRoots(ctx context.Context, peer string) (map[string]MerkleZoneRoot, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerMerkleRootsTCP(ctx, peer)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerURL(peer, "/api/distributed/merkle/roots"), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer merkle roots returned %s", resp.Status)
	}
	var roots map[string]MerkleZoneRoot
	if err := json.NewDecoder(resp.Body).Decode(&roots); err != nil {
		return nil, err
	}
	if roots == nil {
		roots = map[string]MerkleZoneRoot{}
	}
	return roots, nil
}

func (s *Service) fetchPeerMerkleBranches(ctx context.Context, peer, zone string) (map[string]MerkleBranch, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerMerkleBranchesTCP(ctx, peer, zone)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerURL(peer, "/api/distributed/merkle/branches")+"?zone="+zone, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer merkle branches returned %s", resp.Status)
	}
	var branches map[string]MerkleBranch
	if err := json.NewDecoder(resp.Body).Decode(&branches); err != nil {
		return nil, err
	}
	if branches == nil {
		branches = map[string]MerkleBranch{}
	}
	return branches, nil
}

func (s *Service) fetchPeerMerkleLeaves(ctx context.Context, peer, zone string, prefixes []string) (map[string]MerkleLeaf, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerMerkleLeavesTCP(ctx, peer, zone, prefixes)
	}
	body, err := json.Marshal(map[string]any{"zone": zone, "prefixes": prefixes})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerURL(peer, "/api/distributed/merkle/leaves"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer merkle leaves returned %s", resp.Status)
	}
	var leaves map[string]MerkleLeaf
	if err := json.NewDecoder(resp.Body).Decode(&leaves); err != nil {
		return nil, err
	}
	if leaves == nil {
		leaves = map[string]MerkleLeaf{}
	}
	return leaves, nil
}

func (s *Service) fetchPeerMerkleRepairEvents(ctx context.Context, peer string, entities []string) ([]Event, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerMerkleRepairEventsTCP(ctx, peer, entities)
	}
	body, err := json.Marshal(map[string]any{"entities": entities})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerURL(peer, "/api/distributed/merkle/repair-events"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer merkle repair events returned %s", resp.Status)
	}
	var events []Event
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Service) fetchPeerMerkleRecords(ctx context.Context, peer, zone string, entities []string) (map[string]MerkleRecord, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerMerkleRecordsTCP(ctx, peer, zone, entities)
	}
	body, err := json.Marshal(map[string]any{"zone": zone, "entities": entities})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerURL(peer, "/api/distributed/merkle/records"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer merkle records returned %s", resp.Status)
	}
	var records map[string]MerkleRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}
	if records == nil {
		records = map[string]MerkleRecord{}
	}
	return records, nil
}

func (s *Service) fetchPeerDNSSECKeys(ctx context.Context, peer, zone string) (map[string]types.StoredKey, error) {
	if useSocketTransport(peer) {
		return s.fetchPeerDNSSECKeysTCP(ctx, peer, zone)
	}
	body, err := json.Marshal(map[string]string{"zone": zone})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerURL(peer, "/api/distributed/dnssec-keys"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("peer dnssec keys returned %s", resp.Status)
	}
	var keys map[string]types.StoredKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = map[string]types.StoredKey{}
	}
	return keys, nil
}

func (s *Service) repairPeerZones(ctx context.Context, peer string) error {
	peerRoots, err := s.fetchPeerMerkleRoots(ctx, peer)
	if err != nil {
		return err
	}
	localRoots, err := s.merkleZoneRoots()
	if err != nil {
		return err
	}
	zones := map[string]bool{}
	for zone := range localRoots {
		zones[zone] = true
	}
	for zone := range peerRoots {
		zones[zone] = true
	}
	for zone := range zones {
		local := localRoots[zone]
		remote := peerRoots[zone]
		if local.Root == remote.Root && local.LeafCount == remote.LeafCount {
			continue
		}
		if err := s.repairPeerZone(ctx, peer, zone); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) repairPeerZone(ctx context.Context, peer, zone string) error {
	localBranches, err := s.merkleZoneBranches(zone)
	if err != nil {
		return err
	}
	peerBranches, err := s.fetchPeerMerkleBranches(ctx, peer, zone)
	if err != nil {
		return err
	}
	prefixes := merkleDifferingBranches(localBranches, peerBranches)
	if len(prefixes) == 0 {
		return nil
	}
	localLeaves, err := s.merkleZoneLeaves(zone, prefixes)
	if err != nil {
		return err
	}
	peerLeaves, err := s.fetchPeerMerkleLeaves(ctx, peer, zone, prefixes)
	if err != nil {
		return err
	}
	entities := merkleDifferingEntities(localLeaves, peerLeaves)
	if len(entities) == 0 {
		return nil
	}
	events, err := s.fetchPeerMerkleRepairEvents(ctx, peer, entities)
	if err != nil {
		return err
	}
	repaired := map[string]bool{}
	for _, event := range events {
		if event.Entity == "" {
			event.Entity = eventEntityKey(event)
		}
		repaired[event.Entity] = true
		if err := s.applyRepairEvent(ctx, event); err != nil {
			return err
		}
	}
	missingEventEntities := make([]string, 0, len(entities))
	for _, entity := range entities {
		if !repaired[entity] {
			missingEventEntities = append(missingEventEntities, entity)
		}
	}
	if len(missingEventEntities) == 0 {
		return s.repairPeerDNSSECKeys(ctx, peer, zone)
	}
	records, err := s.fetchPeerMerkleRecords(ctx, peer, zone, missingEventEntities)
	if err != nil {
		return err
	}
	if err := s.applyMerkleRecords(records); err != nil {
		return err
	}
	return s.repairPeerDNSSECKeys(ctx, peer, zone)
}

func (s *Service) applyMerkleRecords(records map[string]MerkleRecord) error {
	for entity, record := range records {
		if strings.TrimSpace(record.Entity) == "" {
			record.Entity = entity
		}
		if record.Entity != entityKey(record.Zone, record.RRType, record.Name) {
			return fmt.Errorf("merkle record entity mismatch for %q", record.Entity)
		}
		if err := s.store.PutRecordRaw(record.Zone, record.RRType, record.Name, record.Value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) repairPeerDNSSECKeys(ctx context.Context, peer, zone string) error {
	keys, err := s.fetchPeerDNSSECKeys(ctx, peer, zone)
	if err != nil {
		return err
	}
	return s.applyDNSSECKeys(zone, keys)
}

func (s *Service) applyDNSSECKeys(zone string, keys map[string]types.StoredKey) error {
	if len(keys) == 0 {
		return nil
	}
	for keyID, key := range keys {
		data, err := json.Marshal(key)
		if err != nil {
			return err
		}
		if err := s.storage.SaveTable("dnssec_keys", keyID, data); err != nil {
			return err
		}
	}
	if err := security.InitDNSSECKeyCache(); err != nil {
		return err
	}
	return zonepkg.RefreshDNSSECKeyMaterial(zone)
}

func (s *Service) DNSSECKeysForZone(zone string) (map[string]types.StoredKey, error) {
	return s.dnssecKeysForZone(zone)
}

func (s *Service) dnssecKeysForZone(zone string) (map[string]types.StoredKey, error) {
	out := map[string]types.StoredKey{}
	if s == nil || s.storage == nil {
		return out, nil
	}
	wantZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	table, err := s.storage.LoadTable("dnssec_keys")
	if err != nil {
		return out, nil
	}
	for keyID, raw := range table {
		var key types.StoredKey
		if err := json.Unmarshal(raw, &key); err != nil {
			continue
		}
		keyZone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(key.Zone)), ".")
		if keyZone == wantZone {
			out[keyID] = key
		}
	}
	return out, nil
}

func (s *Service) applyEventLocked(ctx context.Context, event Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	switch eventType(event) {
	case EntityConfig:
		return s.applyConfigEvent(event)
	case EntityTSIGKey:
		return s.applyTSIGEvent(event)
	case EntityDNSSECKey:
		return s.applyDNSSECKeyEvent(event)
	}
	switch event.Operation {
	case OperationUpsert:
		var value any
		if len(event.Value) > 0 {
			if err := json.Unmarshal(event.Value, &value); err != nil {
				return err
			}
		}
		return s.store.PutRecordRaw(event.Zone, event.RRType, event.Name, value)
	case OperationDelete:
		return s.store.DeleteRecordRaw(event.Zone, event.RRType, event.Name)
	default:
		return fmt.Errorf("unknown distributed operation %q", event.Operation)
	}
}

func (s *Service) applyConfigEvent(event Event) error {
	if event.Operation != OperationUpsert {
		return fmt.Errorf("unsupported config operation %q", event.Operation)
	}
	// Defensively strip the node-local distributed block; a peer must never overwrite
	// its own identity/keys/listener from a replicated config event. The JSON-overlay
	// merge preserves presence so false/empty values from the origin are applied.
	stripped, hasKeys, err := stripDistributedKey(event.Value)
	if err != nil {
		return err
	}
	if !hasKeys {
		return nil
	}
	stripped, err = mergeDistributedMembershipPatch(stripped)
	if err != nil {
		return err
	}
	// A node that opted out of auth replication must never have its auth config
	// (x-auth-key/mode/OIDC) overwritten by a peer event.
	if !liveConfig().Distributed.AuthSyncEnabled() {
		var hasRest bool
		stripped, hasRest, err = dropJSONKey(stripped, "auth")
		if err != nil {
			return err
		}
		if !hasRest {
			return nil
		}
	}
	return config.AppConfig.MergeUpdateLiveJSON(stripped)
}

// dropJSONKey removes a top-level key from a JSON object, returning the re-encoded
// document and whether any other keys remain.
func dropJSONKey(raw []byte, key string) ([]byte, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false, err
	}
	delete(fields, key)
	if len(fields) == 0 {
		return nil, false, nil
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

func mergeDistributedMembershipPatch(raw []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	rawDist, ok := fields["distributed"]
	if !ok {
		return raw, nil
	}
	var dist map[string]json.RawMessage
	if err := json.Unmarshal(rawDist, &dist); err != nil {
		return nil, err
	}
	live := liveConfig()
	if rawPeers, ok := dist["peers"]; ok {
		var incoming string
		if err := json.Unmarshal(rawPeers, &incoming); err != nil {
			return nil, err
		}
		peers := splitCSV(live.Distributed.Peers)
		self := advertisedSyncEndpoint()
		for _, peer := range splitCSV(incoming) {
			if peer != self {
				peers = appendUnique(peers, peer)
			}
		}
		sort.Strings(peers)
		encoded, err := json.Marshal(strings.Join(peers, ","))
		if err != nil {
			return nil, err
		}
		dist["peers"] = encoded
	}
	if rawKeys, ok := dist["peer_public_keys"]; ok {
		incoming := map[string]string{}
		if err := json.Unmarshal(rawKeys, &incoming); err != nil {
			return nil, err
		}
		merged := map[string]string{}
		for nodeID, publicKey := range live.Distributed.PeerPublicKeys {
			merged[nodeID] = publicKey
		}
		for nodeID, publicKey := range incoming {
			merged[nodeID] = publicKey
		}
		encoded, err := json.Marshal(merged)
		if err != nil {
			return nil, err
		}
		dist["peer_public_keys"] = encoded
	}
	encoded, err := json.Marshal(dist)
	if err != nil {
		return nil, err
	}
	fields["distributed"] = encoded
	return json.Marshal(fields)
}

func (s *Service) applyTSIGEvent(event Event) error {
	switch event.Operation {
	case OperationUpsert:
		if strings.TrimSpace(event.Name) == "" {
			return errors.New("missing TSIG key name")
		}
		if err := s.storage.SaveTable("tsig-keys", event.Name, event.Value); err != nil {
			return err
		}
		return security.LoadTSIGKeysFromStorage()
	case OperationDelete:
		if err := s.storage.DeleteFromTable("tsig-keys", event.Name); err != nil {
			return err
		}
		security.DeleteTSIGKey(event.Name)
		return nil
	default:
		return fmt.Errorf("unsupported TSIG operation %q", event.Operation)
	}
}

func (s *Service) applyDNSSECKeyEvent(event Event) error {
	switch event.Operation {
	case OperationUpsert:
		if strings.TrimSpace(event.Name) == "" {
			return errors.New("missing DNSSEC key id")
		}
		if err := s.storage.SaveTable("dnssec_keys", event.Name, event.Value); err != nil {
			return err
		}
		var key types.StoredKey
		if err := json.Unmarshal(event.Value, &key); err != nil {
			return err
		}
		if err := security.InitDNSSECKeyCache(); err != nil {
			return err
		}
		if key.Zone != "" {
			return zonepkg.RefreshDNSSECKeyMaterial(key.Zone)
		}
		return nil
	case OperationDelete:
		if err := s.storage.DeleteFromTable("dnssec_keys", event.Name); err != nil {
			return err
		}
		return security.InitDNSSECKeyCache()
	default:
		return fmt.Errorf("unsupported DNSSEC key operation %q", event.Operation)
	}
}

func (s *Service) applyRepairEvent(ctx context.Context, event Event) error {
	if eventType(event) != EntityZoneRecord {
		return nil
	}
	if strings.TrimSpace(event.Origin) == "" || event.Seq == 0 || event.EventID == "" {
		return errors.New("invalid distributed repair event identity")
	}
	if event.Origin == liveConfig().Distributed.NodeID {
		return nil
	}
	if err := verifyEvent(event); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	apply := s.eventWinsLocked(event) || s.eventMatchesEntityClockLocked(event)
	if !apply {
		return nil
	}
	if err := s.applyEventLocked(ctx, event); err != nil {
		return err
	}
	if err := s.saveEntityClock(event.Entity, entityClockForEvent(event)); err != nil {
		return err
	}
	if err := s.saveEvent(event); err != nil {
		return err
	}
	vector, err := s.loadVector()
	if err != nil {
		return err
	}
	if vector[event.Origin] < event.Seq {
		vector[event.Origin] = event.Seq
		return s.saveVector(vector)
	}
	return nil
}

func (s *Service) latestEventsForEntities(entities []string) ([]Event, error) {
	wanted := map[string]bool{}
	for _, entity := range entities {
		entity = strings.TrimSpace(entity)
		if entity != "" {
			wanted[entity] = true
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	table, err := s.storage.LoadTable(eventsTable)
	if err != nil {
		return nil, err
	}
	latest := map[string]Event{}
	for _, raw := range table {
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			continue
		}
		if event.Entity == "" {
			event.Entity = eventEntityKey(event)
		}
		if eventType(event) != EntityZoneRecord || !wanted[event.Entity] {
			continue
		}
		current, ok := latest[event.Entity]
		if !ok || eventWinsEvent(event, current) {
			latest[event.Entity] = event
		}
	}
	out := make([]Event, 0, len(latest))
	for _, event := range latest {
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Entity < out[j].Entity
	})
	return out, nil
}

func (s *Service) LatestEventsForEntities(entities []string) ([]Event, error) {
	return s.latestEventsForEntities(entities)
}

func (s *Service) SaveInvite(record InviteRecord) error {
	if s == nil || s.storage == nil {
		return errors.New("distributed service is not initialized")
	}
	if strings.TrimSpace(record.TokenID) == "" {
		return errors.New("missing invite jti")
	}
	if record.UsageCount <= 0 {
		return errors.New("invite usage_count must be greater than zero")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return s.storage.SaveTable(invitesTable, record.TokenID, data)
}

func (s *Service) ConsumeInvite(tokenID string) (InviteRecord, error) {
	record, err := s.loadInvite(tokenID)
	if err != nil {
		return InviteRecord{}, err
	}
	return s.consumeInviteRecord(record)
}

func (s *Service) ConsumeInviteToken(tokenID, token string) (InviteRecord, error) {
	record, err := s.loadInvite(tokenID)
	if err != nil {
		return InviteRecord{}, err
	}
	if strings.TrimSpace(record.Token) != "" && record.Token != strings.TrimSpace(token) {
		return InviteRecord{}, errors.New("invite token mismatch")
	}
	return s.consumeInviteRecord(record)
}

func (s *Service) validateInviteTokenUsable(tokenID, token string) (InviteRecord, error) {
	record, err := s.loadInvite(tokenID)
	if err != nil {
		return InviteRecord{}, err
	}
	if strings.TrimSpace(record.Token) != "" && record.Token != strings.TrimSpace(token) {
		return InviteRecord{}, errors.New("invite token mismatch")
	}
	now := time.Now().Unix()
	if record.ExpiresAt > 0 && now > record.ExpiresAt {
		return InviteRecord{}, errors.New("invite expired")
	}
	if record.UsedCount >= record.UsageCount {
		return InviteRecord{}, errors.New("invite usage limit reached")
	}
	return record, nil
}

func (s *Service) loadInvite(tokenID string) (InviteRecord, error) {
	if s == nil || s.storage == nil {
		return InviteRecord{}, errors.New("distributed service is not initialized")
	}
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" {
		return InviteRecord{}, errors.New("missing invite jti")
	}
	table, err := s.storage.LoadTable(invitesTable)
	if err != nil {
		return InviteRecord{}, err
	}
	raw, ok := table[tokenID]
	if !ok {
		return InviteRecord{}, errors.New("invite not found")
	}
	var record InviteRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return InviteRecord{}, err
	}
	return record, nil
}

func (s *Service) consumeInviteRecord(record InviteRecord) (InviteRecord, error) {
	now := time.Now().Unix()
	if record.ExpiresAt > 0 && now > record.ExpiresAt {
		return InviteRecord{}, errors.New("invite expired")
	}
	if record.UsedCount >= record.UsageCount {
		return InviteRecord{}, errors.New("invite usage limit reached")
	}
	record.UsedCount++
	record.LastUsedAt = now
	if err := s.SaveInvite(record); err != nil {
		return InviteRecord{}, err
	}
	return record, nil
}

func (s *Service) SubmitJoinRequest(ctx context.Context, req JoinRequest) (bool, error) {
	if s == nil || !enabled() {
		return false, errors.New("distributed mode is disabled")
	}
	if err := validateJoinRequest(req); err != nil {
		return false, err
	}
	record, err := s.validateInviteTokenUsable(req.TokenID, req.Token)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(record.JoinNodeID) != "" && record.JoinNodeID != req.JoinNodeID {
		return false, errors.New("join node id does not match invite")
	}
	// Whether a join is auto-accepted is the issuer's decision, recorded on the
	// signed invite — never something the joining node can assert in its request.
	if record.AutoAccept {
		return true, s.acceptJoinRequest(ctx, req)
	}
	if err := s.SaveJoinRequest(req); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Service) AcceptJoinRequest(ctx context.Context, req JoinRequest) error {
	return s.acceptJoinRequest(ctx, req)
}

func (s *Service) acceptJoinRequest(_ context.Context, req JoinRequest) error {
	if s == nil || !enabled() {
		return errors.New("distributed mode is disabled")
	}
	if err := validateJoinRequest(req); err != nil {
		return err
	}
	if _, err := s.ConsumeInviteToken(req.TokenID, req.Token); err != nil {
		return err
	}
	patch, err := joinMembershipPatch(req)
	if err != nil {
		return err
	}
	if err := config.AppConfig.MergeUpdateLiveJSON(patch); err != nil {
		return err
	}
	return s.PublishConfig(patch)
}

func (s *Service) SaveJoinRequest(req JoinRequest) error {
	if s == nil || s.storage == nil {
		return errors.New("distributed service is not initialized")
	}
	req.JoinNodeID = strings.TrimSpace(req.JoinNodeID)
	if req.JoinNodeID == "" {
		return errors.New("missing join node id")
	}
	if req.SubmittedAt == 0 {
		req.SubmittedAt = time.Now().Unix()
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return s.storage.SaveTable(joinRequestsTable, req.JoinNodeID, data)
}

func (s *Service) ListJoinRequests() ([]JoinRequest, error) {
	if s == nil || s.storage == nil {
		return nil, errors.New("distributed service is not initialized")
	}
	table, err := s.storage.LoadTable(joinRequestsTable)
	if err != nil {
		return nil, err
	}
	out := make([]JoinRequest, 0, len(table))
	for _, raw := range table {
		var req JoinRequest
		if err := json.Unmarshal(raw, &req); err == nil {
			out = append(out, req)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SubmittedAt < out[j].SubmittedAt
	})
	return out, nil
}

func (s *Service) ApproveJoinRequest(ctx context.Context, nodeID string) (JoinRequest, error) {
	req, err := s.loadJoinRequest(nodeID)
	if err != nil {
		return JoinRequest{}, err
	}
	if err := s.acceptJoinRequest(ctx, req); err != nil {
		return JoinRequest{}, err
	}
	_ = s.storage.DeleteFromTable(joinRequestsTable, req.JoinNodeID)
	return req, nil
}

func (s *Service) loadJoinRequest(nodeID string) (JoinRequest, error) {
	if s == nil || s.storage == nil {
		return JoinRequest{}, errors.New("distributed service is not initialized")
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return JoinRequest{}, errors.New("missing join node id")
	}
	table, err := s.storage.LoadTable(joinRequestsTable)
	if err != nil {
		return JoinRequest{}, err
	}
	raw, ok := table[nodeID]
	if !ok {
		return JoinRequest{}, errors.New("join request not found")
	}
	var req JoinRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return JoinRequest{}, err
	}
	return req, nil
}

func validateJoinRequest(req JoinRequest) error {
	if strings.TrimSpace(req.TokenID) == "" || strings.TrimSpace(req.Token) == "" {
		return errors.New("missing join invite token")
	}
	if strings.TrimSpace(req.JoinNodeID) == "" || strings.TrimSpace(req.JoinSyncEndpoint) == "" || strings.TrimSpace(req.JoinPublicKey) == "" {
		return errors.New("missing join node identity")
	}
	pub, err := publicKey(req.JoinPublicKey)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Proof))
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, joinRequestPayload(req), sig) {
		return errors.New("invalid join request proof")
	}
	return nil
}

func joinMembershipPatch(req JoinRequest) ([]byte, error) {
	live := liveConfig()
	peers := splitCSV(live.Distributed.Peers)
	peers = appendUnique(peers, req.JoinSyncEndpoint)
	sort.Strings(peers)
	peerKeys := map[string]string{}
	for nodeID, publicKey := range live.Distributed.PeerPublicKeys {
		peerKeys[nodeID] = publicKey
	}
	peerKeys[req.JoinNodeID] = req.JoinPublicKey
	return json.Marshal(map[string]any{
		"distributed": map[string]any{
			"peers":            strings.Join(peers, ","),
			"peer_public_keys": peerKeys,
		},
	})
}

func JoinRequestPayload(req JoinRequest) []byte {
	return joinRequestPayload(req)
}

func joinRequestPayload(req JoinRequest) []byte {
	return []byte("go53-join-request-v1:" +
		strings.TrimSpace(req.TokenID) + ":" +
		strings.TrimSpace(req.JoinNodeID) + ":" +
		strings.TrimSpace(req.JoinSyncEndpoint) + ":" +
		strings.TrimSpace(req.JoinPublicKey))
}

func splitCSV(value string) []string {
	out := []string{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func (s *Service) eventWinsLocked(event Event) bool {
	if event.Entity == "" {
		event.Entity = eventEntityKey(event)
	}
	current, ok := s.loadEntityClock(event.Entity)
	if !ok {
		return true
	}
	return eventWinsClock(event, current)
}

func (s *Service) eventMatchesEntityClockLocked(event Event) bool {
	if event.Entity == "" {
		event.Entity = eventEntityKey(event)
	}
	current, ok := s.loadEntityClock(event.Entity)
	if !ok {
		return false
	}
	if current.Origin != event.Origin || current.Seq != event.Seq {
		return false
	}
	eventVector := normalizedEventVector(event)
	currentVector := normalizedClockVector(current)
	return vectorsEqual(eventVector, currentVector)
}

func entityClockForEvent(event Event) EntityClock {
	return EntityClock{
		Origin: event.Origin,
		Seq:    event.Seq,
		Vector: cloneVector(normalizedEventVector(event)),
	}
}

func eventWinsClock(event Event, current EntityClock) bool {
	eventVector := normalizedEventVector(event)
	currentVector := normalizedClockVector(current)
	eventDominates := vectorDominates(eventVector, currentVector)
	currentDominates := vectorDominates(currentVector, eventVector)
	switch {
	case eventDominates && !currentDominates:
		return true
	case currentDominates && !eventDominates:
		return false
	case eventDominates && currentDominates:
		return eventTieBreak(event.Origin, event.Seq, current.Origin, current.Seq)
	default:
		return eventTieBreak(event.Origin, event.Seq, current.Origin, current.Seq)
	}
}

func eventWinsEvent(candidate, current Event) bool {
	candidateVector := normalizedEventVector(candidate)
	currentVector := normalizedEventVector(current)
	candidateDominates := vectorDominates(candidateVector, currentVector)
	currentDominates := vectorDominates(currentVector, candidateVector)
	switch {
	case candidateDominates && !currentDominates:
		return true
	case currentDominates && !candidateDominates:
		return false
	case candidateDominates && currentDominates:
		return eventTieBreak(candidate.Origin, candidate.Seq, current.Origin, current.Seq)
	default:
		return eventTieBreak(candidate.Origin, candidate.Seq, current.Origin, current.Seq)
	}
}

func normalizedEventVector(event Event) map[string]uint64 {
	vector := cloneVector(event.Vector)
	if vector == nil {
		vector = map[string]uint64{}
	}
	if strings.TrimSpace(event.Origin) != "" && vector[event.Origin] < event.Seq {
		vector[event.Origin] = event.Seq
	}
	return vector
}

func normalizedClockVector(clock EntityClock) map[string]uint64 {
	vector := cloneVector(clock.Vector)
	if vector == nil {
		vector = map[string]uint64{}
	}
	if strings.TrimSpace(clock.Origin) != "" && vector[clock.Origin] < clock.Seq {
		vector[clock.Origin] = clock.Seq
	}
	return vector
}

func vectorDominates(a, b map[string]uint64) bool {
	strict := false
	nodes := map[string]bool{}
	for node := range a {
		nodes[node] = true
	}
	for node := range b {
		nodes[node] = true
	}
	for node := range nodes {
		av := a[node]
		bv := b[node]
		if av < bv {
			return false
		}
		if av > bv {
			strict = true
		}
	}
	return strict
}

func vectorsEqual(a, b map[string]uint64) bool {
	nodes := map[string]bool{}
	for node := range a {
		nodes[node] = true
	}
	for node := range b {
		nodes[node] = true
	}
	for node := range nodes {
		if a[node] != b[node] {
			return false
		}
	}
	return true
}

func eventTieBreak(candidateOrigin string, candidateSeq uint64, currentOrigin string, currentSeq uint64) bool {
	if candidateSeq != currentSeq {
		return candidateSeq > currentSeq
	}
	return candidateOrigin > currentOrigin
}

func (s *Service) loadVector() (map[string]uint64, error) {
	raw, err := s.storage.LoadTable(vectorTable)
	if err != nil {
		return nil, err
	}
	vector := make(map[string]uint64, len(raw))
	for node, data := range raw {
		var seq uint64
		if err := json.Unmarshal(data, &seq); err != nil {
			continue
		}
		vector[node] = seq
	}
	return vector, nil
}

func (s *Service) saveVector(vector map[string]uint64) error {
	for node, seq := range vector {
		data, err := json.Marshal(seq)
		if err != nil {
			return err
		}
		if err := s.storage.SaveTable(vectorTable, node, data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) saveEvent(event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return s.storage.SaveTable(eventsTable, eventKey(event.Origin, event.Seq), data)
}

func (s *Service) loadEntityClock(entity string) (EntityClock, bool) {
	table, err := s.storage.LoadTable(entityTable)
	if err != nil {
		return EntityClock{}, false
	}
	raw, ok := table[entity]
	if !ok {
		return EntityClock{}, false
	}
	var clock EntityClock
	if err := json.Unmarshal(raw, &clock); err != nil {
		return EntityClock{}, false
	}
	return clock, true
}

func (s *Service) saveEntityClock(entity string, clock EntityClock) error {
	data, err := json.Marshal(clock)
	if err != nil {
		return err
	}
	return s.storage.SaveTable(entityTable, entity, data)
}

func signEvent(privateKeyB64 string, event Event) (string, error) {
	priv, err := privateKey(privateKeyB64)
	if err != nil {
		return "", err
	}
	payload, err := signingPayload(event)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)), nil
}

func verifyEvent(event Event) error {
	live := liveConfig()
	pubB64 := live.Distributed.PeerPublicKeys[event.Origin]
	if pubB64 == "" {
		return fmt.Errorf("no public key configured for distributed peer %q", event.Origin)
	}
	pub, err := publicKey(pubB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(event.Signature)
	if err != nil {
		return err
	}
	payload, err := signingPayload(event)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return errors.New("invalid distributed event signature")
	}
	return nil
}

func signingPayload(event Event) ([]byte, error) {
	event.Signature = ""
	return json.Marshal(event)
}

func privateKey(value string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("invalid distributed private_key: %w", err)
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("invalid distributed private_key length %d", len(raw))
	}
}

func publicKey(value string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("invalid distributed peer public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid distributed peer public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func GenerateKeyPair() (privateKeyB64 string, publicKeyB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

func eventKey(origin string, seq uint64) string {
	return origin + "/" + fmt.Sprintf("%020d", seq)
}

func eventType(event Event) string {
	if event.EntityType == "" {
		return EntityZoneRecord
	}
	return event.EntityType
}

func eventEntityKey(event Event) string {
	switch eventType(event) {
	case EntityConfig:
		return EntityConfig + "/live"
	case EntityTSIGKey:
		return EntityTSIGKey + "/" + strings.ToLower(strings.TrimSpace(event.Name))
	case EntityDNSSECKey:
		return EntityDNSSECKey + "/" + strings.TrimSpace(event.Name)
	default:
		return entityKey(event.Zone, event.RRType, event.Name)
	}
}

func entityKey(zone, rrtype, name string) string {
	return strings.ToLower(strings.TrimSpace(zone)) + "/" + strings.ToUpper(strings.TrimSpace(rrtype)) + "/" + strings.ToLower(strings.TrimSpace(name))
}

func cloneVector(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func enabled() bool {
	return liveConfig().Mode == "distributed"
}

func readyToPublish() bool {
	live := liveConfig()
	return live.Mode == "distributed" &&
		strings.TrimSpace(live.Distributed.NodeID) != "" &&
		strings.TrimSpace(live.Distributed.PrivateKey) != ""
}

func liveConfig() config.LiveConfig {
	return config.AppConfig.GetLive()
}

func peers() []string {
	raw := liveConfig().Distributed.Peers
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		peer := strings.TrimSpace(part)
		if peer == "" {
			continue
		}
		out = append(out, strings.TrimRight(peer, "/"))
	}
	return out
}

func peerURL(peer, path string) string {
	return strings.TrimRight(peer, "/") + path
}

func useTCPTransport(peer string) bool {
	return useSocketTransport(peer)
}

func useSocketTransport(peer string) bool {
	peer = strings.TrimSpace(strings.ToLower(peer))
	if strings.HasPrefix(peer, "tcp://") || strings.HasPrefix(peer, "tls://") || strings.HasPrefix(peer, "mtls://") {
		return true
	}
	if strings.HasPrefix(peer, "http://") || strings.HasPrefix(peer, "https://") {
		return false
	}
	return socketTransportEnabled()
}

func distributedTransport() string {
	transport := strings.TrimSpace(strings.ToLower(liveConfig().Distributed.Transport))
	if transport == "" {
		return "http"
	}
	return transport
}

func advertisedSyncEndpoint() string {
	live := liveConfig()
	transport := distributedTransport()
	if transport == "tcp" || transport == "tls" || transport == "mtls" {
		addr := strings.TrimSpace(live.Distributed.SyncPort)
		if addr == "" {
			return ""
		}
		scheme := "tcp"
		if transport == "tls" || transport == "mtls" {
			scheme = "tls"
		}
		host := strings.TrimSpace(live.Distributed.SyncBindHost)
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		if strings.Contains(addr, ":") {
			if strings.HasPrefix(addr, ":") {
				return scheme + "://" + host + addr
			}
			return scheme + "://" + addr
		}
		return scheme + "://" + host + ":" + addr
	}
	return ""
}

func socketTransportEnabled() bool {
	transport := distributedTransport()
	return transport == "tcp" || transport == "tls" || transport == "mtls"
}

func PublicKeyFingerprint(publicKeyB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func newEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b[:]), "=")
}
