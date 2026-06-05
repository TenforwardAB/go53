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
	"reflect"
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

	eventsTable = "distributed-events"
	vectorTable = "distributed-vector"
	entityTable = "distributed-entities"
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
	Origin string `json:"origin"`
	Seq    uint64 `json:"seq"`
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

func (s *Service) PublishConfig(partial config.LiveConfig) error {
	if s == nil || !readyToPublish() {
		return nil
	}
	partial.Distributed = config.DistributedConfig{}
	if reflect.DeepEqual(partial, config.LiveConfig{}) {
		return nil
	}
	raw, err := json.Marshal(partial)
	if err != nil {
		return err
	}
	return s.publish(Event{
		EntityType: EntityConfig,
		Name:       "live",
		Operation:  OperationUpsert,
		Value:      raw,
	})
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
	if err := s.saveEntityClock(event.Entity, EntityClock{Origin: event.Origin, Seq: event.Seq}); err != nil {
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
		if err := s.saveEntityClock(event.Entity, EntityClock{Origin: event.Origin, Seq: event.Seq}); err != nil {
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
	return nil
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
	var partial config.LiveConfig
	if err := json.Unmarshal(event.Value, &partial); err != nil {
		return err
	}
	partial.Distributed = config.DistributedConfig{}
	config.AppConfig.MergeUpdateLive(partial)
	return nil
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

func (s *Service) eventWinsLocked(event Event) bool {
	if event.Entity == "" {
		event.Entity = eventEntityKey(event)
	}
	current, ok := s.loadEntityClock(event.Entity)
	if !ok {
		return true
	}
	if event.Seq != current.Seq {
		return event.Seq > current.Seq
	}
	return event.Origin > current.Origin
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
