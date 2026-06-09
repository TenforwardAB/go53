package distributed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	frameTypeHello                 = "HELLO"
	frameTypeEvent                 = "EVENT"
	frameTypeAck                   = "ACK"
	frameTypeVectorRequest         = "VECTOR_REQUEST"
	frameTypeVector                = "VECTOR"
	frameTypeEventsRequest         = "EVENTS_REQUEST"
	frameTypeEvents                = "EVENTS"
	frameTypeMerkleRootsRequest    = "MERKLE_ROOTS_REQUEST"
	frameTypeMerkleRoots           = "MERKLE_ROOTS"
	frameTypeMerkleBranchesRequest = "MERKLE_BRANCHES_REQUEST"
	frameTypeMerkleBranches        = "MERKLE_BRANCHES"
	frameTypeMerkleLeavesRequest   = "MERKLE_LEAVES_REQUEST"
	frameTypeMerkleLeaves          = "MERKLE_LEAVES"
	frameTypeMerkleRepairRequest   = "MERKLE_REPAIR_REQUEST"
	frameTypeJoinRequest           = "JOIN_REQUEST"
	frameTypeError                 = "ERROR"

	maxFrameBytes = 16 << 20
)

var (
	tlsCertMu       sync.Mutex
	tlsCertCacheKey string
	tlsCertCache    tls.Certificate
)

type frame struct {
	Type           string                    `json:"type"`
	NodeID         string                    `json:"node_id,omitempty"`
	Nonce          string                    `json:"nonce,omitempty"`
	Proof          string                    `json:"proof,omitempty"`
	Event          *Event                    `json:"event,omitempty"`
	Events         []Event                   `json:"events,omitempty"`
	Vector         map[string]uint64         `json:"vector,omitempty"`
	Origin         string                    `json:"origin,omitempty"`
	After          uint64                    `json:"after,omitempty"`
	Zone           string                    `json:"zone,omitempty"`
	Prefixes       []string                  `json:"prefixes,omitempty"`
	Entities       []string                  `json:"entities,omitempty"`
	MerkleRoots    map[string]MerkleZoneRoot `json:"merkle_roots,omitempty"`
	MerkleBranches map[string]MerkleBranch   `json:"merkle_branches,omitempty"`
	MerkleLeaves   map[string]MerkleLeaf     `json:"merkle_leaves,omitempty"`
	JoinRequest    *JoinRequest              `json:"join_request,omitempty"`
	AutoAccept     bool                      `json:"auto_accept,omitempty"`
	Applied        bool                      `json:"applied,omitempty"`
	Error          string                    `json:"error,omitempty"`
}

func (s *Service) StartTCPListener(ctx context.Context) {
	if s == nil {
		return
	}
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !enabled() {
			time.Sleep(time.Second)
			continue
		}
		addr := syncListenAddr()
		if addr == "" {
			time.Sleep(time.Second)
			continue
		}
		if err := s.serveTCPListener(ctx, addr); err != nil && err.Error() != lastErr {
			lastErr = err.Error()
			log.Printf("distributed: TCP sync listener on %s stopped: %v", addr, err)
		}
		time.Sleep(time.Second)
	}
}

func (s *Service) serveTCPListener(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("distributed: TCP sync listener started on %s", addr)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		if tlsTransportEnabled() {
			cfg, err := serverTLSConfig()
			if err != nil {
				_ = conn.Close()
				log.Printf("distributed: TLS config failed: %v", err)
				continue
			}
			conn = tls.Server(conn, cfg)
		}
		go s.handleTCPConn(ctx, conn)
	}
}

func (s *Service) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("distributed: TLS handshake failed: %v", err)
			return
		}
	}
	ready, err := s.acceptTCPIntro(ctx, conn)
	if err != nil {
		log.Printf("distributed: TCP hello failed: %v", err)
		return
	}
	if !ready {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		req, err := readFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("distributed: TCP read failed: %v", err)
			}
			return
		}
		resp := s.handleTCPFrame(ctx, req)
		if err := writeFrame(conn, resp); err != nil {
			log.Printf("distributed: TCP write failed: %v", err)
			return
		}
	}
}

func (s *Service) handleTCPFrame(ctx context.Context, req frame) frame {
	if !enabled() {
		return frame{Type: frameTypeError, Error: "distributed mode is disabled"}
	}
	switch req.Type {
	case frameTypeEvent:
		if req.Event == nil {
			return frame{Type: frameTypeError, Error: "missing event"}
		}
		applied, err := s.ReceiveEvent(ctx, *req.Event)
		if err != nil {
			return frame{Type: frameTypeError, Error: err.Error()}
		}
		return frame{Type: frameTypeAck, Applied: applied}
	case frameTypeVectorRequest:
		vector, err := s.Vector()
		if err != nil {
			return frame{Type: frameTypeError, Error: err.Error()}
		}
		return frame{Type: frameTypeVector, Vector: vector}
	case frameTypeEventsRequest:
		events, err := s.Events(req.Origin, req.After)
		if err != nil {
			return frame{Type: frameTypeError, Error: err.Error()}
		}
		return frame{Type: frameTypeEvents, Events: events}
	case frameTypeMerkleRootsRequest:
		roots, err := s.merkleZoneRoots()
		if err != nil {
			return frame{Type: frameTypeError, Error: err.Error()}
		}
		return frame{Type: frameTypeMerkleRoots, MerkleRoots: roots}
	case frameTypeMerkleBranchesRequest:
		branches, err := s.merkleZoneBranches(req.Zone)
		if err != nil {
			return frame{Type: frameTypeError, Error: err.Error()}
		}
		return frame{Type: frameTypeMerkleBranches, Zone: req.Zone, MerkleBranches: branches}
	case frameTypeMerkleLeavesRequest:
		leaves, err := s.merkleZoneLeaves(req.Zone, req.Prefixes)
		if err != nil {
			return frame{Type: frameTypeError, Error: err.Error()}
		}
		return frame{Type: frameTypeMerkleLeaves, Zone: req.Zone, MerkleLeaves: leaves}
	case frameTypeMerkleRepairRequest:
		events, err := s.latestEventsForEntities(req.Entities)
		if err != nil {
			return frame{Type: frameTypeError, Error: err.Error()}
		}
		return frame{Type: frameTypeEvents, Events: events}
	default:
		return frame{Type: frameTypeError, Error: "unknown frame type " + req.Type}
	}
}

func (s *Service) pushEventTCP(ctx context.Context, peer string, event Event) error {
	resp, err := s.roundTripTCP(ctx, peer, frame{Type: frameTypeEvent, Event: &event})
	if err != nil {
		return err
	}
	if resp.Type == frameTypeError {
		return errors.New(resp.Error)
	}
	if resp.Type != frameTypeAck {
		return fmt.Errorf("unexpected TCP response %q", resp.Type)
	}
	return nil
}

func (s *Service) fetchPeerVectorTCP(ctx context.Context, peer string) (map[string]uint64, error) {
	resp, err := s.roundTripTCP(ctx, peer, frame{Type: frameTypeVectorRequest})
	if err != nil {
		return nil, err
	}
	if resp.Type == frameTypeError {
		return nil, errors.New(resp.Error)
	}
	if resp.Type != frameTypeVector {
		return nil, fmt.Errorf("unexpected TCP response %q", resp.Type)
	}
	if resp.Vector == nil {
		resp.Vector = map[string]uint64{}
	}
	return resp.Vector, nil
}

func (s *Service) fetchPeerEventsTCP(ctx context.Context, peer, origin string, after uint64) ([]Event, error) {
	resp, err := s.roundTripTCP(ctx, peer, frame{Type: frameTypeEventsRequest, Origin: origin, After: after})
	if err != nil {
		return nil, err
	}
	if resp.Type == frameTypeError {
		return nil, errors.New(resp.Error)
	}
	if resp.Type != frameTypeEvents {
		return nil, fmt.Errorf("unexpected TCP response %q", resp.Type)
	}
	return resp.Events, nil
}

func (s *Service) fetchPeerMerkleRootsTCP(ctx context.Context, peer string) (map[string]MerkleZoneRoot, error) {
	resp, err := s.roundTripTCP(ctx, peer, frame{Type: frameTypeMerkleRootsRequest})
	if err != nil {
		return nil, err
	}
	if resp.Type == frameTypeError {
		return nil, errors.New(resp.Error)
	}
	if resp.Type != frameTypeMerkleRoots {
		return nil, fmt.Errorf("unexpected TCP response %q", resp.Type)
	}
	if resp.MerkleRoots == nil {
		resp.MerkleRoots = map[string]MerkleZoneRoot{}
	}
	return resp.MerkleRoots, nil
}

func (s *Service) fetchPeerMerkleBranchesTCP(ctx context.Context, peer, zone string) (map[string]MerkleBranch, error) {
	resp, err := s.roundTripTCP(ctx, peer, frame{Type: frameTypeMerkleBranchesRequest, Zone: zone})
	if err != nil {
		return nil, err
	}
	if resp.Type == frameTypeError {
		return nil, errors.New(resp.Error)
	}
	if resp.Type != frameTypeMerkleBranches {
		return nil, fmt.Errorf("unexpected TCP response %q", resp.Type)
	}
	if resp.MerkleBranches == nil {
		resp.MerkleBranches = map[string]MerkleBranch{}
	}
	return resp.MerkleBranches, nil
}

func (s *Service) fetchPeerMerkleLeavesTCP(ctx context.Context, peer, zone string, prefixes []string) (map[string]MerkleLeaf, error) {
	resp, err := s.roundTripTCP(ctx, peer, frame{Type: frameTypeMerkleLeavesRequest, Zone: zone, Prefixes: prefixes})
	if err != nil {
		return nil, err
	}
	if resp.Type == frameTypeError {
		return nil, errors.New(resp.Error)
	}
	if resp.Type != frameTypeMerkleLeaves {
		return nil, fmt.Errorf("unexpected TCP response %q", resp.Type)
	}
	if resp.MerkleLeaves == nil {
		resp.MerkleLeaves = map[string]MerkleLeaf{}
	}
	return resp.MerkleLeaves, nil
}

func (s *Service) fetchPeerMerkleRepairEventsTCP(ctx context.Context, peer string, entities []string) ([]Event, error) {
	resp, err := s.roundTripTCP(ctx, peer, frame{Type: frameTypeMerkleRepairRequest, Entities: entities})
	if err != nil {
		return nil, err
	}
	if resp.Type == frameTypeError {
		return nil, errors.New(resp.Error)
	}
	if resp.Type != frameTypeEvents {
		return nil, fmt.Errorf("unexpected TCP response %q", resp.Type)
	}
	return resp.Events, nil
}

func (s *Service) roundTripTCP(ctx context.Context, peer string, req frame) (frame, error) {
	timeout := time.Duration(liveConfig().Distributed.PushTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", tcpPeerAddr(peer))
	if err != nil {
		return frame{}, err
	}
	defer conn.Close()
	if useTLSTransport(peer) {
		cfg, err := clientTLSConfig(peer)
		if err != nil {
			return frame{}, err
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.Handshake(); err != nil {
			return frame{}, err
		}
		conn = tlsConn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := s.dialTCPHello(conn); err != nil {
		return frame{}, err
	}
	if err := writeFrame(conn, req); err != nil {
		return frame{}, err
	}
	return readFrame(conn)
}

func (s *Service) dialTCPHello(conn net.Conn) error {
	hello, err := localHelloFrame()
	if err != nil {
		return err
	}
	if err := writeFrame(conn, hello); err != nil {
		return err
	}
	resp, err := readFrame(conn)
	if err != nil {
		return err
	}
	if resp.Type == frameTypeError {
		return errors.New(resp.Error)
	}
	if resp.Type != frameTypeHello {
		return fmt.Errorf("unexpected TCP hello response %q", resp.Type)
	}
	if err := verifyHelloFrame(resp); err != nil {
		return err
	}
	return verifyTLSConnNode(conn, resp.NodeID)
}

func (s *Service) acceptTCPIntro(ctx context.Context, conn net.Conn) (bool, error) {
	req, err := readFrame(conn)
	if err != nil {
		return false, err
	}
	if req.Type == frameTypeJoinRequest {
		if req.JoinRequest == nil {
			_ = writeFrame(conn, frame{Type: frameTypeError, Error: "missing join_request"})
			return false, errors.New("missing join_request")
		}
		applied, err := s.SubmitJoinRequest(ctx, *req.JoinRequest, req.AutoAccept)
		if err != nil {
			_ = writeFrame(conn, frame{Type: frameTypeError, Error: err.Error()})
			return false, err
		}
		_ = writeFrame(conn, frame{Type: frameTypeAck, Applied: applied})
		return false, nil
	}
	if req.Type != frameTypeHello {
		_ = writeFrame(conn, frame{Type: frameTypeError, Error: "missing HELLO"})
		return false, errors.New("missing HELLO")
	}
	if err := verifyHelloFrame(req); err != nil {
		_ = writeFrame(conn, frame{Type: frameTypeError, Error: err.Error()})
		return false, err
	}
	if err := verifyTLSConnNode(conn, req.NodeID); err != nil {
		_ = writeFrame(conn, frame{Type: frameTypeError, Error: err.Error()})
		return false, err
	}
	hello, err := localHelloFrame()
	if err != nil {
		_ = writeFrame(conn, frame{Type: frameTypeError, Error: err.Error()})
		return false, err
	}
	return true, writeFrame(conn, hello)
}

func localHelloFrame() (frame, error) {
	live := liveConfig()
	nodeID := strings.TrimSpace(live.Distributed.NodeID)
	if nodeID == "" {
		return frame{}, errors.New("distributed node_id is required")
	}
	nonce, err := newNonce()
	if err != nil {
		return frame{}, err
	}
	proof, err := signHello(live.Distributed.PrivateKey, nodeID, nonce)
	if err != nil {
		return frame{}, err
	}
	return frame{Type: frameTypeHello, NodeID: nodeID, Nonce: nonce, Proof: proof}, nil
}

func verifyHelloFrame(f frame) error {
	if f.Type != frameTypeHello {
		return fmt.Errorf("unexpected hello frame type %q", f.Type)
	}
	if strings.TrimSpace(f.NodeID) == "" || f.Nonce == "" || f.Proof == "" {
		return errors.New("invalid HELLO frame")
	}
	pubB64 := liveConfig().Distributed.PeerPublicKeys[f.NodeID]
	if pubB64 == "" {
		return fmt.Errorf("no public key configured for distributed peer %q", f.NodeID)
	}
	pub, err := publicKey(pubB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(f.Proof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, helloPayload(f.NodeID, f.Nonce), sig) {
		return errors.New("invalid HELLO proof")
	}
	return nil
}

func signHello(privateKeyB64, nodeID, nonce string) (string, error) {
	priv, err := privateKey(privateKeyB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, helloPayload(nodeID, nonce))), nil
}

func helloPayload(nodeID, nonce string) []byte {
	return []byte("go53-sync-hello-v1:" + nodeID + ":" + nonce)
}

func newNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func serverTLSConfig() (*tls.Config, error) {
	cert, err := localTLSCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		Certificates:             []tls.Certificate{cert},
		ClientAuth:               tls.RequestClientCert,
		PreferServerCipherSuites: false,
	}, nil
}

func clientTLSConfig(_ string) (*tls.Config, error) {
	cert, err := localTLSCertificate()
	if err != nil {
		return nil, err
	}
	// Trust is established by Ed25519 public-key pinning (peer_public_keys), not by
	// PKI chain/hostname validation. Standard verification would reject peers reached
	// by IP literal (the auto-generated certs only carry the node_id as a DNS SAN), so
	// we disable it and pin the peer key in VerifyConnection instead. The server side
	// likewise pins the client cert via RequireAnyClientCert + verifyPeerCertificate.
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPeerPublicKey(state.PeerCertificates)
		},
	}, nil
}

func localTLSCertificate() (tls.Certificate, error) {
	live := liveConfig()
	nodeID := strings.TrimSpace(live.Distributed.NodeID)
	if nodeID == "" {
		return tls.Certificate{}, errors.New("distributed node_id is required")
	}
	cacheKey := nodeID + "\x00" + strings.TrimSpace(live.Distributed.PrivateKey)
	tlsCertMu.Lock()
	if tlsCertCacheKey == cacheKey && len(tlsCertCache.Certificate) > 0 {
		cert := tlsCertCache
		tlsCertMu.Unlock()
		return cert, nil
	}
	tlsCertMu.Unlock()

	priv, err := privateKey(live.Distributed.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	serialBytes := sha256.Sum256([]byte("go53-sync-tls-v1:" + nodeID + ":" + base64.StdEncoding.EncodeToString(pub)))
	serial := new(big.Int).SetBytes(serialBytes[:16])
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: nodeID,
		},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{nodeID},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
	tlsCertMu.Lock()
	tlsCertCacheKey = cacheKey
	tlsCertCache = cert
	tlsCertMu.Unlock()
	return cert, nil
}

func TLSCertificatePEM(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
}

func TLSCertificateFingerprint(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("missing peer TLS certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("peer TLS certificate must use Ed25519")
	}
	for _, configured := range liveConfig().Distributed.PeerPublicKeys {
		allowed, err := publicKey(configured)
		if err != nil {
			continue
		}
		if pub.Equal(allowed) {
			return nil
		}
	}
	return errors.New("peer TLS certificate public key is not trusted")
}

func verifyPeerPublicKey(peerCerts []*x509.Certificate) error {
	if len(peerCerts) == 0 {
		return errors.New("missing peer TLS certificate")
	}
	pub, ok := peerCerts[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("peer TLS certificate must use Ed25519")
	}
	for _, configured := range liveConfig().Distributed.PeerPublicKeys {
		allowed, err := publicKey(configured)
		if err != nil {
			continue
		}
		if pub.Equal(allowed) {
			return nil
		}
	}
	return errors.New("peer TLS certificate public key is not trusted")
}

func verifyTLSConnNode(conn net.Conn, nodeID string) error {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("missing peer TLS certificate")
	}
	expectedB64 := liveConfig().Distributed.PeerPublicKeys[nodeID]
	if expectedB64 == "" {
		return fmt.Errorf("no public key configured for distributed peer %q", nodeID)
	}
	expected, err := publicKey(expectedB64)
	if err != nil {
		return err
	}
	actual, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("peer TLS certificate must use Ed25519")
	}
	if !actual.Equal(expected) {
		return fmt.Errorf("peer TLS certificate does not match distributed node %q", nodeID)
	}
	return nil
}

func writeFrame(w io.Writer, f frame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(data) > maxFrameBytes {
		return fmt.Errorf("frame too large: %d bytes", len(data))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readFrame(r io.Reader) (frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return frame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > maxFrameBytes {
		return frame{}, fmt.Errorf("invalid frame size %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return frame{}, err
	}
	var out frame
	if err := json.Unmarshal(data, &out); err != nil {
		return frame{}, err
	}
	return out, nil
}

func syncListenAddr() string {
	live := liveConfig()
	host := strings.TrimSpace(live.Distributed.SyncBindHost)
	port := strings.TrimSpace(live.Distributed.SyncPort)
	if port == "" {
		return ""
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if strings.Contains(port, ":") {
		if strings.HasPrefix(port, ":") {
			return host + port
		}
		return port
	}
	return net.JoinHostPort(host, port)
}

func tcpPeerAddr(peer string) string {
	peer = strings.TrimSpace(peer)
	peer = strings.TrimPrefix(peer, "tcp://")
	peer = strings.TrimPrefix(peer, "tls://")
	peer = strings.TrimPrefix(peer, "mtls://")
	if strings.Contains(peer, "://") {
		return peer
	}
	if _, err := strconv.Atoi(peer); err == nil {
		return net.JoinHostPort("127.0.0.1", peer)
	}
	return peer
}

func tlsTransportEnabled() bool {
	transport := distributedTransport()
	return transport == "tls" || transport == "mtls"
}

func useTLSTransport(peer string) bool {
	peer = strings.TrimSpace(strings.ToLower(peer))
	if strings.HasPrefix(peer, "tls://") || strings.HasPrefix(peer, "mtls://") {
		return true
	}
	if strings.HasPrefix(peer, "tcp://") || strings.HasPrefix(peer, "http://") || strings.HasPrefix(peer, "https://") {
		return false
	}
	return tlsTransportEnabled()
}

func tlsServerName(peer string) string {
	addr := tcpPeerAddr(peer)
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	return strings.Trim(addr, "[]")
}
