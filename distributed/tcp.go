package distributed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	frameTypeHello         = "HELLO"
	frameTypeEvent         = "EVENT"
	frameTypeAck           = "ACK"
	frameTypeVectorRequest = "VECTOR_REQUEST"
	frameTypeVector        = "VECTOR"
	frameTypeEventsRequest = "EVENTS_REQUEST"
	frameTypeEvents        = "EVENTS"
	frameTypeError         = "ERROR"

	maxFrameBytes = 16 << 20
)

type frame struct {
	Type    string            `json:"type"`
	NodeID  string            `json:"node_id,omitempty"`
	Nonce   string            `json:"nonce,omitempty"`
	Proof   string            `json:"proof,omitempty"`
	Event   *Event            `json:"event,omitempty"`
	Events  []Event           `json:"events,omitempty"`
	Vector  map[string]uint64 `json:"vector,omitempty"`
	Origin  string            `json:"origin,omitempty"`
	After   uint64            `json:"after,omitempty"`
	Applied bool              `json:"applied,omitempty"`
	Error   string            `json:"error,omitempty"`
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
		go s.handleTCPConn(ctx, conn)
	}
}

func (s *Service) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := s.acceptTCPHello(conn); err != nil {
		log.Printf("distributed: TCP hello failed: %v", err)
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
	return verifyHelloFrame(resp)
}

func (s *Service) acceptTCPHello(conn net.Conn) error {
	req, err := readFrame(conn)
	if err != nil {
		return err
	}
	if req.Type != frameTypeHello {
		_ = writeFrame(conn, frame{Type: frameTypeError, Error: "missing HELLO"})
		return errors.New("missing HELLO")
	}
	if err := verifyHelloFrame(req); err != nil {
		_ = writeFrame(conn, frame{Type: frameTypeError, Error: err.Error()})
		return err
	}
	hello, err := localHelloFrame()
	if err != nil {
		_ = writeFrame(conn, frame{Type: frameTypeError, Error: err.Error()})
		return err
	}
	return writeFrame(conn, hello)
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
	if strings.Contains(peer, "://") {
		return peer
	}
	if _, err := strconv.Atoi(peer); err == nil {
		return net.JoinHostPort("127.0.0.1", peer)
	}
	return peer
}
