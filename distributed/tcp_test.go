package distributed

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"net"
	"testing"

	"go53/config"
)

func TestTCPFrameRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	want := frame{
		Type:   frameTypeEventsRequest,
		Origin: "node-a",
		After:  42,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeFrame(left, want)
	}()

	got, err := readFrame(right)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if got.Type != want.Type || got.Origin != want.Origin || got.After != want.After {
		t.Fatalf("frame = %#v, want %#v", got, want)
	}
}

func TestHandleTCPFrameRequests(t *testing.T) {
	aPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	bPriv, bPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}
	svc := newTestService(t, "node-a", aPriv, map[string]string{"node-b": bPub})
	ctx := context.Background()
	entity := entityKey("example.test.", "A", "www")
	event := Event{
		EventID:   "event-1",
		Origin:    "node-b",
		Seq:       1,
		Entity:    entity,
		Zone:      "example.test.",
		RRType:    "A",
		Name:      "www",
		Operation: OperationUpsert,
		Value:     json.RawMessage(`{"ip":"192.0.2.1","ttl":300}`),
		Vector:    map[string]uint64{"node-b": 1},
		CreatedAt: 1,
	}
	event.Signature, err = signEvent(bPriv, event)
	if err != nil {
		t.Fatalf("signEvent: %v", err)
	}

	resp := svc.handleTCPFrame(ctx, frame{Type: frameTypeEvent, Event: &event})
	if resp.Type != frameTypeAck || !resp.Applied {
		t.Fatalf("EVENT response = %#v, want applied ACK", resp)
	}
	resp = svc.handleTCPFrame(ctx, frame{Type: frameTypeVectorRequest})
	if resp.Type != frameTypeVector || resp.Vector["node-b"] != 1 {
		t.Fatalf("VECTOR response = %#v", resp)
	}
	resp = svc.handleTCPFrame(ctx, frame{Type: frameTypeEventsRequest, Origin: "node-b", After: 0})
	if resp.Type != frameTypeEvents || len(resp.Events) != 1 {
		t.Fatalf("EVENTS response = %#v", resp)
	}

	if err := svc.store.PutRecordRaw("example.test.", "AAAA", "www", []any{map[string]any{"ip": "2001:db8::1"}}); err != nil {
		t.Fatalf("PutRecordRaw: %v", err)
	}
	resp = svc.handleTCPFrame(ctx, frame{Type: frameTypeMerkleRootsRequest})
	if resp.Type != frameTypeMerkleRoots || resp.MerkleRoots["example.test."].Root == "" {
		t.Fatalf("MERKLE_ROOTS response = %#v", resp)
	}
	resp = svc.handleTCPFrame(ctx, frame{Type: frameTypeMerkleBranchesRequest, Zone: "example.test."})
	if resp.Type != frameTypeMerkleBranches || len(resp.MerkleBranches) == 0 {
		t.Fatalf("MERKLE_BRANCHES response = %#v", resp)
	}
	resp = svc.handleTCPFrame(ctx, frame{Type: frameTypeMerkleLeavesRequest, Zone: "example.test."})
	if resp.Type != frameTypeMerkleLeaves || len(resp.MerkleLeaves) == 0 {
		t.Fatalf("MERKLE_LEAVES response = %#v", resp)
	}
	resp = svc.handleTCPFrame(ctx, frame{Type: frameTypeMerkleRepairRequest, Entities: []string{entity}})
	if resp.Type != frameTypeEvents || len(resp.Events) != 1 || resp.Events[0].EventID != "event-1" {
		t.Fatalf("MERKLE_REPAIR response = %#v", resp)
	}

	if resp := svc.handleTCPFrame(ctx, frame{Type: frameTypeEvent}); resp.Type != frameTypeError || resp.Error == "" {
		t.Fatalf("missing EVENT response = %#v, want error", resp)
	}
	if resp := svc.handleTCPFrame(ctx, frame{Type: "NOPE"}); resp.Type != frameTypeError || resp.Error == "" {
		t.Fatalf("unknown response = %#v, want error", resp)
	}
	config.AppConfig.Live.Mode = "primary"
	if resp := svc.handleTCPFrame(ctx, frame{Type: frameTypeVectorRequest}); resp.Type != frameTypeError || resp.Error == "" {
		t.Fatalf("disabled response = %#v, want error", resp)
	}
}

func TestTCPHelloRoundTripOverPipe(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-local", priv, map[string]string{"node-local": pub})
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.acceptTCPHello(left)
	}()
	if err := svc.dialTCPHello(right); err != nil {
		t.Fatalf("dialTCPHello: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("acceptTCPHello: %v", err)
	}
}

func TestHelloFrameVerification(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.Distributed.NodeID = "node-local"
	config.AppConfig.Live.Distributed.PrivateKey = priv
	config.AppConfig.Live.Distributed.PeerPublicKeys = map[string]string{
		"node-local": pub,
	}

	hello, err := localHelloFrame()
	if err != nil {
		t.Fatalf("localHelloFrame: %v", err)
	}
	if err := verifyHelloFrame(hello); err != nil {
		t.Fatalf("verifyHelloFrame: %v", err)
	}

	hello.Proof = hello.Proof[:len(hello.Proof)-2] + "AA"
	if err := verifyHelloFrame(hello); err == nil {
		t.Fatalf("verifyHelloFrame accepted a bad proof")
	}
}

func TestTLSCertificateUsesDistributedKey(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.Distributed.NodeID = "node-local"
	config.AppConfig.Live.Distributed.PrivateKey = priv
	config.AppConfig.Live.Distributed.PeerPublicKeys = map[string]string{
		"node-local": pub,
	}

	cert, err := localTLSCertificate()
	if err != nil {
		t.Fatalf("localTLSCertificate: %v", err)
	}
	certAgain, err := localTLSCertificate()
	if err != nil {
		t.Fatalf("localTLSCertificate again: %v", err)
	}
	if TLSCertificateFingerprint(cert) != TLSCertificateFingerprint(certAgain) {
		t.Fatalf("TLS certificate fingerprint changed for the same distributed key")
	}
	if TLSCertificatePEM(cert) == "" {
		t.Fatalf("TLSCertificatePEM returned empty PEM")
	}
	if TLSCertificateFingerprint(cert) == "" {
		t.Fatalf("TLSCertificateFingerprint returned empty fingerprint")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	got, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T, want ed25519.PublicKey", leaf.PublicKey)
	}
	want, err := publicKey(pub)
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("certificate public key does not match distributed public key")
	}
	if err := verifyPeerCertificate(cert.Certificate, nil); err != nil {
		t.Fatalf("verifyPeerCertificate: %v", err)
	}

	config.AppConfig.Live.Distributed.PeerPublicKeys = map[string]string{}
	if err := verifyPeerCertificate(cert.Certificate, nil); err == nil {
		t.Fatalf("verifyPeerCertificate accepted an untrusted certificate")
	}
}

func TestTransportSelectionSupportsTLS(t *testing.T) {
	config.AppConfig.Live = config.DefaultLiveConfig

	config.AppConfig.Live.Distributed.Transport = "tls"
	if !useSocketTransport("127.0.0.1:19090") || !useTLSTransport("127.0.0.1:19090") {
		t.Fatalf("plain peer did not inherit tls transport")
	}
	if useTLSTransport("tcp://127.0.0.1:19090") {
		t.Fatalf("tcp:// peer unexpectedly used TLS")
	}
	if !useSocketTransport("mtls://127.0.0.1:19090") || !useTLSTransport("mtls://127.0.0.1:19090") {
		t.Fatalf("mtls:// peer did not use TLS socket transport")
	}

	config.AppConfig.Live.Distributed.Transport = "http"
	if useSocketTransport("https://127.0.0.1:18080") {
		t.Fatalf("https peer unexpectedly used socket transport")
	}
}

func TestTCPAddressAndTLSConfigHelpers(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.Distributed.NodeID = "node-local"
	config.AppConfig.Live.Distributed.PrivateKey = priv
	config.AppConfig.Live.Distributed.PeerPublicKeys = map[string]string{"node-local": pub}
	config.AppConfig.Live.Distributed.Transport = "mtls"
	config.AppConfig.Live.Distributed.SyncBindHost = "127.0.0.1"
	config.AppConfig.Live.Distributed.SyncPort = ":53530"

	if got := syncListenAddr(); got != "127.0.0.1:53530" {
		t.Fatalf("syncListenAddr = %q", got)
	}
	config.AppConfig.Live.Distributed.SyncPort = "53531"
	if got := syncListenAddr(); got != "127.0.0.1:53531" {
		t.Fatalf("syncListenAddr numeric = %q", got)
	}
	config.AppConfig.Live.Distributed.SyncPort = ""
	if got := syncListenAddr(); got != "" {
		t.Fatalf("syncListenAddr empty port = %q", got)
	}

	if got := tcpPeerAddr("tls://10.0.0.10:53530"); got != "10.0.0.10:53530" {
		t.Fatalf("tcpPeerAddr tls = %q", got)
	}
	if got := tcpPeerAddr("53530"); got != "127.0.0.1:53530" {
		t.Fatalf("tcpPeerAddr port = %q", got)
	}
	if got := tlsServerName("tls://[2001:db8::1]:53530"); got != "2001:db8::1" {
		t.Fatalf("tlsServerName IPv6 = %q", got)
	}

	serverCfg, err := serverTLSConfig()
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}
	if serverCfg.MinVersion == 0 || len(serverCfg.Certificates) != 1 {
		t.Fatalf("server TLS config incomplete: %#v", serverCfg)
	}
	clientCfg, err := clientTLSConfig("tls://node-local:53530")
	if err != nil {
		t.Fatalf("clientTLSConfig: %v", err)
	}
	if clientCfg.ServerName != "node-local" || len(clientCfg.Certificates) != 1 {
		t.Fatalf("client TLS config incomplete: %#v", clientCfg)
	}
	if err := verifyPeerCertificate(nil, nil); err == nil {
		t.Fatalf("verifyPeerCertificate accepted empty cert list")
	}
}
