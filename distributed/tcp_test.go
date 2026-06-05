package distributed

import (
	"crypto/ed25519"
	"crypto/x509"
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
