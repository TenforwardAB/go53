package distributed

import (
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
