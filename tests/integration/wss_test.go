package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/resoul/wireauth/v2"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/transport/ws"
	fbWS "airlance.org/api/internal/transport/ws/airlance/ws"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Airlance Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func TestWSS_SuccessfulHandshakeOverTLS(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	cfg := &config.Config{
		RequireTLS:              true,
		AllowedWSOrigins:        []string{"*"},
		MaxWSConnections:        10,
		MaxWSConnectionsPerIP:   10,
		MaxWSConnectionsPerUser: 5,
		WSPreUpgradeTimeout:     2 * time.Second,
		WSHandshakeTimeout:      2 * time.Second,
		MaxWSFrameBytes:         64 * 1024,
		AuditSubjectHMACKeyRing: config.KeyRing{
			CurrentKeyID: 1,
			Keys:         map[uint16][]byte{1: []byte("01234567890123456789012345678901")},
		},
	}

	ticketRepo := &mockTicketRepo{}
	sessionRepo := &mockSessionRepo{}
	deviceRepo := &mockDeviceRepo{}
	registry := ws.NewConnectionRegistry()
	router := ws.NewRouter(1, 1, nil, nil)
	log := logger.New("error", "json")

	server := ws.NewServer(ticketRepo, sessionRepo, deviceRepo, nil, nil, registry, router, nil, cfg, log)

	ts := httptest.NewUnstartedServer(server)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	ts.StartTLS()
	defer ts.Close()

	// 1. Issue valid ticket
	ticketID := "test-wss-ticket-123"
	_ = ticketRepo.Create(context.Background(), &wsticket.Ticket{
		ID:        ticketID,
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}, 1*time.Minute)

	// 2. Connect via WSS dialer
	wssURL := "wss" + strings.TrimPrefix(ts.URL, "https") + "?ticket=" + ticketID
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	conn, resp, err := dialer.Dial(wssURL, nil)
	if err != nil {
		t.Fatalf("WSS dial failed: err=%v, resp=%v", err, resp)
	}
	defer func() { _ = conn.Close() }()

	// 3. Construct and send encrypted Ping message over WSS
	b := flatbuffers.NewBuilder(128)
	fbWS.PingStart(b)
	fbWS.PingAddTimestamp(b, uint64(time.Now().UnixMilli()))
	pingOffset := fbWS.PingEnd(b)

	fbWS.EnvelopeStart(b)
	fbWS.EnvelopeAddProtocolVersion(b, 1)
	fbWS.EnvelopeAddMessageId(b, 42)
	fbWS.EnvelopeAddPayloadType(b, fbWS.PayloadPing)
	fbWS.EnvelopeAddPayload(b, pingOffset)
	envOffset := fbWS.EnvelopeEnd(b)
	b.Finish(envOffset)
	pingPayload := b.FinishedBytes()

	testKey := make([]byte, 32)
	encryptedPing, err := wireauth.EncryptAESGCM(testKey, pingPayload, 1)
	if err != nil {
		t.Fatalf("failed to encrypt ping: %v", err)
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, encryptedPing); err != nil {
		t.Fatalf("failed to write encrypted ping message: %v", err)
	}

	// 4. Read encrypted Pong response from server over WSS
	_, pongEncrypted, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read pong: %v", err)
	}

	decryptedPong, seq, err := wireauth.DecryptAESGCM(testKey, pongEncrypted)
	if err != nil {
		t.Fatalf("failed to decrypt pong: %v", err)
	}

	if seq != 1 {
		t.Errorf("expected sequence 1 for first server message, got %d", seq)
	}

	envelope := fbWS.GetRootAsEnvelope(decryptedPong, 0)
	if envelope.PayloadType() != fbWS.PayloadPong {
		t.Errorf("expected PayloadPong, got %v", envelope.PayloadType())
	}
}
