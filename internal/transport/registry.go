package transport

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type NoiseConn interface {
	ReadFrame() ([]byte, error)
	WriteFrame(data []byte) error
	SetReadDeadline(t time.Time) error
	RemoteStaticKey() []byte
	Close() error
}

type ActiveConn struct {
	ID           string
	Conn         NoiseConn
	DevicePubKey []byte
}

type ConnectionRegistry struct {
	mu    sync.RWMutex
	conns map[string]*ActiveConn
}

func NewConnectionRegistry() *ConnectionRegistry {
	return &ConnectionRegistry{
		conns: make(map[string]*ActiveConn),
	}
}

func (r *ConnectionRegistry) Register(conn NoiseConn) *ActiveConn {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)

	var pubKey []byte
	if conn != nil {
		pubKey = conn.RemoteStaticKey()
	}

	active := &ActiveConn{
		ID:           id,
		Conn:         conn,
		DevicePubKey: pubKey,
	}

	r.mu.Lock()
	r.conns[id] = active
	r.mu.Unlock()

	return active
}

func (r *ConnectionRegistry) Unregister(id string) {
	r.mu.Lock()
	delete(r.conns, id)
	r.mu.Unlock()
}

func (r *ConnectionRegistry) Get(id string) (*ActiveConn, bool) {
	r.mu.RLock()
	active, ok := r.conns[id]
	r.mu.RUnlock()
	return active, ok
}

func (r *ConnectionRegistry) Count() int {
	r.mu.RLock()
	n := len(r.conns)
	r.mu.RUnlock()
	return n
}
