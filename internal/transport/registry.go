package transport

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/airlance/api/internal/domain/account"
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
	AccountID    account.AccountID
}

type ConnectionRegistry struct {
	mu        sync.RWMutex
	conns     map[string]*ActiveConn
	byAccount map[account.AccountID][]string
}

func NewConnectionRegistry() *ConnectionRegistry {
	return &ConnectionRegistry{
		conns:     make(map[string]*ActiveConn),
		byAccount: make(map[account.AccountID][]string),
	}
}

func (r *ConnectionRegistry) Register(conn NoiseConn, accountID account.AccountID) *ActiveConn {
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
		AccountID:    accountID,
	}

	r.mu.Lock()
	r.conns[id] = active
	if accountID != 0 {
		r.byAccount[accountID] = append(r.byAccount[accountID], id)
	}
	r.mu.Unlock()

	return active
}

func (r *ConnectionRegistry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ac, ok := r.conns[id]; ok {
		ids := r.byAccount[ac.AccountID]
		for i, cid := range ids {
			if cid == id {
				r.byAccount[ac.AccountID] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
		if len(r.byAccount[ac.AccountID]) == 0 {
			delete(r.byAccount, ac.AccountID)
		}
	}
	delete(r.conns, id)
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

func (r *ConnectionRegistry) PushToAccount(accountID account.AccountID, frame []byte) bool {
	r.mu.RLock()
	ids := append([]string(nil), r.byAccount[accountID]...)
	r.mu.RUnlock()

	sent := false
	for _, id := range ids {
		r.mu.RLock()
		ac, ok := r.conns[id]
		r.mu.RUnlock()
		if ok && ac.Conn != nil {
			if err := ac.Conn.WriteFrame(frame); err == nil {
				sent = true
			}
		}
	}
	return sent
}
