package transport

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airlance/api/internal/domain/account"
)

func TestMessageRouter_SequentialPerAccount(t *testing.T) {
	router := NewMessageRouter()
	defer router.Close()

	var counter int64
	accID := account.AccountID(10)

	for i := 0; i < 5; i++ {
		router.Submit(accID, func(ctx context.Context) error {
			atomic.AddInt64(&counter, 1)
			return nil
		})
	}

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt64(&counter) != 5 {
		t.Fatalf("expected counter = 5, got %d", atomic.LoadInt64(&counter))
	}
}
