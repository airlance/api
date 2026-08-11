package transport

import (
	"context"
	"sync"

	"github.com/airlance/api/internal/domain/account"
)

type MessageRouter struct {
	mu       sync.Mutex
	queues   map[account.AccountID]chan func(ctx context.Context) error
	ctx      context.Context
	cancel   context.CancelFunc
	workerWg sync.WaitGroup
}

func NewMessageRouter() *MessageRouter {
	ctx, cancel := context.WithCancel(context.Background())
	return &MessageRouter{
		queues: make(map[account.AccountID]chan func(ctx context.Context) error),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (r *MessageRouter) Submit(accountID account.AccountID, task func(ctx context.Context) error) {
	r.mu.Lock()
	ch, ok := r.queues[accountID]
	if !ok {
		ch = make(chan func(ctx context.Context) error, 64)
		r.queues[accountID] = ch
		r.workerWg.Add(1)
		go r.runWorker(accountID, ch)
	}
	r.mu.Unlock()

	select {
	case ch <- task:
	case <-r.ctx.Done():
	}
}

func (r *MessageRouter) runWorker(accountID account.AccountID, ch chan func(ctx context.Context) error) {
	defer r.workerWg.Done()
	for {
		select {
		case task, ok := <-ch:
			if !ok {
				return
			}
			_ = task(r.ctx)
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *MessageRouter) Close() {
	r.cancel()
	r.mu.Lock()
	for _, ch := range r.queues {
		close(ch)
	}
	r.queues = make(map[account.AccountID]chan func(ctx context.Context) error)
	r.mu.Unlock()
	r.workerWg.Wait()
}
