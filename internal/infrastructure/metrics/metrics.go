package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
)

type Registry struct {
	mu sync.RWMutex

	httpRequestsTotal       map[string]*uint64
	authEventsTotal         map[string]*uint64
	rateLimitHitsTotal      map[string]*uint64
	wsHandshakeErrorsTotal  uint64
	wsMessagesSentTotal     uint64
	wsMessagesReceivedTotal uint64
	wsActiveConnections     int64
}

func NewRegistry() *Registry {
	return &Registry{
		httpRequestsTotal:  make(map[string]*uint64),
		authEventsTotal:    make(map[string]*uint64),
		rateLimitHitsTotal: make(map[string]*uint64),
	}
}

func (r *Registry) IncHTTPRequests(method, path string, status int) {
	key := fmt.Sprintf(`method="%s",path="%s",status="%d"`, method, path, status)
	r.mu.Lock()
	ptr, ok := r.httpRequestsTotal[key]
	if !ok {
		var val uint64
		ptr = &val
		r.httpRequestsTotal[key] = ptr
	}
	r.mu.Unlock()
	atomic.AddUint64(ptr, 1)
}

func (r *Registry) IncAuthEvents(ceremony, result string) {
	key := fmt.Sprintf(`ceremony="%s",result="%s"`, ceremony, result)
	r.mu.Lock()
	ptr, ok := r.authEventsTotal[key]
	if !ok {
		var val uint64
		ptr = &val
		r.authEventsTotal[key] = ptr
	}
	r.mu.Unlock()
	atomic.AddUint64(ptr, 1)
}

func (r *Registry) IncRateLimitHits(scope string) {
	key := fmt.Sprintf(`scope="%s"`, scope)
	r.mu.Lock()
	ptr, ok := r.rateLimitHitsTotal[key]
	if !ok {
		var val uint64
		ptr = &val
		r.rateLimitHitsTotal[key] = ptr
	}
	r.mu.Unlock()
	atomic.AddUint64(ptr, 1)
}

func (r *Registry) IncWSHandshakeErrors() {
	atomic.AddUint64(&r.wsHandshakeErrorsTotal, 1)
}

func (r *Registry) IncWSMessagesSent() {
	atomic.AddUint64(&r.wsMessagesSentTotal, 1)
}

func (r *Registry) IncWSMessagesReceived() {
	atomic.AddUint64(&r.wsMessagesReceivedTotal, 1)
}

func (r *Registry) SetWSConnections(count int64) {
	atomic.StoreInt64(&r.wsActiveConnections, count)
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		r.mu.RLock()
		defer r.mu.RUnlock()

		fmt.Fprintln(w, "# HELP http_requests_total Total number of HTTP requests processed")
		fmt.Fprintln(w, "# TYPE http_requests_total counter")
		for labels, countPtr := range r.httpRequestsTotal {
			fmt.Fprintf(w, "http_requests_total{%s} %d\n", labels, atomic.LoadUint64(countPtr))
		}

		fmt.Fprintln(w, "# HELP auth_events_total Total authentication ceremonies outcome")
		fmt.Fprintln(w, "# TYPE auth_events_total counter")
		for labels, countPtr := range r.authEventsTotal {
			fmt.Fprintf(w, "auth_events_total{%s} %d\n", labels, atomic.LoadUint64(countPtr))
		}

		fmt.Fprintln(w, "# HELP ratelimit_rejections_total Total rate limit rejections")
		fmt.Fprintln(w, "# TYPE ratelimit_rejections_total counter")
		for labels, countPtr := range r.rateLimitHitsTotal {
			fmt.Fprintf(w, "ratelimit_rejections_total{%s} %d\n", labels, atomic.LoadUint64(countPtr))
		}

		fmt.Fprintln(w, "# HELP ws_active_connections Current active WebSocket connections")
		fmt.Fprintln(w, "# TYPE ws_active_connections gauge")
		fmt.Fprintf(w, "ws_active_connections %d\n", atomic.LoadInt64(&r.wsActiveConnections))

		fmt.Fprintln(w, "# HELP ws_handshake_errors_total Total failed WS handshakes")
		fmt.Fprintln(w, "# TYPE ws_handshake_errors_total counter")
		fmt.Fprintf(w, "ws_handshake_errors_total %d\n", atomic.LoadUint64(&r.wsHandshakeErrorsTotal))
	})
}
