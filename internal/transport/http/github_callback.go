package http

import (
	"net/http"
	"net/url"
)

// githubCallbackHandler bridges GitHub's OAuth redirect (which must be an
// https:// URL) back to the native client's custom URL scheme.
//
// It does NOT exchange the code or talk to GitHub itself — the actual
// exchange happens in LoginByGithubRPC (see
// internal/transport/grpc/authservice/server.go), which the client calls
// over gRPC/wireauthgrpc once it has the code. This handler's only job is
// to hand the `code` (and `state`, for CSRF validation) from the query
// string back to the app via a redirect to appCallbackURL.
type githubCallbackHandler struct {
	appCallbackURL string
}

func newGithubCallbackHandler(appCallbackURL string) *githubCallbackHandler {
	return &githubCallbackHandler{appCallbackURL: appCallbackURL}
}

func (h *githubCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	dest, err := url.Parse(h.appCallbackURL)
	if err != nil {
		http.Error(w, "server misconfigured", http.StatusInternalServerError)
		return
	}
	destQuery := dest.Query()

	if ghErr := q.Get("error"); ghErr != "" {
		destQuery.Set("error", ghErr)
		dest.RawQuery = destQuery.Encode()
		http.Redirect(w, r, dest.String(), http.StatusFound)
		return
	}

	code := q.Get("code")
	if code == "" {
		destQuery.Set("error", "missing_code")
		dest.RawQuery = destQuery.Encode()
		http.Redirect(w, r, dest.String(), http.StatusFound)
		return
	}

	destQuery.Set("code", code)
	// state is round-tripped as-is; the client generated it before
	// opening the browser and must verify it matches on return.
	if state := q.Get("state"); state != "" {
		destQuery.Set("state", state)
	}
	dest.RawQuery = destQuery.Encode()

	http.Redirect(w, r, dest.String(), http.StatusFound)
}
