package v1

import (
	"encoding/json"
	"net/http"

	"airlance.org/api/internal/infrastructure/logger"
)

type errorResponse struct {
	Error errorDetail `json:"error"`
}

func writeOperationError(w http.ResponseWriter, r *http.Request, status int, code, message string, err error) {
	logger.FromContext(r.Context()).Error(err, "HTTP operation failed", "error_code", code)
	writeError(w, status, code, message)
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{
		Error: errorDetail{
			Code:    code,
			Message: message,
		},
	})
}
