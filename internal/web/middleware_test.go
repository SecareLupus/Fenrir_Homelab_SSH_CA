package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	s := &Server{mux: http.NewServeMux()}

	// Create a dummy handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with middleware
	secured := s.securityHeaders(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	secured.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify headers
	tests := []struct {
		name string
		want string
	}{
		{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
		{"X-Frame-Options", "DENY"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}

	for _, tt := range tests {
		if got := rr.Header().Get(tt.name); got != tt.want {
			t.Errorf("Header %q = %q, want %q", tt.name, got, tt.want)
		}
	}

	// CSP is complex, just check if it's there
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Errorf("Content-Security-Policy header is missing")
	}
}
