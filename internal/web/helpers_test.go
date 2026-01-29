package web

import (
	"net/http/httptest"
	"testing"
)

func TestIsSecure(t *testing.T) {
	s := &Server{}

	// Case 1: Standard HTTPS
	req := httptest.NewRequest("GET", "https://example.com", nil)
	if !s.isSecure(req) {
		t.Errorf("isSecure failed to detect native HTTPS")
	}

	// Case 2: HTTP
	req = httptest.NewRequest("GET", "http://example.com", nil)
	if s.isSecure(req) {
		t.Errorf("isSecure incorrectly detected HTTP as secure")
	}

	// Case 3: X-Forwarded-Proto
	req = httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if !s.isSecure(req) {
		t.Errorf("isSecure failed to detect X-Forwarded-Proto: https")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter()

	key := "test-ip"

	// Allow 10 attempts
	for i := 0; i < 10; i++ {
		if !rl.allow(key) {
			t.Errorf("RateLimiter blocked attempt %d which should be allowed", i+1)
		}
	}

	// 11th should be blocked
	if rl.allow(key) {
		t.Errorf("RateLimiter failed to block 11th attempt")
	}

	// Different key should be allowed
	if !rl.allow("other-ip") {
		t.Errorf("RateLimiter incorrectly blocked different key")
	}
}

func TestSafeRedirectPath(t *testing.T) {
	s := &Server{}

	tests := []struct {
		input string
		want  string
	}{
		{"/admin", "/admin"},
		{"http://evil.com/path", "/"},
		{"//evil.com", "/"},
		{"/path/with/more", "/path/with/more"},
		{"", "/"},
	}

	for _, tt := range tests {
		if got := s.safeRedirectPath(tt.input); got != tt.want {
			t.Errorf("safeRedirectPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
