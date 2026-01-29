package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHealth(t *testing.T) {
	s := setupServer(t)
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	s.handleHealth(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handleHealth returned wrong status: got %v want %v", status, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("handleHealth returned wrong body: %v", body)
	}
}

func TestHandleMetrics(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	s.handleMetrics(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handleMetrics returned wrong status: got %v want %v", status, http.StatusOK)
	}
}

func TestHandleDocs(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/docs", nil)
	rr := httptest.NewRecorder()

	s.handleDocs(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handleDocs returned wrong status: got %v want %v", status, http.StatusOK)
	}
}
