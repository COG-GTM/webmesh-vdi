package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLimitRangeHeader(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("kvdi", 1024)
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	h := limitRangeHeader(http.FileServer(http.Dir(dir)))

	cases := []struct {
		name   string
		rng    string
		status int
	}{
		{"single range", "bytes=0-9", http.StatusPartialContent},
		{"excessive ranges", "bytes=" + strings.TrimSuffix(strings.Repeat("0-0,", 10000), ","), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
			req.Header.Set("Range", tc.rng)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("expected %d, got %d", tc.status, rec.Code)
			}
			if tc.status == http.StatusOK && rec.Body.String() != content {
				t.Fatalf("expected full asset body, got %d bytes", rec.Body.Len())
			}
		})
	}
}
