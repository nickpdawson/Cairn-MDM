package enroll

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/micromdm/plist"
)

type fakeTopics map[string]string

func (f fakeTopics) GetSetting(_ context.Context, key string) (string, error) {
	return f[key], nil
}

func testHandler(topics fakeTopics) *Handler {
	return New(Config{
		Organization: "cairn.example.com",
		CADER:        []byte("der"),
		SCEPURL:      "https://mdm.example.com/scep",
		MDMServerURL: "https://mdm.example.com/mdm",
	}, topics, "apns_topic", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestEnrollNoPushCertIs503(t *testing.T) {
	h := testHandler(fakeTopics{}) // no topic set
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enroll", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no push cert loaded", rr.Code)
	}
}

func TestEnrollServesProfileWithTopic(t *testing.T) {
	topic := "com.apple.mgmt.External.abc"
	h := testHandler(fakeTopics{"apns_topic": topic})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enroll", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-apple-aspen-config" {
		t.Errorf("content-type = %q", ct)
	}

	var prof map[string]any
	if err := plist.Unmarshal(rr.Body.Bytes(), &prof); err != nil {
		t.Fatalf("body is not a valid plist: %v", err)
	}
	if !strings.Contains(rr.Body.String(), topic) {
		t.Error("served profile does not contain the APNs topic")
	}
}
