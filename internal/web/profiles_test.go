package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dzsec/cairn/internal/auth"
)

const testProfileXML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>com.example.test</string>
  <key>PayloadUUID</key><string>11111111-2222-3333-4444-555555555555</string>
  <key>PayloadDisplayName</key><string>Test Profile</string>
  <key>PayloadContent</key><array>
    <dict>
      <key>PayloadType</key><string>com.apple.wifi.managed</string>
      <key>PayloadIdentifier</key><string>com.example.test.1</string>
      <key>PayloadUUID</key><string>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</string>
    </dict>
  </array>
</dict></plist>`

// adminSession creates a live session directly (bypassing the login form) and
// returns its cookie + CSRF token.
func adminSession(t *testing.T, sessions *auth.SessionStore) (*http.Cookie, string) {
	t.Helper()
	sess, err := sessions.Create(context.Background(),
		auth.Identity{Username: "nick", Role: auth.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: SessionCookie, Value: sess.Token}, sess.CSRF
}

func TestProfileUploadListDetail(t *testing.T) {
	app, sessions, _ := testApp(t)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)

	// Upload.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("csrf", csrf)
	fw, _ := mw.CreateFormFile("profile", "test.mobileconfig")
	_, _ = fw.Write([]byte(testProfileXML))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/profiles/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "/admin/profiles/") {
		t.Fatalf("upload = %d -> %q, want 303 -> profile detail", rr.Code, rr.Header().Get("Location"))
	}
	detailURL := strings.Split(rr.Header().Get("Location"), "?")[0]

	// Library list shows it.
	req = httptest.NewRequest(http.MethodGet, "/admin/profiles", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "com.example.test") {
		t.Fatalf("profiles list = %d, missing identifier", rr.Code)
	}

	// Detail page renders.
	req = httptest.NewRequest(http.MethodGet, detailURL, nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "com.apple.wifi.managed") {
		t.Fatalf("profile detail = %d, missing payload type", rr.Code)
	}

	// Download round-trips the exact bytes.
	req = httptest.NewRequest(http.MethodGet, detailURL+"/download", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != testProfileXML {
		t.Fatalf("download = %d, bytes mismatch", rr.Code)
	}
}

func TestProfileUploadRejectsGarbageAndBadCSRF(t *testing.T) {
	app, sessions, _ := testApp(t)
	m := mux(app)
	cookie, csrf := adminSession(t, sessions)

	// Garbage file: redirected back with an error, nothing saved.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("csrf", csrf)
	fw, _ := mw.CreateFormFile("profile", "junk.mobileconfig")
	_, _ = fw.Write([]byte("not a plist"))
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/profiles/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Fatalf("garbage upload = %d -> %q, want redirect with error", rr.Code, rr.Header().Get("Location"))
	}

	// Missing CSRF: forbidden.
	body.Reset()
	mw = multipart.NewWriter(&body)
	fw, _ = mw.CreateFormFile("profile", "test.mobileconfig")
	_, _ = fw.Write([]byte(testProfileXML))
	mw.Close()
	req = httptest.NewRequest(http.MethodPost, "/admin/profiles/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	m.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("upload without CSRF = %d, want 403", rr.Code)
	}
}
