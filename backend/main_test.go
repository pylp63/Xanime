package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// ─── Test harness ─────────────────────────────────────────────────────────────

// setupTestServer boots the real router against a fresh sqlite DB in a temp
// dir, creating the admin user and returning an authenticated cookie jar.
func setupTestServer(t *testing.T) *testServer {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// httptest requests all originate from the same pseudo-IP; reset the
	// package-level rate limiters so logins from earlier tests don't throttle
	// this one.
	globalLimiter = newIPLimiter()
	authLimiter = &ipLimiter{visitors: make(map[string]*rate.Limiter)}

	dir := t.TempDir()
	t.Setenv("DB_DRIVER", "sqlite3")
	t.Setenv("DB_PATH", filepath.Join(dir, "test.db"))
	t.Setenv("VIDEO_PATH", filepath.Join(dir, "videos"))
	t.Setenv("STATIC_PATH", filepath.Join(dir, "static"))
	t.Setenv("DIST_PATH", filepath.Join(dir, "dist"))
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("REFERER_CHECK", "false")
	os.MkdirAll(filepath.Join(dir, "dist"), 0755)
	os.MkdirAll(filepath.Join(dir, "videos"), 0755)

	initDB()
	t.Cleanup(func() { db.Close() })
	seedAdmin()
	loadStorageSources()

	srv := &testServer{ts: httptest.NewServer(newRouter())}
	t.Cleanup(srv.ts.Close)

	// Login as admin, keep the session cookie for authenticated requests.
	code, body := srv.do("POST", "/api/auth/login", `{"username":"admin","password":"admin"}`, "")
	if code != 200 {
		t.Fatalf("admin login failed: %d %s", code, body)
	}
	var loginResp struct{ Token string `json:"token"` }
	json.Unmarshal([]byte(body), &loginResp)
	if loginResp.Token == "" {
		t.Fatal("login returned no token")
	}
	srv.token = loginResp.Token
	return srv
}

type testServer struct {
	ts    *httptest.Server
	token string
}

func (s *testServer) do(method, path, body, token string) (int, string) {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, s.ts.URL+path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, s.ts.URL+path, nil)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.ts.Config.Handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func (s *testServer) auth(method, path, body string) (int, string) {
	return s.do(method, path, body, s.token)
}

// ─── The bug: settings page calls endpoints that don't exist ─────────────────

// The old settings page did GET /api/settings — backend has no such route, so
// the page rendered empty and "save" silently failed. The new settings page
// manages storage SOURCES via /api/storage-srcs.
func TestSettingsPageStorageSourcesContract(t *testing.T) {
	s := setupTestServer(t)

	// GET /api/storage-srcs lists existing sources without leaking secrets.
	code, body := s.auth("GET", "/api/storage-srcs", "")
	if code != 200 {
		t.Fatalf("list sources: got %d %s", code, body)
	}
	var listResp struct {
		Sources []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Type       string `json:"type"`
			VideoPath  string `json:"video_path"`
			SecretSet  bool   `json:"s3_secret_set"`
		} `json:"sources"`
	}
	if err := json.Unmarshal([]byte(body), &listResp); err != nil {
		t.Fatalf("bad list JSON: %v", err)
	}
	if len(listResp.Sources) == 0 {
		t.Fatal("expected at least the seeded local source")
	}
	if listResp.Sources[0].Type != "local" {
		t.Fatalf("first source should be local, got %q", listResp.Sources[0].Type)
	}
	if strings.Contains(body, "s3_secret_key") || strings.Contains(body, "S3SecretKey") {
		t.Fatal("list response must not contain the secret key value")
	}
}

// ─── Add/delete sources: the "可随时增删" requirement ──────────────────────────

func TestAddAndDeleteStorageSources(t *testing.T) {
	s := setupTestServer(t)

	// Add an NFS source.
	code, body := s.auth("POST", "/api/storage-srcs",
		`{"name":"媒体库NFS","type":"nfs","video_path":"/mnt/nfsmedia"}`)
	if code != 200 && code != 201 {
		t.Fatalf("add nfs source: got %d %s", code, body)
	}
	var addResp struct {
		Sources []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"sources"`
	}
	json.Unmarshal([]byte(body), &addResp)
	var nfsID string
	for _, src := range addResp.Sources {
		if src.Type == "nfs" {
			nfsID = src.ID
		}
	}
	if nfsID == "" {
		t.Fatalf("added nfs source not in list: %s", body)
	}

	// Deleting it must work and remove it from the list.
	code, _ = s.auth("DELETE", "/api/storage-srcs/"+nfsID, "")
	if code != 200 {
		t.Fatalf("delete nfs source: got %d", code)
	}
	_, body = s.auth("GET", "/api/storage-srcs", "")
	if strings.Contains(body, nfsID) {
		t.Fatal("deleted source still listed")
	}
}

func TestAddS3SourceRequiresCredentials(t *testing.T) {
	s := setupTestServer(t)

	// S3 without access/secret keys would generate broken presigned URLs —
	// reject at creation time.
	code, body := s.auth("POST", "/api/storage-srcs",
		`{"name":"minio","type":"s3","s3_endpoint":"http://10.10.10.9:9000","s3_bucket":"media","s3_region":"us-east-1"}`)
	if code != 400 {
		t.Fatalf("s3 without keys must be rejected, got %d %s", code, body)
	}

	// With full credentials it must be accepted.
	code, _ = s.auth("POST", "/api/storage-srcs",
		`{"name":"minio","type":"s3","s3_endpoint":"http://10.10.10.9:9000","s3_bucket":"media","s3_region":"us-east-1","s3_access_key":"AKIA1","s3_secret_key":"SECRET1"}`)
	if code != 200 && code != 201 {
		t.Fatalf("valid s3 source rejected: %d %s", code, body)
	}
}

// The last remaining filesystem source must not be deletable — the platform
// needs at least one place to resolve "bare" video paths against.
func TestCannotDeleteLastSource(t *testing.T) {
	s := setupTestServer(t)

	// The seeded DB has exactly one local source. Delete it → must 400.
	_, body := s.auth("GET", "/api/storage-srcs", "")
	var listResp struct {
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
	}
	json.Unmarshal([]byte(body), &listResp)
	if len(listResp.Sources) != 1 {
		t.Fatalf("expected exactly 1 seeded source, got %d", len(listResp.Sources))
	}
	code, _ := s.auth("DELETE", "/api/storage-srcs/"+listResp.Sources[0].ID, "")
	if code != 400 {
		t.Fatalf("deleting the last source must be rejected, got %d", code)
	}
}

// ─── Streaming across sources ────────────────────────────────────────────────

func TestStreamFromMultipleSources(t *testing.T) {
	s := setupTestServer(t)

	// Create two filesystem sources with real files.
	root := t.TempDir()
	srcA := filepath.Join(root, "a"); os.MkdirAll(srcA, 0755)
	srcB := filepath.Join(root, "b"); os.MkdirAll(srcB, 0755)
	os.WriteFile(filepath.Join(srcA, "ep1.mp4"), []byte("AAAA-video-bytes"), 0644)
	os.WriteFile(filepath.Join(srcB, "ep2.mp4"), []byte("BBBB-video-bytes"), 0644)

	code, body := s.auth("POST", "/api/storage-srcs", fmt.Sprintf(`{"name":"A","type":"local","video_path":%q}`, srcA))
	if code != 200 && code != 201 { t.Fatalf("add A: %d %s", code, body) }
	code, body = s.auth("POST", "/api/storage-srcs", fmt.Sprintf(`{"name":"B","type":"nfs","video_path":%q}`, srcB))
	if code != 200 && code != 201 { t.Fatalf("add B: %d %s", code, body) }

	var listResp struct {
		Sources []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"sources"`
	}
	_, body = s.auth("GET", "/api/storage-srcs", "")
	json.Unmarshal([]byte(body), &listResp)
	ids := map[string]string{}
	for _, src := range listResp.Sources {
		ids[src.Name] = src.ID
	}

	// Stream from each source via the "sourceID:path" contract.
	for name, want := range map[string]string{"A": "AAAA-video-bytes", "B": "BBBB-video-bytes"} {
		file := "ep1.mp4"
		if name == "B" { file = "ep2.mp4" }
		code, body := s.auth("GET", "/api/stream?path="+ids[name]+"/"+file, "")
		if code != 200 {
			t.Fatalf("stream from %s: got %d %s", name, code, body)
		}
		if !strings.Contains(body, want) {
			t.Fatalf("stream from %s returned wrong bytes: %q", name, body)
		}
	}

// Source isolation: A's file must not be reachable through B.
	code, _ = s.auth("GET", "/api/stream?path="+ids["B"]+"/ep1.mp4", "")
	if code != 404 {
		t.Fatalf("cross-source leak: expected 404, got %d", code)
	}
}

// Legacy seeded rows store "videos/1/1.mp4" against a source whose root IS the
// videos dir — streaming must tolerate that duplicated prefix, otherwise every
// pre-existing episode 404s.
func TestStreamToleratesLegacyVideosPrefix(t *testing.T) {
	s := setupTestServer(t)

	// The seeded local source points at $VIDEO_PATH; place a file at
	// <root>/1/1.mp4 and ask for the legacy-prefixed key "videos/1/1.mp4".
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "1"), 0755)
	os.WriteFile(filepath.Join(root, "1", "1.mp4"), []byte("LEGACY-OK"), 0644)

	// Re-point the first source's VideoPath at root (simulating a configured
	// volume) by adding a fresh source and using its ID.
	code, body := s.auth("POST", "/api/storage-srcs", fmt.Sprintf(`{"name":"R","type":"local","video_path":%q}`, root))
	if code != 200 && code != 201 { t.Fatalf("add R: %d %s", code, body) }
	_, body = s.auth("GET", "/api/storage-srcs", "")
	var listResp struct {
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
	}
	json.Unmarshal([]byte(body), &listResp)
	rID := listResp.Sources[len(listResp.Sources)-1].ID

	code, body = s.auth("GET", "/api/stream?path="+rID+"/videos/1/1.mp4", "")
	if code != 200 {
		t.Fatalf("legacy videos/ prefix stream: got %d %s", code, body)
	}
	if !strings.Contains(body, "LEGACY-OK") {
		t.Fatalf("legacy stream returned wrong bytes: %q", body)
	}

	// And the clean form (no prefix) must also work.
	code, body = s.auth("GET", "/api/stream?path="+rID+"/1/1.mp4", "")
	if code != 200 || !strings.Contains(body, "LEGACY-OK") {
		t.Fatalf("clean stream: got %d %s", code, body)
	}
}

// ─── The presign contract both storage kinds must satisfy ────────────────────

func TestPresignLocalAndS3(t *testing.T) {
	s := setupTestServer(t)

	// Local: presign returns a same-origin /api/stream URL.
	code, body := s.auth("GET", "/api/files/presign?key=videos/1/1.mp4", "")
	if code != 200 {
		t.Fatalf("presign local: %d %s", code, body)
	}
	var p struct {
		URL      string `json:"url"`
		Provider string `json:"provider"`
	}
	json.Unmarshal([]byte(body), &p)
	if !strings.HasPrefix(p.URL, "/api/stream?path=") {
		t.Fatalf("local presign URL should be /api/stream, got %q", p.URL)
	}

	// S3: presign returns an absolute presigned URL with a signature.
	code, _ = s.auth("POST", "/api/storage-srcs",
		`{"name":"minio","type":"s3","s3_endpoint":"http://10.10.10.9:9000","s3_bucket":"media","s3_region":"us-east-1","s3_access_key":"AKIA1","s3_secret_key":"SECRET1"}`)
	if code != 200 && code != 201 { t.Fatalf("add s3: %d", code) }
	_, body = s.auth("GET", "/api/storage-srcs", "")
	var listResp struct {
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
	}
	json.Unmarshal([]byte(body), &listResp)
	s3ID := ""
	for _, src := range listResp.Sources {
		if !strings.Contains(src.ID, "local") {
			s3ID = src.ID
		}
	}
	if s3ID == "" { t.Fatal("s3 source missing") }

	code, body = s.auth("GET", "/api/files/presign?key="+s3ID+"/anime/1/1.mp4", "")
	if code != 200 {
		t.Fatalf("presign s3: %d %s", code, body)
	}
	json.Unmarshal([]byte(body), &p)
	if !strings.HasPrefix(p.URL, "http://10.10.10.9:9000/media/") {
		t.Fatalf("s3 presign URL wrong: %q", p.URL)
	}
	if !strings.Contains(p.URL, "X-Amz-Signature=") {
		t.Fatalf("s3 presign URL missing signature: %q", p.URL)
	}
}

// ─── Security invariants that must not regress ───────────────────────────────

func TestStorageAPIRequiresAuth(t *testing.T) {
	s := setupTestServer(t)
	if code, _ := s.do("GET", "/api/storage-srcs", "", ""); code != 401 {
		t.Fatalf("unauthenticated list must 401, got %d", code)
	}
	if code, _ := s.do("POST", "/api/storage-srcs", `{"type":"s3"}`, ""); code != 401 {
		t.Fatalf("unauthenticated add must 401, got %d", code)
	}
}

func TestStreamRejectsPathTraversal(t *testing.T) {
	s := setupTestServer(t)
	_, body := s.auth("GET", "/api/storage-srcs", "")
	var listResp struct {
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
	}
	json.Unmarshal([]byte(body), &listResp)
	first := listResp.Sources[0].ID
	code, _ := s.auth("GET", "/api/stream?path="+first+"/../../etc/passwd", "")
	if code != 403 && code != 404 {
		t.Fatalf("path traversal must be blocked, got %d", code)
	}
}

// CSP must allow presigned S3 media, otherwise the watch page can never play
// S3-hosted videos.
func TestCSPAllowsS3Media(t *testing.T) {
	s := setupTestServer(t)
	req := httptest.NewRequest("GET", s.ts.URL+"/login", nil)
	rec := httptest.NewRecorder()
	s.ts.Config.Handler.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "media-src") {
		t.Fatalf("CSP missing media-src: %q", csp)
	}
	if !strings.Contains(csp, "https:") || !strings.Contains(csp, "http:") {
		t.Fatalf("CSP media-src must allow external presigned URLs: %q", csp)
	}
}

// Sources persist across restarts (stored in the settings table).
func TestSourcesPersistAcrossRestart(t *testing.T) {
	s := setupTestServer(t)
	code, _ := s.auth("POST", "/api/storage-srcs", `{"name":"nfs1","type":"nfs","video_path":"/mnt/nfs1"}`)
	if code != 200 && code != 201 { t.Fatalf("add: %d", code) }

	// Simulate restart: reload from DB into a fresh in-memory slice.
	storageSources = nil
	loadStorageSources()
	found := false
	for _, src := range storageSources {
		if src.Name == "nfs1" {
			found = true
		}
	}
	if !found {
		t.Fatal("nfs1 source did not survive reload")
	}
}
