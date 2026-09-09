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

// ─── Library: real directory / file scanning ──────────────────────────────────

// The personal library lists animes from REAL directories under a filesystem
// source and episodes from REAL video files, with natural ordering and no
// rating metadata.
func TestLibraryScansRealDirectories(t *testing.T) {
	s := setupTestServer(t)

	root := t.TempDir()
	// anime A: 3 eps out of order + cover image
	os.MkdirAll(filepath.Join(root, "葬送的芙莉莲"), 0755)
	os.WriteFile(filepath.Join(root, "葬送的芙莉莲", "第10话.mkv"), []byte("A10"), 0644)
	os.WriteFile(filepath.Join(root, "葬送的芙莉莲", "第02话.mkv"), []byte("A2"), 0644)
	os.WriteFile(filepath.Join(root, "葬送的芙莉莲", "第01话.mkv"), []byte("A1"), 0644)
	os.WriteFile(filepath.Join(root, "葬送的芙莉莲", "cover.jpg"), []byte("JPGDATA"), 0644)
	// anime B: 1 ep, year in name, no cover
	os.MkdirAll(filepath.Join(root, "孤独摇滚 (2022)"), 0755)
	os.WriteFile(filepath.Join(root, "孤独摇滚 (2022)", "EP01.mp4"), []byte("B1"), 0644)
	// non-anime entries: empty dir, hidden dir, loose file
	os.MkdirAll(filepath.Join(root, "空目录"), 0755)
	os.MkdirAll(filepath.Join(root, ".hidden"), 0755)
	os.WriteFile(filepath.Join(root, ".hidden", "x.mp4"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(root, "loose.mp4"), []byte("x"), 0644)

	code, _ := s.auth("POST", "/api/storage-srcs", fmt.Sprintf(`{"name":"R","type":"local","video_path":%q}`, root))
	if code != 200 && code != 201 { t.Fatalf("add source: %d", code) }

	// ── list: only real anime dirs, with episode counts and cover flags
	code, body := s.auth("GET", "/api/library", "")
	if code != 200 {
		t.Fatalf("library list: got %d %s", code, body)
	}
	var libResp struct {
		Data []struct {
			Name     string `json:"name"`
			SourceID string `json:"source_id"`
			Cover    string `json:"cover"`
			Episodes int    `json:"episodes"`
			Year     int    `json:"year"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &libResp); err != nil {
		t.Fatalf("bad library JSON: %v", err)
	}
	if len(libResp.Data) != 2 {
		t.Fatalf("expected 2 animes (dirs with videos), got %d: %s", len(libResp.Data), body)
	}
	byName := map[string]json.RawMessage{}
	var frieren, bocchi *struct {
		Name     string `json:"name"`
		SourceID string `json:"source_id"`
		Cover    string `json:"cover"`
		Episodes int    `json:"episodes"`
		Year     int    `json:"year"`
	}
	for i := range libResp.Data {
		a := &libResp.Data[i]
		byName[a.Name] = json.RawMessage("{}")
		if a.Name == "葬送的芙莉莲" { frieren = a }
		if a.Name == "孤独摇滚 (2022)" { bocchi = a }
	}
	if frieren == nil || bocchi == nil {
		t.Fatalf("missing expected animes: %s", body)
	}
	if frieren.Episodes != 3 {
		t.Fatalf("葬送的芙莉莲 episodes: got %d, want 3", frieren.Episodes)
	}
	if frieren.Cover == "" {
		t.Fatal("cover.jpg should set cover URL")
	}
	if bocchi.Year != 2022 {
		t.Fatalf("year not extracted from dir name: got %d", bocchi.Year)
	}
	if bocchi.Cover != "" {
		t.Fatal("no cover file → cover must be empty")
	}
	if strings.Contains(body, "rating") {
		t.Fatal("library response must not contain rating (个人项目)")
	}
	_ = byName

	// ── search filters by dir name
	code, body = s.auth("GET", "/api/library?search=芙莉莲", "")
	if code != 200 { t.Fatalf("search: %d", code) }
	if !strings.Contains(body, "葬送的芙莉莲") || strings.Contains(body, "孤独摇滚") {
		t.Fatalf("search filter wrong: %s", body)
	}

	// ── episodes: real file names (no extension), natural order 第02话 < 第10话
	code, body = s.auth("GET", "/api/library/"+frieren.SourceID+"/"+frieren.Name+"/episodes", "")
	if code != 200 { t.Fatalf("episodes: %d %s", code, body) }
	var eps []struct {
		Name string `json:"name"`
		File string `json:"file"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(body), &eps); err != nil { t.Fatalf("bad eps JSON: %v", err) }
	if len(eps) != 3 { t.Fatalf("expected 3 episodes, got %d: %s", len(eps), body) }
	if eps[0].Name != "第01话" || eps[1].Name != "第02话" || eps[2].Name != "第10话" {
		t.Fatalf("natural order broken: %v %v %v", eps[0].Name, eps[1].Name, eps[2].Name)
	}
	if eps[0].File != "第01话.mkv" {
		t.Fatalf("file field wrong: %s", eps[0].File)
	}

	// ── stream an episode through the returned path
	code, body = s.auth("GET", "/api/stream?path="+eps[1].Path, "")
	if code != 200 || !strings.Contains(body, "A2") {
		t.Fatalf("stream via library path: got %d %s", code, body)
	}

	// ── cover is served
	code, body = s.auth("GET", frieren.Cover, "")
	if code != 200 || !strings.Contains(body, "JPGDATA") {
		t.Fatalf("cover serve: got %d", code)
	}

	// ── traversal in library name is blocked
	code, _ = s.auth("GET", "/api/library/..%2F..%2Fetc/episodes", "")
	if code != 400 && code != 404 && code != 403 {
		t.Fatalf("library traversal must be blocked, got %d", code)
	}

	// ── library requires auth
	if code, _ := s.do("GET", "/api/library", "", ""); code != 401 {
		t.Fatalf("unauthenticated library must 401, got %d", code)
	}
}

// The /data/Xanime workflow: host-side symlinks land inside the single mounted
// source dir. Symlinked anime dirs must be recognized (DirEntry.IsDir() is
// false for symlinks — the scanner must resolve them), and a symlinked WHOLE
// storage (collection dir containing anime dirs) must expose its animes with
// nested names.
func TestLibraryFollowsSymlinksAndCollections(t *testing.T) {
	s := setupTestServer(t)

	root := t.TempDir()
	// real anime elsewhere on "disk"
	external := t.TempDir()
	os.MkdirAll(filepath.Join(external, "进击的巨人"), 0755)
	os.WriteFile(filepath.Join(external, "进击的巨人", "01.mkv"), []byte("G1"), 0644)
	os.WriteFile(filepath.Join(external, "进击的巨人", "02.mkv"), []byte("G2"), 0644)
	// whole storage: a dir of anime dirs (like an NFS export)
	nfsRoot := t.TempDir()
	os.MkdirAll(filepath.Join(nfsRoot, "葬送的芙莉莲"), 0755)
	os.WriteFile(filepath.Join(nfsRoot, "葬送的芙莉莲", "第01话.mp4"), []byte("F1"), 0644)

	// symlink: single anime
	if err := os.Symlink(filepath.Join(external, "进击的巨人"), filepath.Join(root, "进击的巨人")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// symlink: whole collection
	os.Symlink(nfsRoot, filepath.Join(root, "NFS媒体库"))

	code, _ := s.auth("POST", "/api/storage-srcs", fmt.Sprintf(`{"name":"R","type":"local","video_path":%q}`, root))
	if code != 200 && code != 201 { t.Fatalf("add source: %d", code) }

	// fetch the real source id (generated as local-<timestamp>)
	code, body := s.auth("GET", "/api/storage-srcs", "")
	if code != 200 { t.Fatalf("list sources: %d", code) }
	var srcList struct {
		Sources []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"sources"`
	}
	json.Unmarshal([]byte(body), &srcList)
	srcID := ""
	for _, src := range srcList.Sources {
		if src.Name == "R" { srcID = src.ID }
	}
	if srcID == "" { t.Fatalf("source R not found: %s", body) }

	code, body = s.auth("GET", "/api/library", "")
	if code != 200 { t.Fatalf("library: %d %s", code, body) }
	var libResp struct {
		Data []struct {
			Name     string `json:"name"`
			Episodes int    `json:"episodes"`
		} `json:"data"`
	}
	json.Unmarshal([]byte(body), &libResp)

	var giant, frieren *struct {
		Name     string `json:"name"`
		Episodes int    `json:"episodes"`
	}
	for i := range libResp.Data {
		if libResp.Data[i].Name == "进击的巨人" { giant = &libResp.Data[i] }
		if libResp.Data[i].Name == "NFS媒体库/葬送的芙莉莲" { frieren = &libResp.Data[i] }
	}
	if giant == nil {
		t.Fatalf("symlinked anime dir not recognized: %s", body)
	}
	if giant.Episodes != 2 {
		t.Fatalf("symlinked anime episodes: got %d", giant.Episodes)
	}
	if frieren == nil {
		t.Fatalf("collection anime not recognized (nested name): %s", body)
	}

	// episodes via nested name (contains a slash)
	code, body = s.auth("GET", "/api/library/"+srcID+"/NFS媒体库/葬送的芙莉莲/episodes", "")
	if code != 200 { t.Fatalf("nested episodes: %d %s", code, body) }
	if !strings.Contains(body, "第01话") {
		t.Fatalf("nested episodes content: %s", body)
	}

	// stream through the symlinked anime
	code, body = s.auth("GET", "/api/stream?path="+srcID+"/进击的巨人/02.mkv", "")
	if code != 200 || !strings.Contains(body, "G2") {
		t.Fatalf("stream symlinked file: got %d %s", code, body)
	}
}

// Dead symlinks (target outside the mounted tree, e.g. host-only paths) must
// be skipped silently by the scanner and 404 — never 500, never listed.
func TestLibrarySkipsDeadSymlinks(t *testing.T) {
	s := setupTestServer(t)

	root := t.TempDir()
	// one healthy anime
	os.MkdirAll(filepath.Join(root, "健康动漫"), 0755)
	os.WriteFile(filepath.Join(root, "健康动漫", "01.mp4"), []byte("OK"), 0644)
	// dead symlink: target does not exist
	os.Symlink(filepath.Join(t.TempDir(), "nope"), filepath.Join(root, "死链动漫"))

	code, _ := s.auth("POST", "/api/storage-srcs", fmt.Sprintf(`{"name":"R","type":"local","video_path":%q}`, root))
	if code != 200 && code != 201 { t.Fatalf("add source: %d", code) }

	code, body := s.auth("GET", "/api/library", "")
	if code != 200 { t.Fatalf("library: %d %s", code, body) }
	if strings.Contains(body, "死链动漫") {
		t.Fatalf("dead symlink must not be listed: %s", body)
	}
	if !strings.Contains(body, "健康动漫") {
		t.Fatalf("healthy anime missing: %s", body)
	}

	// episodes of a dead-linked name → 404, not 500
	code, _ = s.auth("GET", "/api/library/R/死链动漫/episodes", "")
	if code != 404 && code != 400 {
		t.Fatalf("dead link episodes should 404/400, got %d", code)
	}
}

