package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// ─── Models ───────────────────────────────────────────────────────────────────

type XAnime struct {
	ID          int64   `json:"id"`
	Title       string  `json:"title"`
	Cover       string  `json:"cover"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Episodes    int     `json:"episodes"`
	Year        int     `json:"year"`
	Rating      float64 `json:"rating"`
	CreatedAt   string  `json:"created_at"`
}

type Episode struct {
	ID       int64  `json:"id"`
	XAnimeID int64  `json:"xanime_id"`
	Number   int    `json:"number"`
	Title    string `json:"title"`
	VideoURL string `json:"video_url"`
	Duration int    `json:"duration"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	Avatar   string `json:"avatar"`
}

var db *sql.DB
var jwtSecret []byte
var distPath string
var staticPath string
var dbDriver string

// StorageSource is one configurable storage backend. Type is one of "local",
// "nas", "nfss" (filesystem paths, differing only as user-facing labels) or
// "s3" (S3-compatible object store). Videos are bound to a source via a
// "sourceID:path" prefix in their video_url.
type StorageSource struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	VideoPath   string `json:"video_path"`
	S3Endpoint  string `json:"s3_endpoint"`
	S3Bucket    string `json:"s3_bucket"`
	S3Region    string `json:"s3_region"`
	S3AccessKey string `json:"s3_access_key"`
	S3SecretKey string `json:"s3_secret_key"`
}

var storageSources []StorageSource

// ─── DB Helpers ───────────────────────────────────────────────────────────────

func placeh(n int) string {
	if dbDriver == "sqlite3" {
		return "?"
	}
	return fmt.Sprintf("$%d", n)
}

func insertXAnime(insertID *int64, query string, args ...interface{}) error {
	if dbDriver == "sqlite3" {
		res, err := db.Exec(query, args...)
		if err != nil {
			return err
		}
		*insertID, _ = res.LastInsertId()
		return nil
	}
	return db.QueryRow(query+" RETURNING id", args...).Scan(insertID)
}

func insertUser(insertID *int64, username, password string) error {
	if dbDriver == "sqlite3" {
		res, err := db.Exec("INSERT INTO users(username,password) VALUES(?,?)", username, hashPassword(password))
		if err != nil {
			return err
		}
		*insertID, _ = res.LastInsertId()
		return nil
	}
	return db.QueryRow("INSERT INTO users(username,password) VALUES($1,$2) RETURNING id", username, hashPassword(password)).Scan(insertID)
}

// ─── Security: path traversal guard ───────────────────────────────────────────

func safePath(base string, sub string) (string, error) {
	clean := filepath.Clean(sub)
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("path traversal blocked")
	}
	joined := filepath.Join(base, clean)
	absBase, _ := filepath.Abs(base)
	absJoined, _ := filepath.Abs(joined)
	if !strings.HasPrefix(absJoined, absBase) {
		return "", fmt.Errorf("path traversal blocked")
	}
	return joined, nil
}

// ─── Security: video hotlink protection ───────────────────────────────────────

func signVideoURL(animeID, ep int64) string {
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(fmt.Sprintf("%d:%d", animeID, ep)))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func verifyVideoURL(animeID, ep int64, sig string) bool {
	return hmac.Equal([]byte(signVideoURL(animeID, ep)), []byte(sig))
}

// ─── Security: rate limiter ───────────────────────────────────────────────────

type ipLimiter struct {
	mu       sync.Mutex
	visitors map[string]*rate.Limiter
}

func newIPLimiter() *ipLimiter {
	return &ipLimiter{visitors: make(map[string]*rate.Limiter)}
}

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.visitors[ip]
	if !ok {
		lim = rate.NewLimiter(10, 20) // 10 req/s burst 20
		l.visitors[ip] = lim
	}
	return lim
}

var globalLimiter = newIPLimiter()
var authLimiter = &ipLimiter{visitors: make(map[string]*rate.Limiter)}

func globalRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
		if ip == "" {
			ip = c.ClientIP()
		}
		if !globalLimiter.get(ip).Allow() {
			c.AbortWithStatusJSON(429, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

func authRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		// 5 login/register attempts per minute
		lim := authLimiter.visitors[ip]
		if lim == nil {
			authLimiter.mu.Lock()
			lim = rate.NewLimiter(rate.Every(12*time.Second), 3)
			authLimiter.visitors[ip] = lim
			authLimiter.mu.Unlock()
		}
		if !lim.Allow() {
			c.AbortWithStatusJSON(429, gin.H{"error": "too many attempts, try later"})
			return
		}
		c.Next()
	}
}

// ─── Database Init ────────────────────────────────────────────────────────────

func initDB() {
	var err error
	dbDriver = os.Getenv("DB_DRIVER")
	if dbDriver == "" {
		dbDriver = "sqlite3"
	}

	switch dbDriver {
	case "sqlite3":
		dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
			dbPath = "./data/xanime.db"
		}
		os.MkdirAll(filepath.Dir(dbPath), 0755)
		db, err = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
		if err != nil {
			log.Fatal(err)
		}
	case "postgres":
		dbHost := os.Getenv("DB_HOST")
		if dbHost == "" {
			dbHost = "localhost"
		}
		dbPort := os.Getenv("DB_PORT")
		if dbPort == "" {
			dbPort = "5432"
		}
		dbUser := os.Getenv("DB_USER")
		if dbUser == "" {
			dbUser = "xanime"
		}
		dbPass := os.Getenv("DB_PASSWORD")
		if dbPass == "" {
			dbPass = "xanime"
		}
		dbName := os.Getenv("DB_NAME")
		if dbName == "" {
			dbName = "xanime"
		}
		dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			dbHost, dbPort, dbUser, dbPass, dbName)
		db, err = sql.Open("postgres", dsn)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("Unsupported DB_DRIVER: %s (use sqlite3 or postgres)", dbDriver)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	createTables()
}

func createTables() {
	var err error
	if dbDriver == "postgres" {
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS xanimes (
				id BIGSERIAL PRIMARY KEY,
				title TEXT NOT NULL,
				cover TEXT DEFAULT '',
				description TEXT DEFAULT '',
				category TEXT DEFAULT '',
				episodes INTEGER DEFAULT 0,
				year INTEGER DEFAULT 2024,
				rating DOUBLE PRECISION DEFAULT 0,
				created_at TIMESTAMPTZ DEFAULT NOW()
			);
			CREATE TABLE IF NOT EXISTS episodes (
				id BIGSERIAL PRIMARY KEY,
				xanime_id BIGINT NOT NULL REFERENCES xanimes(id),
				number INTEGER NOT NULL,
				title TEXT DEFAULT '',
				video_url TEXT NOT NULL,
				duration INTEGER DEFAULT 0
			);
			CREATE TABLE IF NOT EXISTS users (
				id BIGSERIAL PRIMARY KEY,
				username TEXT UNIQUE NOT NULL,
				password TEXT NOT NULL,
				avatar TEXT DEFAULT ''
			);
			CREATE INDEX IF NOT EXISTS idx_episodes_xanime ON episodes(xanime_id);
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT DEFAULT ''
		);
		`)
	} else {
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS xanimes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				title TEXT NOT NULL,
				cover TEXT DEFAULT '',
				description TEXT DEFAULT '',
				category TEXT DEFAULT '',
				episodes INTEGER DEFAULT 0,
				year INTEGER DEFAULT 2024,
				rating REAL DEFAULT 0,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);
			CREATE TABLE IF NOT EXISTS episodes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				xanime_id INTEGER NOT NULL,
				number INTEGER NOT NULL,
				title TEXT DEFAULT '',
				video_url TEXT NOT NULL,
				duration INTEGER DEFAULT 0,
				FOREIGN KEY(xanime_id) REFERENCES xanimes(id)
			);
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT UNIQUE NOT NULL,
				password TEXT NOT NULL,
				avatar TEXT DEFAULT ''
			);
			CREATE INDEX IF NOT EXISTS idx_episodes_xanime ON episodes(xanime_id);
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT DEFAULT ''
		);
		`)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func hashPassword(pw string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(bytes)
}

func verifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func generateToken(userID int64) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(72 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, _ := token.SignedString(jwtSecret)
	return t
}

// authMiddleware parses the JWT from the Authorization: Bearer header or the
// "token" HttpOnly cookie, validates signature + expiry, and aborts with 401 on
// any failure. On success it stashes the user id in the gin context.
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string

		// 1) Authorization: Bearer <token>
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			tokenStr = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}

		// 2) HttpOnly cookie fallback
		if tokenStr == "" {
			if ck, err := c.Cookie("token"); err == nil && ck != "" {
				tokenStr = ck
			}
		}

		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
			return
		}
		userID, _ := claims["user_id"].(float64)
		c.Set("user_id", int64(userID))
		c.Next()
	}
}

// hasValidCookie reports whether the request carries a valid "token" HttpOnly
// cookie (used to gate page/HTML routes — a 302 redirect, not a JSON 401).
func hasValidCookie(c *gin.Context) bool {
	tokenStr, err := c.Cookie("token")
	if err != nil || tokenStr == "" {
		return false
	}
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return false
	}
	_, ok := token.Claims.(jwt.MapClaims)
	return ok
}

func register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required,min=3,max=32"`
		Password string `json:"password" binding:"required,min=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var exists int
	db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM users WHERE username=%s", placeh(1)), req.Username).Scan(&exists)
	if exists > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "username taken"})
		return
	}
	var id int64
	if err := insertUser(&id, req.Username, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "username": req.Username, "token": generateToken(id)})
}

func login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var user User
	err := db.QueryRow(fmt.Sprintf("SELECT id,username,password,avatar FROM users WHERE username=%s", placeh(1)), req.Username).
		Scan(&user.ID, &user.Username, &user.Password, &user.Avatar)
	if err != nil || !verifyPassword(user.Password, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad credentials"})
		return
	}

	token := generateToken(user.ID)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   72 * 3600,
	})

	c.JSON(http.StatusOK, gin.H{"id": user.ID, "username": user.Username, "avatar": user.Avatar, "token": token})
}

// ─── Anime API ────────────────────────────────────────────────────────────────

func listAnimes(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "12"))
	if size > 100 {
		size = 100 // cap to prevent abuse
	}
	category := c.Query("category")
	search := c.Query("search")
	offset := (page - 1) * size

	var total int
	query := "SELECT COUNT(*) FROM xanimes WHERE 1=1"
	var args []interface{}
	argIdx := 1

	if category != "" {
		query += fmt.Sprintf(" AND category=%s", placeh(argIdx))
		args = append(args, category)
		argIdx++
	}
	if search != "" {
		query += fmt.Sprintf(" AND title LIKE %s", placeh(argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}
	db.QueryRow(query, args...).Scan(&total)

	query = "SELECT id,title,cover,description,category,episodes,year,rating,created_at FROM xanimes WHERE 1=1"
	args = args[:0]
	argIdx = 1

	if category != "" {
		query += fmt.Sprintf(" AND category=%s", placeh(argIdx))
		args = append(args, category)
		argIdx++
	}
	if search != "" {
		query += fmt.Sprintf(" AND title LIKE %s", placeh(argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %s OFFSET %s", placeh(argIdx), placeh(argIdx+1))
	args = append(args, size, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var xanimes []XAnime
	for rows.Next() {
		var a XAnime
		rows.Scan(&a.ID, &a.Title, &a.Cover, &a.Description, &a.Category, &a.Episodes, &a.Year, &a.Rating, &a.CreatedAt)
		xanimes = append(xanimes, a)
	}
	if xanimes == nil {
		xanimes = []XAnime{}
	}
	c.JSON(http.StatusOK, gin.H{"data": xanimes, "total": total, "page": page, "size": size})
}

func getAnime(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var a XAnime
	err := db.QueryRow(fmt.Sprintf("SELECT id,title,cover,description,category,episodes,year,rating,created_at FROM xanimes WHERE id=%s", placeh(1)), id).
		Scan(&a.ID, &a.Title, &a.Cover, &a.Description, &a.Category, &a.Episodes, &a.Year, &a.Rating, &a.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

func listEpisodes(c *gin.Context) {
	xanimeID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	rows, err := db.Query(fmt.Sprintf("SELECT id,xanime_id,number,title,video_url,duration FROM episodes WHERE xanime_id=%s ORDER BY number", placeh(1)), xanimeID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var episodes []Episode
	for rows.Next() {
		var ep Episode
		rows.Scan(&ep.ID, &ep.XAnimeID, &ep.Number, &ep.Title, &ep.VideoURL, &ep.Duration)
		episodes = append(episodes, ep)
	}
	if episodes == nil {
		episodes = []Episode{}
	}
	c.JSON(http.StatusOK, episodes)
}

// ─── Video Streaming ──────────────────────────────────────────────────────────

// findVideoFile resolves a source-relative key to an existing file. Legacy
// seeded rows store keys like "videos/1/1.mp4" against a source whose root IS
// the videos directory — when the direct hit misses, retry with the first
// path segment stripped ("1/1.mp4") so old episodes keep playing after a
// source re-point.
func findVideoFile(src *StorageSource, rel string) string {
	candidates := []string{rel}
	if first, rest, ok := strings.Cut(rel, "/"); ok && (first == "videos" || first == "static") && rest != "" {
		candidates = append(candidates, rest)
	}
	for _, cand := range candidates {
		full, err := safePath(src.VideoPath, cand)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			return full
		}
	}
	return ""
}

func streamVideo(c *gin.Context) {
	videoRel := c.Query("path")
	if videoRel == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path required"})
		return
	}

	src, rel := resolveVideoURL(videoRel)

	// S3 sources stream via a presigned redirect — the browser fetches
	// directly from the object store.
	if src != nil && src.Type == "s3" {
		c.Redirect(http.StatusFound, generateS3PresignedURL(src, rel))
		return
	}

	if src == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "no filesystem storage source configured"})
		return
	}

	fullPath := findVideoFile(src, rel)
	if fullPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "video not found"})
		return
	}

	// Require Referer header for video access
	ref := c.GetHeader("Referer")
	if ref == "" || !strings.Contains(ref, c.GetHeader("Host")) {
		if os.Getenv("REFERER_CHECK") != "false" && c.GetHeader("X-Requested-With") != "XMLHttpRequest" {
			c.JSON(http.StatusForbidden, gin.H{"error": "hotlinking not allowed"})
			return
		}
	}

	c.File(fullPath)
}

// ─── Library: scan real directories ──────────────────────────────────────────

// videoExts are the file extensions treated as playable episodes.
var videoExts = map[string]bool{
	".mp4": true, ".mkv": true, ".webm": true, ".avi": true, ".mov": true, ".flv": true, ".m4v": true, ".ts": true, ".wmv": true,
}

// coverNames are file names recognized as an anime cover image.
var coverNames = map[string]bool{
	"cover.jpg": true, "cover.jpeg": true, "cover.png": true, "cover.webp": true,
	"poster.jpg": true, "poster.jpeg": true, "poster.png": true, "poster.webp": true,
}

// LibraryAnime is one anime = one real directory under a filesystem source.
type LibraryAnime struct {
	Name     string `json:"name"`
	SourceID string `json:"source_id"`
	SourceName string `json:"source_name"`
	Cover    string `json:"cover"`
	Episodes int    `json:"episodes"`
	Year     int    `json:"year"`
}

// LibraryEpisode is one episode = one real video file. Name is the file name
// without extension (the user's own naming), File the real name, Path the
// streamable "sourceID/dir/file" key.
type LibraryEpisode struct {
	Name string `json:"name"`
	File string `json:"file"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// naturalLess compares strings with embedded numbers compared numerically
// ("第02话" < "第10话", "EP2" < "EP10").
func naturalLess(a, b string) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		ca, cb := a[i], b[j]
		da, db := ca >= '0' && ca <= '9', cb >= '0' && cb <= '9'
		switch {
		case da && db:
			// compare number runs numerically
			si, sj := i, j
			for si < len(a) && a[si] >= '0' && a[si] <= '9' { si++ }
			for sj < len(b) && b[sj] >= '0' && b[sj] <= '9' { sj++ }
			na, _ := strconv.Atoi(a[i:si])
			nb, _ := strconv.Atoi(b[j:sj])
			if na != nb { return na < nb }
			i, j = si, sj
		default:
			if ca != cb { return ca < cb }
			i++; j++
		}
	}
	return len(a)-i < len(b)-j
}

// extractYear pulls a 4-digit year (1900-2099) from a directory name,
// e.g. "孤独摇滚 (2022)" or "孤独摇滚（2022）" or "进击的巨人 2023".
func extractYear(name string) int {
	re := regexp.MustCompile(`(19|20)\d{2}`)
	for _, m := range re.FindAllString(name, -1) {
		y, _ := strconv.Atoi(m)
		if y >= 1900 && y <= 2099 {
			return y
		}
	}
	return 0
}

// isDirEntry reports whether an entry is a directory, resolving symlinks
// (host-side "ln -s" workflow relies on this).
func isDirEntry(root, name string) bool {
	fi, err := os.Stat(filepath.Join(root, name))
	return err == nil && fi.IsDir()
}

// countVideos returns (episodeCount, coverURL) for a directory.
func countVideos(dir string) (int, string, string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return 0, "", ""
	}
	epCount, firstVideo, cover := 0, "", ""
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".") { continue }
		full := filepath.Join(dir, f.Name())
		fi, err := os.Stat(full)
		if err != nil || fi.IsDir() { continue }
		if videoExts[strings.ToLower(filepath.Ext(f.Name()))] {
			epCount++
			if firstVideo == "" { firstVideo = f.Name() }
		} else if coverNames[strings.ToLower(f.Name())] {
			cover = f.Name()
		}
	}
	return epCount, firstVideo, cover
}

// scanSourceDir returns the animes found under a filesystem source root.
// Each non-hidden directory containing video files is one anime. A directory
// WITHOUT videos but WITH anime subdirectories (a symlinked collection, e.g.
// "ln -s /mnt/nfs /data/Xanime/NFS媒体库") is recursed one level: its animes
// are exposed as "Collection/AnimeName" so files stream from the right path.
func scanSourceDir(src *StorageSource) []LibraryAnime {
	var out []LibraryAnime
	var walk func(baseRel string, depth int)
	walk = func(baseRel string, depth int) {
		absBase := filepath.Join(src.VideoPath, baseRel)
		entries, err := os.ReadDir(absBase)
		if err != nil {
			return
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") { continue }
			if !isDirEntry(absBase, e.Name()) { continue }
			dirAbs := filepath.Join(absBase, e.Name())
			epCount, _, coverFile := countVideos(dirAbs)
			relName := e.Name()
			if baseRel != "" {
				relName = baseRel + "/" + e.Name()
			}
			if epCount > 0 {
				cover := ""
				if coverFile != "" {
					cover = fmt.Sprintf("/api/library/%s/%s/cover", src.ID, relName)
				}
				out = append(out, LibraryAnime{
					Name: relName, SourceID: src.ID, SourceName: src.Name,
					Cover: cover, Episodes: epCount, Year: extractYear(e.Name()),
				})
				continue
			}
			// no videos directly inside → maybe a collection dir; recurse once
			if depth < 2 {
				walk(relName, depth+1)
			}
		}
	}
	walk("", 0)
	return out
}

// listLibrary handles GET /api/library[?search=] — scans every filesystem
// source in real time; no DB rows involved.
func listLibrary(c *gin.Context) {
	search := strings.ToLower(strings.TrimSpace(c.Query("search")))
	var data []LibraryAnime
	for i := range storageSources {
		src := &storageSources[i]
		if src.Type == "s3" {
			continue // S3 listing requires a ListObjects call — filesystem only for now
		}
		for _, a := range scanSourceDir(src) {
			if search == "" || strings.Contains(strings.ToLower(a.Name), search) {
				data = append(data, a)
			}
		}
	}
	if data == nil { data = []LibraryAnime{} }
	c.JSON(http.StatusOK, gin.H{"data": data, "total": len(data)})
}

// libraryResource dispatches /api/library/:src/*rest: rest = "Name/episodes"
// or "Name/cover" (Name possibly nested "Collection/Anime").
func libraryResource(c *gin.Context) {
	rest := strings.TrimPrefix(c.Param("rest"), "/")
	switch {
	case strings.HasSuffix(rest, "/episodes"):
		listLibraryEpisodes(c, strings.TrimSuffix(rest, "/episodes"))
	case strings.HasSuffix(rest, "/cover"):
		serveLibraryCover(c, strings.TrimSuffix(rest, "/cover"))
	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	}
}

// validLibraryName validates a possibly-nested anime name from a *name route:
// 1-2 non-empty segments, no dots, no backslashes, no hidden segments.
func validLibraryName(name string) bool {
	if name == "" || len(name) > 512 {
		return false
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, "\\") {
		return false
	}
	segs := strings.Split(name, "/")
	if len(segs) > 2 {
		return false
	}
	for _, s := range segs {
		if s == "" || strings.HasPrefix(s, ".") {
			return false
		}
	}
	return true
}

// listLibraryEpisodes handles the episodes resource — real file names,
// naturally sorted. src disambiguates same-named dirs across sources;
// name may be one level nested ("Collection/Anime").
func listLibraryEpisodes(c *gin.Context, name string) {
	srcID := c.Param("src")
	if !validLibraryName(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid name"})
		return
	}

	src := findSource(srcID)
	if src == nil || src.Type == "s3" {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}

	dirBase := filepath.Join(src.VideoPath, name)
	if fi, err := os.Stat(dirBase); err != nil || !fi.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"error": "anime not found"})
		return
	}

	var eps []LibraryEpisode
	files, err := os.ReadDir(dirBase)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, f := range files {
		if f.IsDir() || strings.HasPrefix(f.Name(), ".") { continue }
		if !videoExts[strings.ToLower(filepath.Ext(f.Name()))] { continue }
		fi, _ := f.Info()
		eps = append(eps, LibraryEpisode{
			Name: strings.TrimSuffix(f.Name(), filepath.Ext(f.Name())),
			File: f.Name(),
			Path: fmt.Sprintf("%s/%s/%s", src.ID, name, f.Name()),
			Size: fi.Size(),
		})
	}
	sort.Slice(eps, func(i, j int) bool { return naturalLess(eps[i].File, eps[j].File) })
	if eps == nil { eps = []LibraryEpisode{} }
	c.JSON(http.StatusOK, eps)
}

// serveLibraryCover handles the cover resource — serves the cover image found
// inside the anime directory on the given source.
func serveLibraryCover(c *gin.Context, name string) {
	srcID := c.Param("src")
	if !validLibraryName(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid name"})
		return
	}
	src := findSource(srcID)
	if src == nil || src.Type == "s3" {
		c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
		return
	}
	dir := filepath.Join(src.VideoPath, name)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"error": "anime not found"})
		return
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, f := range files {
		if f.IsDir() { continue }
		if coverNames[strings.ToLower(f.Name())] {
			c.File(filepath.Join(dir, f.Name()))
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "cover not found"})
}

// ─── Settings / Storage Sources ───────────────────────────────────────────────

func getSetting(key string) string {
	var v string
	_ = db.QueryRow(fmt.Sprintf("SELECT value FROM settings WHERE key=%s", placeh(1)), key).Scan(&v)
	return v
}

func setSetting(key, value string) error {
	if dbDriver == "sqlite3" {
		_, err := db.Exec("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", key, value)
		return err
	}
	_, err := db.Exec("INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", key, value)
	return err
}

// loadStorageSources fills storageSources from the settings DB. If nothing is
// persisted yet, it seeds a single default "local" source from env VIDEO_PATH.
func loadStorageSources() {
	if raw := getSetting("storage_sources"); raw != "" {
		var list []StorageSource
		if err := json.Unmarshal([]byte(raw), &list); err == nil && len(list) > 0 {
			storageSources = list
			return
		}
	}
	vp := os.Getenv("VIDEO_PATH")
	if vp == "" {
		vp = "./videos"
	}
	storageSources = []StorageSource{
		{ID: "local", Name: "本地磁盘", Type: "local", VideoPath: vp},
	}
	_ = saveStorageSources()
}

func saveStorageSources() error {
	b, err := json.Marshal(storageSources)
	if err != nil {
		return err
	}
	return setSetting("storage_sources", string(b))
}

func findSource(id string) *StorageSource {
	for i := range storageSources {
		if storageSources[i].ID == id {
			return &storageSources[i]
		}
	}
	return nil
}

// resolveVideoURL splits "sourceID:path" (colon form) or "sourceID/path"
// (slash form) into (source, path). A bare path that matches no source prefix
// falls back to the first filesystem source, since legacy rows store plain
// relative paths and streaming requires a directory. Generated source IDs
// ("local-<timestamp>") never collide with real path segments.
func resolveVideoURL(v string) (*StorageSource, string) {
	if idx := strings.Index(v, ":"); idx > 0 {
		if src := findSource(v[:idx]); src != nil {
			return src, v[idx+1:]
		}
	}
	if idx := strings.Index(v, "/"); idx > 0 {
		if src := findSource(v[:idx]); src != nil {
			return src, v[idx+1:]
		}
	}
	for i := range storageSources {
		if storageSources[i].Type != "s3" {
			return &storageSources[i], v
		}
	}
	return nil, ""
}

// ─── Session Handlers ─────────────────────────────────────────────────────────

func me(c *gin.Context) {
	uid, _ := c.Get("user_id")
	var u User
	err := db.QueryRow(fmt.Sprintf("SELECT id,username,password,avatar FROM users WHERE id=%s", placeh(1)), uid).
		Scan(&u.ID, &u.Username, &u.Password, &u.Avatar)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": u.ID, "username": u.Username, "avatar": u.Avatar})
}

func logout(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Storage Source CRUD ──────────────────────────────────────────────────────

func listSources(c *gin.Context) {
	// serialize without exposing secret keys
	type out struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		VideoPath   string `json:"video_path"`
		S3Endpoint  string `json:"s3_endpoint"`
		S3Bucket    string `json:"s3_bucket"`
		S3Region    string `json:"s3_region"`
		S3AccessKey string `json:"s3_access_key"`
		SecretSet   bool   `json:"s3_secret_set"`
	}
	list := make([]out, 0, len(storageSources))
	for _, s := range storageSources {
		list = append(list, out{
			ID: s.ID, Name: s.Name, Type: s.Type, VideoPath: s.VideoPath,
			S3Endpoint: s.S3Endpoint, S3Bucket: s.S3Bucket, S3Region: s.S3Region,
			S3AccessKey: s.S3AccessKey, SecretSet: s.S3SecretKey != "",
		})
	}
	c.JSON(http.StatusOK, gin.H{"sources": list})
}

func addSource(c *gin.Context) {
	var req StorageSource
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	switch req.Type {
	case "local", "nas", "nfs":
		if req.VideoPath == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "video_path required"})
			return
		}
		if strings.Contains(req.VideoPath, "..") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "video_path 不能包含 .."})
			return
		}
		req.S3Endpoint = ""
		req.S3Bucket = ""
		req.S3Region = ""
		req.S3AccessKey = ""
		req.S3SecretKey = ""
	case "s3":
		if req.S3Endpoint == "" || req.S3Bucket == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "s3 需要 endpoint 和 bucket"})
			return
		}
		// A presigned URL is only usable with a full credential pair — reject
		// half-configured sources at creation time instead of failing at
		// playback.
		if req.S3AccessKey == "" || req.S3SecretKey == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "s3 需要 access key 和 secret key"})
			return
		}
		if req.S3Region == "" {
			req.S3Region = "us-east-1"
		}
		req.VideoPath = ""
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be local/nas/nfs/s3"})
		return
	}
	req.ID = fmt.Sprintf("%s-%d", req.Type, time.Now().UnixNano())
	if req.Name == "" {
		req.Name = req.Type
	}
	storageSources = append(storageSources, req)
	if err := saveStorageSources(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "save failed"})
		return
	}
	listSources(c)
}

func deleteSource(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id required"})
		return
	}

	// Count non-S3 sources: at least one filesystem source must remain —
	// bare video paths (no "sourceID:" prefix) resolve against the first one,
	// and deleting it would orphan every legacy episode.
	fsCount := 0
	for _, s := range storageSources {
		if s.Type != "s3" {
			fsCount++
		}
	}
	target := findSource(id)
	if target != nil && target.Type != "s3" && fsCount <= 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无法删除唯一的本地/NFS存储源，请先添加其它存储源"})
		return
	}

	for i, s := range storageSources {
		if s.ID == id {
			storageSources = append(storageSources[:i], storageSources[i+1:]...)
			if err := saveStorageSources(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "save failed"})
				return
			}
			listSources(c)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "source not found"})
}

// ── S3 / File Presign ───────────────────────────────────────────────────────

func presignVideo(c *gin.Context) {
	fileKey := c.Query("key")
	if fileKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key required"})
		return
	}
	cleanKey := filepath.Clean(fileKey)
	if strings.Contains(cleanKey, "..") {
		c.JSON(http.StatusForbidden, gin.H{"error": "path traversal"})
		return
	}
	src, rel := resolveVideoURL(fileKey)
	if src == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no storage source"})
		return
	}
	if src.Type == "s3" {
		if src.S3Endpoint == "" || src.S3Bucket == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "S3 not configured"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"url":      generateS3PresignedURL(src, rel),
			"provider": "s3",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"url":      fmt.Sprintf("/api/stream?path=%s", fileKey),
		"provider": src.Type,
	})
}

// generateS3PresignedURL creates a presigned GET URL using AWS Signature V4.
func generateS3PresignedURL(src *StorageSource, key string) string {
	accessKey := src.S3AccessKey
	secretKey := src.S3SecretKey
	region := src.S3Region
	bucket := src.S3Bucket
	endpoint := src.S3Endpoint
	if region == "" {
		region = "us-east-1"
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	shortDate := expiresAt.Format("20060102")
	isoDate := expiresAt.Format("20060102T150405Z")

	credential := fmt.Sprintf("%s/%s/%s/s3/aws4_request", accessKey, shortDate, region)

	canonicalURI := "/" + bucket + "/" + key
	if !strings.HasPrefix(canonicalURI, "/") {
		canonicalURI = "/" + canonicalURI
	}
	canonicalQuery := fmt.Sprintf("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s&X-Amz-Date=%s&X-Amz-Expires=3600&X-Amz-SignedHeaders=host",
		urlEncode(credential), isoDate)
	canonicalHeaders := "host:" + stripProto(endpoint) + "\n"
	signedHeaders := "host"

	payloadHash := "UNSIGNED-PAYLOAD"
	canonicalRequest := fmt.Sprintf("GET\n%s\n%s\n%s\n%s\n%s",
		canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash)

	algorithm := "AWS4-HMAC-SHA256"
	stringToSign := fmt.Sprintf("%s\n%s\n%s/%s/s3/aws4_request\n%s",
		algorithm, isoDate, shortDate, region, sha256Hex(canonicalRequest))

	signingKey := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+secretKey), shortDate), region), "s3"), "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	return fmt.Sprintf("%s/%s/%s?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s&X-Amz-Date=%s&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=%s",
		strings.TrimRight(endpoint, "/"), bucket, key, urlEncode(credential), isoDate, signature)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func urlEncode(s string) string {
	return strings.ReplaceAll(s, "/", "%2F")
}

func stripProto(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return s
}

// ─── Security: CSP + security headers ─────────────────────────────────────────

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; media-src 'self' blob: http: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'")
		c.Next()
	}
}

// ─── Health ───────────────────────────────────────────────────────────────────

func health(c *gin.Context) {
	err := db.Ping()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func ready(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// ─── Seed Data ────────────────────────────────────────────────────────────────

func seedData() {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM xanimes").Scan(&count)
	if count > 0 {
		return
	}

	animes := []struct {
		Title, Cover, Description, Category string
		Episodes, Year                      int
		Rating                              float64
	}{
		{"进击的巨人 最终季", "/covers/attack_on_titan.jpg", "艾伦·耶格尔激活了始祖巨人之力，发动地鸣踏平世界。", "动作", 16, 2023, 9.3},
		{"鬼灭之刃 刀匠村篇", "/covers/demon_slayer.jpg", "炭治郎前往刀匠村，对抗上弦之鬼。", "冒险", 11, 2023, 9.0},
		{"咒术回战 第二季", "/covers/jujutsu_kaisen.jpg", "涩谷事变篇，五条悟被封印。", "动作", 23, 2023, 9.0},
		{"葬送的芙莉莲", "/covers/frieren.jpg", "精灵魔法使在勇者死后踏上了解人类的旅程。", "奇幻", 28, 2023, 9.4},
		{"药屋少女的呢喃", "/covers/apothecary.jpg", "猫猫在后宫解决各种毒药谜案。", "推理", 24, 2023, 8.8},
		{"孤独摇滚！", "/covers/bocchi.jpg", "社恐少女加入乐队改变人生。", "日常", 12, 2022, 9.1},
		{"间谍过家家", "/covers/spy_family.jpg", "间谍+杀手+超能力少女组成虚假家庭。", "喜剧", 25, 2022, 9.0},
		{"莉可丽丝", "/covers/lycoris.jpg", "秘密特工少女与咖啡店日常。", "动作", 13, 2022, 8.5},
		{"夏日重现", "/covers/summer_time.jpg", "时间循环中的岛屿悬疑故事。", "悬疑", 25, 2022, 9.2},
		{"电锯人", "/covers/chainsaw_man.jpg", "少年与电锯恶魔的黑暗冒险。", "黑暗", 12, 2022, 8.7},
		{"石纪元", "/covers/dr_stone.jpg", "科学少年在石化的世界中重建文明。", "科幻", 35, 2023, 8.9},
		{"无职转生 第二季", "/covers/mushoku.jpg", "异世界转生者认真活下去的故事。", "奇幻", 12, 2023, 8.6},
	}

	for _, a := range animes {
		var xanimeID int64
		if err := insertXAnime(&xanimeID,
			"INSERT INTO xanimes(title,cover,description,category,episodes,year,rating) VALUES("+placeh(1)+","+placeh(2)+","+placeh(3)+","+placeh(4)+","+placeh(5)+","+placeh(6)+","+placeh(7)+")",
			a.Title, a.Cover, a.Description, a.Category, a.Episodes, a.Year, a.Rating); err != nil {
			log.Printf("seed xanime err: %v", err)
			continue
		}
		for ep := 1; ep <= a.Episodes && ep <= 3; ep++ {
			db.Exec("INSERT INTO episodes(xanime_id,number,title,video_url,duration) VALUES("+placeh(1)+","+placeh(2)+","+placeh(3)+","+placeh(4)+","+placeh(5)+")",
				xanimeID, ep, fmt.Sprintf("第 %d 集", ep),
				fmt.Sprintf("videos/%d/%d.mp4", xanimeID, ep), 1440)
		}
	}
	log.Println("Seed Xanime data inserted")
}

func seedAdmin() {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		return
	}
	adminUser := os.Getenv("ADMIN_USER")
	if adminUser == "" {
		adminUser = "admin"
	}
	adminPass := os.Getenv("ADMIN_PASS")
	if adminPass == "" {
		adminPass = "admin"
	}
	if dbDriver == "sqlite3" {
		db.Exec("INSERT OR IGNORE INTO users(username,password,avatar) VALUES(?,?,?)", adminUser, hashPassword(adminPass), "")
	} else {
		db.Exec("INSERT INTO users(username,password,avatar) VALUES($1,$2,$3) ON CONFLICT(username) DO NOTHING", adminUser, hashPassword(adminPass), "")
	}
	log.Println("Admin user created")
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("xanime-platform-secret-change-in-production")
	}

	staticPath = os.Getenv("STATIC_PATH")
	if staticPath == "" {
		staticPath = "./static"
	}
	distPath = os.Getenv("DIST_PATH")
	if distPath == "" {
		distPath = "./dist"
	}

	initDB()
	seedData()
	seedAdmin()
	loadStorageSources()

	ginMode := os.Getenv("GIN_MODE")
	if ginMode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := newRouter()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Xanime Platform API starting on :%s (db=%s)", port, dbDriver)

	// Use http.Server with timeouts for production safety
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// newRouter builds the full gin engine: middleware, API routes, static file
// handlers and the SPA fallback. Extracted from main so tests can exercise
// the real routing stack (auth, CORS, CSP, rate limits) end-to-end.
func newRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(securityHeaders())
	r.Use(globalRateLimit())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/health", health)
	r.GET("/ready", ready)

	// Static — path-traversal guarded
	staticBase, _ := filepath.Abs(staticPath)
	r.GET("/static/*filepath", func(c *gin.Context) {
		sub := c.Param("filepath")
		fp, err := safePath(staticBase, sub)
		if err != nil {
			c.AbortWithStatus(403)
			return
		}
		c.File(fp)
	})

	// Auth with stricter rate limiting
	auth := r.Group("/api/auth")
	auth.Use(authRateLimit())
	auth.POST("/register", register)
	auth.POST("/login", login)
	auth.POST("/logout", logout)

	// API (authenticated) — all reads now require a valid JWT
	api := r.Group("/api")
	api.Use(authMiddleware())
	api.GET("/xanimes", listAnimes)
	api.GET("/xanimes/:id", getAnime)
	api.GET("/xanimes/:id/episodes", listEpisodes)

	// Current user + storage sources
	api.GET("/me", me)
	api.GET("/storage-srcs", listSources)
	api.POST("/storage-srcs", addSource)
	api.DELETE("/storage-srcs/:id", deleteSource)

	// Library — real directory / file scanning (personal library).
	// One catch-all route: /api/library/:src/*rest where rest is
	// "Name" (unused), "Name/episodes", "Name/cover"; Name may be nested
	// one level ("Collection/AnimeName").
	api.GET("/library", listLibrary)
	api.GET("/library/:src/*rest", libraryResource)

	// Video streaming (with anti-hotlink)
	api.GET("/stream", streamVideo)

	// S3 presigned URL (abstracts storage backend)
	api.GET("/files/presign", presignVideo)

	// SPA: serve Astro dist, with login gate on page routes
	distBase, _ := filepath.Abs(distPath)
	r.Static("/assets", filepath.Join(distPath, "assets"))
	r.StaticFile("/favicon.svg", filepath.Join(distPath, "favicon.svg"))
	r.StaticFile("/spa-client.js", filepath.Join(distPath, "spa-client.js"))
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path

		// Unmatched /api/* routes should 404, never fall back to the SPA.
		if strings.HasPrefix(p, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		// /login is public; every other page route requires a valid session.
		isLogin := p == "/login" || p == "/login/"
		if !isLogin && !hasValidCookie(c) {
			c.Redirect(http.StatusFound, "/login")
			return
		}

		fp, err := safePath(distBase, p)
		if err != nil {
			c.File(filepath.Join(distPath, "index.html"))
			return
		}
		if _, err := os.Stat(fp); os.IsNotExist(err) {
			// SPA route (e.g. /xanime/123, /watch/1/2) — serve the app shell.
			c.File(filepath.Join(distPath, "index.html"))
			return
		}
		c.File(fp)
	})

	return r
}
