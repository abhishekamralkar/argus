package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/abhishekamralkar/argus/internal/store"
)

//go:embed assets
var assets embed.FS

// Config holds the configuration for the embedded web server.
type Config struct {
	DBPath   string
	Host     string
	Port     int
	ReadOnly bool
}

// statusResponse is the JSON shape of /api/v1/status.
type statusResponse struct {
	DBPath     string              `json:"db_path"`
	Ecosystems []ecosystemResponse `json:"ecosystems"`
}

type ecosystemResponse struct {
	Ecosystem  string `json:"ecosystem"`
	VulnCount  int64  `json:"vuln_count"`
	ChunkCount int64  `json:"chunk_count"`
	LastIngest string `json:"last_ingest,omitempty"`
}

// Serve opens the database and starts the HTTP server. It blocks until the
// server is stopped.
func Serve(cfg Config) error {
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = db.Close() }()

	mux := http.NewServeMux()

	// Static assets — serve index.html at /.
	fileServer := http.FileServer(http.FS(assets))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			r.URL.Path = "/assets/index.html"
		} else {
			r.URL.Path = "/assets" + r.URL.Path
		}
		fileServer.ServeHTTP(w, r)
	})

	// API endpoints.
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		rows, err := db.Status(ctx)
		if err != nil {
			slog.Warn("dashboard: status query failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp := statusResponse{DBPath: cfg.DBPath}
		for _, row := range rows {
			resp.Ecosystems = append(resp.Ecosystems, ecosystemResponse{
				Ecosystem:  row.Ecosystem,
				VulnCount:  row.VulnCount,
				ChunkCount: row.ChunkCount,
				LastIngest: row.LastIngest,
			})
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		runs, err := db.ListScanRuns(ctx, 100)
		if err != nil {
			slog.Warn("dashboard: scan runs query failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if runs == nil {
			runs = []store.ScanRun{}
		}
		writeJSON(w, runs)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	slog.Info("argus dashboard running", "url", fmt.Sprintf("http://%s", addr), "db", cfg.DBPath)
	return http.ListenAndServe(addr, mux) //nolint:gosec // user-controlled address is intentional
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Warn("dashboard: json encode failed", "error", err)
	}
}
