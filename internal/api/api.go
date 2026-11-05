// Package api là HTTP API của rh-server: nhận sự kiện từ agent, xem incident, tải danh sách file.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"ransomwarehunter/internal/detect"
	"ransomwarehunter/internal/event"
	"ransomwarehunter/internal/store"
)

// EventBatch là thân yêu cầu POST /api/v1/events.
type EventBatch struct {
	Events []event.FileEvent `json:"events"`
}

// Server phục vụ API.
type Server struct {
	Store       *store.Store
	Events      chan<- event.FileEvent
	Baselines   chan<- detect.Baseline
	IngestToken string // rỗng = tắt ingest từ agent
	UIUser      string // rỗng = không yêu cầu đăng nhập khi xem (chỉ nên dùng khi listen 127.0.0.1)
	UIPassword  string
	Status      func() any
}

// Handler trả về http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("POST /api/v1/events", s.ingest(s.events))
	mux.HandleFunc("POST /api/v1/baseline", s.ingest(s.baseline))
	mux.HandleFunc("GET /api/v1/status", s.view(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Status()) }))
	mux.HandleFunc("GET /api/v1/incidents", s.view(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Store.List()) }))
	mux.HandleFunc("GET /api/v1/incidents/{id}", s.view(s.incident))
	mux.HandleFunc("GET /api/v1/incidents/{id}/files.csv", s.view(s.files))
	return mux
}

func (s *Server) ingest(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.IngestToken == "" {
			http.Error(w, "ingest bị tắt", http.StatusNotFound)
			return
		}
		if !eq(r.Header.Get("Authorization"), "Bearer "+s.IngestToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
		h(w, r)
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	var b EventBatch
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, ev := range b.Events {
		if ev.System == "" || ev.Share == "" || ev.Op == 0 {
			continue
		}
		if err := send(r.Context(), s.Events, ev); err != nil {
			http.Error(w, "server đang dừng", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) baseline(w http.ResponseWriter, r *http.Request) {
	var b detect.Baseline
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.System == "" || b.Share == "" {
		http.Error(w, "baseline không hợp lệ", http.StatusBadRequest)
		return
	}
	if err := send(r.Context(), s.Baselines, b); err != nil {
		http.Error(w, "server đang dừng", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func send[T any](ctx context.Context, ch chan<- T, v T) error {
	select {
	case ch <- v:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) view(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.UIUser != "" {
			u, p, ok := r.BasicAuth()
			if !ok || !eq(u, s.UIUser) || !eq(p, s.UIPassword) {
				w.Header().Set("WWW-Authenticate", `Basic realm="RansomwareHunter", charset="UTF-8"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h(w, r)
	}
}

func (s *Server) incident(w http.ResponseWriter, r *http.Request) {
	inc, ok := s.Store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, inc)
}

func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Store.Get(id); !ok {
		http.NotFound(w, r)
		return
	}
	s.Store.Flush(id)
	p := s.Store.CSVPath(id)
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.files.csv"`)
	http.ServeContent(w, r, "", time.Time{}, f)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
