// Package canary giám sát file mồi bằng stat() định kỳ (không đọc nội dung) và tạo file mồi.
package canary

import (
	"context"
	"crypto/rand"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"ransomwarehunter/internal/event"
)

// Config là danh sách file mồi trên một share.
type Config struct {
	System   string
	Share    string
	Root     string
	Paths    []string // đường dẫn tương đối, phân tách '/'
	Interval time.Duration
}

type state struct {
	exists bool
	size   int64
	mtime  int64
}

// Monitor stat các file mồi theo chu kỳ và phát sự kiện Canary khi chúng thay đổi.
type Monitor struct {
	cfg   Config
	out   chan<- event.FileEvent
	log   *slog.Logger
	state map[string]state
}

// New tạo monitor.
func New(cfg Config, out chan<- event.FileEvent, log *slog.Logger) *Monitor {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &Monitor{cfg: cfg, out: out, log: log.With("canary", cfg.System+"|"+cfg.Share), state: map[string]state{}}
}

// Run chạy cho tới khi ctx bị hủy.
func (m *Monitor) Run(ctx context.Context) {
	missing := 0
	for _, p := range m.cfg.Paths {
		st := m.stat(p)
		m.state[p] = st
		if !st.exists {
			missing++
		}
	}
	m.log.Info("bắt đầu giám sát file mồi", "count", len(m.cfg.Paths), "missing", missing)
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Check(ctx)
		}
	}
}

// Check stat tất cả file mồi một lần.
func (m *Monitor) Check(ctx context.Context) {
	for _, p := range m.cfg.Paths {
		prev := m.state[p]
		cur := m.stat(p)
		if cur == prev {
			continue
		}
		m.state[p] = cur
		ev := event.FileEvent{
			TS: time.Now(), Source: "canary", System: m.cfg.System, Share: m.cfg.Share,
			Path: p, Size: cur.size, OldSize: prev.size, Canary: true,
		}
		switch {
		case prev.exists && !cur.exists:
			ev.Op = event.OpDelete
		case !prev.exists && cur.exists:
			ev.Op = event.OpCreate
		default:
			ev.Op = event.OpModify
		}
		if cur.exists {
			ev.MTime = time.Unix(0, cur.mtime)
		}
		m.log.Warn("file mồi thay đổi", "path", p, "op", ev.Op)
		select {
		case m.out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

func (m *Monitor) stat(rel string) state {
	fi, err := os.Lstat(filepath.Join(m.cfg.Root, filepath.FromSlash(rel)))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.log.Debug("stat file mồi lỗi", "path", rel, "err", err)
		}
		return state{}
	}
	return state{exists: true, size: fi.Size(), mtime: fi.ModTime().UnixNano()}
}

// DefaultNames là tên file mồi, đứng đầu theo thứ tự alphabet để ransomware gặp sớm.
var DefaultNames = []string{"!000_Do_Not_Delete.docx", "000_Budget_Plan.xlsx", "!001_Contract.pdf"}

// Deploy tạo file mồi (nội dung ngẫu nhiên) trong các thư mục dirs (tương đối so với root).
// File đã tồn tại được giữ nguyên. Trả về danh sách đường dẫn tương đối của file mồi.
func Deploy(root string, dirs, names []string) ([]string, error) {
	if len(names) == 0 {
		names = DefaultNames
	}
	var out []string
	for _, d := range dirs {
		for _, n := range names {
			rel := event.Join(d, n)
			abs := filepath.Join(root, filepath.FromSlash(rel))
			if _, err := os.Lstat(abs); err == nil {
				out = append(out, rel)
				continue
			}
			sz, _ := rand.Int(rand.Reader, big.NewInt(40<<10))
			buf := make([]byte, 20<<10+sz.Int64())
			if _, err := rand.Read(buf); err != nil {
				return out, err
			}
			if err := os.WriteFile(abs, buf, 0o644); err != nil {
				return out, err
			}
			out = append(out, rel)
		}
	}
	return out, nil
}
