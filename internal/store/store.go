// Package store lưu incident (ảnh chụp JSON) và danh sách đầy đủ file bị đổi đuôi (CSV),
// đồng thời chuyển các bản cập nhật cần cảnh báo sang notifier.
// PoC dùng file; bản MVP thay bằng PostgreSQL (thiết kế §7).
package store

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"ransomwarehunter/internal/detect"
	"ransomwarehunter/internal/notify"
)

// Sender nhận cảnh báo cần gửi.
type Sender interface{ Send(notify.Alert) }

// Store cài đặt detect.Output.
type Store struct {
	dir     string
	baseURL string
	sender  Sender
	log     *slog.Logger

	mu        sync.RWMutex
	incidents map[string]detect.Incident
	csv       map[string]*csvFile
}

type csvFile struct {
	f *os.File
	b *bufio.Writer
	w *csv.Writer
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// Open mở (hoặc tạo) thư mục dữ liệu và nạp các incident đã lưu.
func Open(dataDir, baseURL string, sender Sender, log *slog.Logger) (*Store, error) {
	dir := filepath.Join(dataDir, "incidents")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, baseURL: strings.TrimSuffix(baseURL, "/"), sender: sender, log: log,
		incidents: map[string]detect.Incident{}, csv: map[string]*csvFile{}}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var inc detect.Incident
		if json.Unmarshal(b, &inc) == nil && inc.ID != "" {
			if inc.Active { // tiến trình trước dừng giữa chừng
				inc.Active = false
			}
			s.incidents[inc.ID] = inc
		}
	}
	return s, nil
}

// IncidentChanged lưu ảnh chụp và gửi cảnh báo nếu kind khác KindNone.
func (s *Store) IncidentChanged(inc detect.Incident, kind detect.AlertKind) {
	inc.FilesURL = s.baseURL + "/api/v1/incidents/" + inc.ID + "/files.csv"
	s.mu.Lock()
	s.incidents[inc.ID] = inc
	if !inc.Active {
		if c := s.csv[inc.ID]; c != nil {
			c.close()
			delete(s.csv, inc.ID)
		}
	}
	s.mu.Unlock()

	if b, err := json.MarshalIndent(inc, "", "  "); err == nil {
		p := filepath.Join(s.dir, inc.ID+".json")
		if err := os.WriteFile(p+".tmp", b, 0o640); err == nil {
			_ = os.Rename(p+".tmp", p)
		}
	}
	if kind != detect.KindNone {
		s.sender.Send(notify.Alert{Kind: kind, Incident: inc})
	}
}

// FileChanges ghi thêm dòng vào CSV của incident.
func (s *Store) FileChanges(id string, changes []detect.FileChange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.csv[id]
	if c == nil {
		var err error
		if c, err = s.openCSV(id); err != nil {
			s.log.Error("mở file CSV incident lỗi", "id", id, "err", err)
			return
		}
		s.csv[id] = c
	}
	for _, ch := range changes {
		_ = c.w.Write([]string{
			ch.TS.Local().Format("2006-01-02 15:04:05.000"), ch.OldPath, ch.NewPath,
			ch.FromExt, ch.ToExt, ch.Actor, ch.Pair, fmt.Sprint(ch.Size),
		})
	}
	c.w.Flush()
	_ = c.b.Flush()
}

func (s *Store) openCSV(id string) (*csvFile, error) {
	p := s.CSVPath(id)
	_, statErr := os.Stat(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	c := &csvFile{f: f, b: bufio.NewWriterSize(f, 256<<10)}
	c.w = csv.NewWriter(c.b)
	if os.IsNotExist(statErr) {
		_, _ = c.b.Write([]byte{0xEF, 0xBB, 0xBF}) // BOM để Excel hiển thị đúng tiếng Việt
		_ = c.w.Write([]string{"thoi_gian", "duong_dan_cu", "duong_dan_moi", "duoi_cu", "duoi_moi", "tac_nhan", "ghep_cap", "kich_thuoc"})
	}
	return c, nil
}

func (c *csvFile) close() {
	c.w.Flush()
	_ = c.b.Flush()
	_ = c.f.Close()
}

// Close đóng mọi file CSV đang mở.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.csv {
		c.close()
		delete(s.csv, id)
	}
}

// List trả về các incident, mới nhất trước.
func (s *Store) List() []detect.Incident {
	s.mu.RLock()
	out := make([]detect.Incident, 0, len(s.incidents))
	for _, inc := range s.incidents {
		out = append(out, inc)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Opened.After(out[j].Opened) })
	return out
}

// Get trả về một incident.
func (s *Store) Get(id string) (detect.Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inc, ok := s.incidents[id]
	return inc, ok
}

// CSVPath trả về đường dẫn file CSV; rỗng nếu id không hợp lệ.
func (s *Store) CSVPath(id string) string {
	if !idRe.MatchString(id) {
		return ""
	}
	return filepath.Join(s.dir, id+".files.csv")
}

// Flush đẩy dữ liệu CSV đang đệm xuống đĩa (trước khi phục vụ tải về).
func (s *Store) Flush(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.csv[id]; c != nil {
		c.w.Flush()
		_ = c.b.Flush()
	}
}
