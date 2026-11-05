// Package detect là detection engine: nhận FileEvent, theo dõi cửa sổ trượt theo
// scope (tác nhân, cây thư mục, share), chấm điểm theo luật R1–R7 và quản lý Incident.
package detect

import (
	"fmt"
	"time"

	"ransomwarehunter/internal/event"
)

// Severity là mức độ nghiêm trọng của incident.
type Severity int

const (
	SevNone Severity = iota
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = [...]string{"NONE", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if int(s) < len(sevNames) {
		return sevNames[s]
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	for i, n := range sevNames {
		if n == string(b) {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("severity không hợp lệ: %q", b)
}

// Ngưỡng điểm theo thiết kế §5.3.
const (
	ScoreMedium   = 30
	ScoreHigh     = 50
	ScoreCritical = 80
	ScoreMax      = 100
)

// SeverityOf quy đổi điểm sang mức độ.
func SeverityOf(score int) Severity {
	switch {
	case score >= ScoreCritical:
		return SevCritical
	case score >= ScoreHigh:
		return SevHigh
	case score >= ScoreMedium:
		return SevMedium
	}
	return SevNone
}

// AlertKind cho biết lý do engine phát ra bản cập nhật incident.
type AlertKind int

const (
	KindNone      AlertKind = iota // chỉ lưu trữ, không gửi cảnh báo
	KindOpened                     // lần đầu đạt HIGH/CRITICAL
	KindEscalated                  // tăng mức độ
	KindUpdate                     // cập nhật định kỳ khi incident tiếp diễn
	KindClosed                     // đóng sau thời gian yên lặng
)

var kindNames = [...]string{"", "OPENED", "ESCALATED", "UPDATE", "CLOSED"}

func (k AlertKind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

func (k AlertKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// RuleHit là một luật đã kích hoạt.
type RuleHit struct {
	ID     string `json:"id"`
	Points int    `json:"points"`
	Desc   string `json:"desc"`
}

// TransitionStat là số file theo cặp đuôi cũ → đuôi mới (dạng hiển thị).
type TransitionStat struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int    `json:"count"`
}

// KeyCount là bộ đếm theo khóa.
type KeyCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// ActorStat là số file bị đổi đuôi theo tác nhân.
type ActorStat struct {
	Actor event.Actor `json:"actor"`
	Count int         `json:"count"`
}

// NoteStat là một tên file nghi là ransom note và số thư mục chứa nó.
type NoteStat struct {
	Name string `json:"name"`
	Dirs int    `json:"dirs"`
}

// CanaryHit là một lần file mồi bị tác động.
type CanaryHit struct {
	TS      time.Time    `json:"ts"`
	Op      string       `json:"op"`
	Verb    string       `json:"verb"` // mô tả tiếng Việt: "đổi tên", "xóa hoặc đổi tên"…
	Path    string       `json:"path"`
	NewPath string       `json:"new_path,omitempty"`
	Actor   *event.Actor `json:"actor,omitempty"`
}

// FileChange là một file bị đổi đuôi, ghi vào danh sách đầy đủ của incident.
type FileChange struct {
	TS      time.Time `json:"ts"`
	OldPath string    `json:"old_path"`
	NewPath string    `json:"new_path"`
	FromExt string    `json:"from_ext"`
	ToExt   string    `json:"to_ext"`
	Actor   string    `json:"actor,omitempty"`
	Pair    string    `json:"pair,omitempty"`
	Size    int64     `json:"size,omitempty"`
}

// Incident là ảnh chụp trạng thái một sự cố nghi ransomware trên một share.
type Incident struct {
	ID          string           `json:"id"`
	System      string           `json:"system"`
	Share       string           `json:"share"`
	Opened      time.Time        `json:"opened"`
	LastEvent   time.Time        `json:"last_event"`
	Closed      time.Time        `json:"closed,omitzero"`
	Active      bool             `json:"active"`
	Score       int              `json:"score"`
	Severity    Severity         `json:"severity"`
	Rules       []RuleHit        `json:"rules"`
	Total       int              `json:"total"`
	DirCount    int              `json:"dir_count"`
	Transitions []TransitionStat `json:"transitions"`
	NewExts     []KeyCount       `json:"new_exts"`
	Actors      []ActorStat      `json:"actors,omitempty"`
	Notes       []NoteStat       `json:"notes,omitempty"`
	Canaries    []CanaryHit      `json:"canaries,omitempty"`
	Samples     []FileChange     `json:"samples"`
	Sources     []string         `json:"sources,omitempty"`
	FilesURL    string           `json:"files_url,omitempty"`
}

// Output nhận kết quả từ engine. Engine chạy một goroutine nên các hàm này phải nhanh.
type Output interface {
	IncidentChanged(inc Incident, kind AlertKind)
	FileChanges(incidentID string, changes []FileChange)
}

// Baseline là kho đuôi file ban đầu của một share (từ lần quét đầu hoặc duyệt MFT).
type Baseline struct {
	System string         `json:"system"`
	Share  string         `json:"share"`
	Exts   map[string]int `json:"exts"`
}

// CanaryRef xác định một file mồi.
type CanaryRef struct {
	System string `json:"system"`
	Share  string `json:"share"`
	Path   string `json:"path"`
}
