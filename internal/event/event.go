// Package event định nghĩa mô hình sự kiện file đã chuẩn hóa mà mọi connector
// (USN Journal, scanner Tầng C, canary, agent từ xa) cùng sinh ra.
// Sự kiện chỉ chứa metadata — không bao giờ có nội dung file.
package event

import (
	"fmt"
	"path"
	"time"
)

// Op là loại thao tác trên file.
type Op uint8

const (
	OpCreate Op = iota + 1
	OpDelete
	OpRename
	OpModify
)

var opNames = [...]string{"", "CREATE", "DELETE", "RENAME", "MODIFY"}

func (o Op) String() string {
	if o > 0 && int(o) < len(opNames) {
		return opNames[o]
	}
	return fmt.Sprintf("Op(%d)", uint8(o))
}

func (o Op) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

func (o *Op) UnmarshalText(b []byte) error {
	for i := 1; i < len(opNames); i++ {
		if opNames[i] == string(b) {
			*o = Op(i)
			return nil
		}
	}
	return fmt.Errorf("op không hợp lệ: %q", b)
}

// PairConf là độ tin cậy của việc xác định một RENAME.
type PairConf uint8

const (
	PairNone     PairConf = iota
	PairExact             // nguồn báo rename trực tiếp hoặc cùng file ID
	PairInferred          // suy luận từ DELETE + CREATE có tên liên quan
	PairWeak              // suy luận theo kích thước, tin cậy thấp
)

var pairNames = [...]string{"", "EXACT", "INFERRED", "WEAK"}

func (p PairConf) String() string {
	if int(p) < len(pairNames) {
		return pairNames[p]
	}
	return fmt.Sprintf("Pair(%d)", uint8(p))
}

func (p PairConf) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

func (p *PairConf) UnmarshalText(b []byte) error {
	for i, n := range pairNames {
		if n == string(b) {
			*p = PairConf(i)
			return nil
		}
	}
	return fmt.Errorf("pair không hợp lệ: %q", b)
}

// Actor là tác nhân thực hiện thao tác, khi nguồn sự kiện cung cấp được.
type Actor struct {
	User     string `json:"user,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
	Session  string `json:"session,omitempty"`
}

// Key trả về khóa định danh tác nhân, rỗng nếu không có thông tin.
func (a *Actor) Key() string {
	if a == nil || (a.User == "" && a.ClientIP == "") {
		return ""
	}
	return a.User + "@" + a.ClientIP
}

func (a *Actor) String() string {
	if a == nil || a.Key() == "" {
		return "(không xác định)"
	}
	s := a.User
	if s == "" {
		s = "(không rõ user)"
	}
	if a.ClientIP != "" {
		s += " từ " + a.ClientIP
	}
	if a.Session != "" {
		s += " (phiên " + a.Session + ")"
	}
	return s
}

// FileEvent là một thay đổi metadata trên hệ thống lưu trữ.
// Path và OldPath là đường dẫn tương đối so với gốc share, phân tách bằng '/'.
type FileEvent struct {
	TS      time.Time `json:"ts"`
	Source  string    `json:"source,omitempty"`
	System  string    `json:"system"`
	Share   string    `json:"share"`
	Op      Op        `json:"op"`
	Path    string    `json:"path"`
	OldPath string    `json:"old_path,omitempty"`
	FileID  uint64    `json:"file_id,omitempty"`
	Size    int64     `json:"size,omitempty"`
	OldSize int64     `json:"old_size,omitempty"`
	MTime   time.Time `json:"mtime,omitzero"`
	IsDir   bool      `json:"is_dir,omitempty"`
	Actor   *Actor    `json:"actor,omitempty"`
	Pair    PairConf  `json:"pair,omitempty"`
	Canary  bool      `json:"canary,omitempty"`
}

// Dir trả về thư mục cha của một đường dẫn tương đối ("" là gốc share).
func Dir(p string) string {
	d := path.Dir(p)
	if d == "." || d == "/" {
		return ""
	}
	return d
}

// Join nối thư mục tương đối với tên file.
func Join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
