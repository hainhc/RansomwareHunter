package usn

import (
	"encoding/json"
	"os"
	"time"
)

// SourceConfig là cấu hình đọc USN Journal của một volume.
type SourceConfig struct {
	Volume       string        // "D:"
	System       string        // tên hệ thống hiển thị trong cảnh báo, vd "fs01"
	Roots        []Root        // thư mục được chia sẻ trên volume; rỗng = cả volume
	StateFile    string        // lưu USN đã xử lý để khởi động lại không mất sự kiện
	PollInterval time.Duration // chờ khi journal không có bản ghi mới
}

type sourceState struct {
	JournalID uint64 `json:"journal_id"`
	NextUSN   int64  `json:"next_usn"`
}

func loadState(path string) (sourceState, bool) {
	var st sourceState
	if path == "" {
		return st, false
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}

func saveState(path string, st sourceState) error {
	if path == "" {
		return nil
	}
	b, _ := json.Marshal(st)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
