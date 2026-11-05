package detect

import (
	"strings"
	"time"
)

// noteTracker theo dõi tên file được tạo ở nhiều thư mục trong thời gian ngắn (R5 – ransom note).
type noteTracker struct {
	window  time.Duration
	minDirs int
	cap     int
	names   map[string]*noteStat
	crossed map[string]*noteStat // các tên đang vượt ngưỡng
}

type noteStat struct {
	name string
	dirs map[string]time.Time
}

func newNoteTracker(cfg Config) *noteTracker {
	return &noteTracker{
		window:  cfg.NoteWindow,
		minDirs: cfg.NoteMinDirs,
		cap:     cfg.NoteCap,
		names:   map[string]*noteStat{},
		crossed: map[string]*noteStat{},
	}
}

// add ghi nhận tên file name được tạo trong dir; trả về true khi lần đầu vượt ngưỡng.
func (t *noteTracker) add(name, dir string, ts time.Time) (*noteStat, bool) {
	key := strings.ToLower(name)
	st := t.names[key]
	if st == nil {
		if len(t.names) >= t.cap {
			return nil, false
		}
		st = &noteStat{name: name, dirs: map[string]time.Time{}}
		t.names[key] = st
	}
	st.dirs[dir] = ts
	if len(st.dirs) >= t.minDirs && t.crossed[key] == nil {
		t.crossed[key] = st
		return st, true
	}
	return st, false
}

// top trả về tên vượt ngưỡng có nhiều thư mục nhất.
func (t *noteTracker) top() *noteStat {
	var best *noteStat
	for _, st := range t.crossed {
		if best == nil || len(st.dirs) > len(best.dirs) || (len(st.dirs) == len(best.dirs) && st.name < best.name) {
			best = st
		}
	}
	return best
}

func (t *noteTracker) prune(now time.Time) {
	for key, st := range t.names {
		for d, ts := range st.dirs {
			if now.Sub(ts) > t.window {
				delete(st.dirs, d)
			}
		}
		if len(st.dirs) == 0 {
			delete(t.names, key)
		}
		if len(st.dirs) < t.minDirs {
			delete(t.crossed, key)
		}
	}
}
