package usn

import (
	"strings"

	"ransomwarehunter/internal/event"
)

// Root ánh xạ một thư mục trên volume thành một share.
type Root struct {
	Path  string `json:"path"`  // tương đối so với gốc volume, phân tách '/', vd "Shares/Finance"
	Share string `json:"share"` // tên share hiển thị, vd "\\\\fs01\\Finance"
}

type dirNode struct {
	parent uint64
	name   string
}

// Tracker chuyển bản ghi USN thành FileEvent. Chỉ cache thư mục (FRN → cha, tên):
// bản ghi USN đã chứa tên file và FRN thư mục cha, nên không cần cache từng file.
type Tracker struct {
	System  string
	Volume  string // "D:", dùng làm share khi không cấu hình Roots
	Roots   []Root
	rootFRN uint64
	dirs    map[uint64]dirNode
	oldName map[uint64]string // FRN → đường dẫn trước khi đổi tên
}

const maxPendingRenames = 100_000

// NewTracker tạo tracker; rootFRN là FRN thư mục gốc volume.
func NewTracker(system, volume string, roots []Root, rootFRN uint64) *Tracker {
	norm := make([]Root, len(roots))
	for i, r := range roots {
		norm[i] = Root{Path: strings.Trim(strings.ReplaceAll(r.Path, `\`, "/"), "/"), Share: r.Share}
	}
	return &Tracker{
		System:  system,
		Volume:  volume,
		Roots:   norm,
		rootFRN: rootFRN,
		dirs:    map[uint64]dirNode{},
		oldName: map[uint64]string{},
	}
}

// AddDir nạp một thư mục vào cache (từ lần duyệt MFT ban đầu).
func (t *Tracker) AddDir(frn, parent uint64, name string) {
	t.dirs[frn] = dirNode{parent: parent, name: name}
}

// Dirs trả về số thư mục trong cache.
func (t *Tracker) Dirs() int { return len(t.dirs) }

// dirPath trả về đường dẫn của thư mục frn tính từ gốc volume ("" là gốc).
func (t *Tracker) dirPath(frn uint64) (string, bool) {
	var parts []string
	for depth := 0; frn != t.rootFRN; depth++ {
		n, ok := t.dirs[frn]
		if !ok || depth > 512 || n.parent == frn {
			return "", false
		}
		parts = append(parts, n.name)
		frn = n.parent
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/"), true
}

func (t *Tracker) fullPath(parent uint64, name string) (string, bool) {
	d, ok := t.dirPath(parent)
	if !ok {
		return "", false
	}
	return event.Join(d, name), true
}

// Map chuyển đường dẫn trên volume thành (share, đường dẫn tương đối share).
func (t *Tracker) Map(volPath string) (share, rel string, ok bool) {
	if len(t.Roots) == 0 {
		return t.Volume, volPath, true
	}
	for _, r := range t.Roots {
		if r.Path == "" {
			return r.Share, volPath, true
		}
		if len(volPath) > len(r.Path) && volPath[len(r.Path)] == '/' && strings.EqualFold(volPath[:len(r.Path)], r.Path) {
			return r.Share, volPath[len(r.Path)+1:], true
		}
	}
	return "", "", false
}

// Handle xử lý một bản ghi, trả về các sự kiện (thường 0 hoặc 1).
//
// Một thao tác sinh nhiều bản ghi có cờ lý do cộng dồn, kết thúc bằng bản ghi có cờ CLOSE.
// Rename sinh RENAME_OLD_NAME (tên cũ) rồi RENAME_NEW_NAME (tên mới): phát RENAME ngay ở
// bản ghi tên mới đầu tiên. CREATE/DELETE/MODIFY phát ở bản ghi CLOSE.
func (t *Tracker) Handle(r Record) []event.FileEvent {
	isDir := r.IsDir()
	if r.Reason&ReasonRenameOldName != 0 {
		if p, ok := t.fullPath(r.ParentFRN, r.Name); ok && len(t.oldName) < maxPendingRenames {
			t.oldName[r.FRN] = p
		}
		return nil
	}

	var out []event.FileEvent
	if r.Reason&ReasonRenameNewName != 0 {
		oldp, had := t.oldName[r.FRN]
		delete(t.oldName, r.FRN)
		if isDir {
			t.dirs[r.FRN] = dirNode{parent: r.ParentFRN, name: r.Name}
		}
		if had {
			if newp, ok := t.fullPath(r.ParentFRN, r.Name); ok {
				if ev, ok := t.rename(r, oldp, newp); ok {
					out = append(out, ev)
				}
			}
		}
	}

	if r.Reason&ReasonClose == 0 {
		return out
	}
	var op event.Op
	switch {
	case r.Reason&ReasonFileDelete != 0:
		op = event.OpDelete
	case r.Reason&ReasonFileCreate != 0:
		op = event.OpCreate
		if isDir {
			t.dirs[r.FRN] = dirNode{parent: r.ParentFRN, name: r.Name}
		}
	case r.Reason&reasonData != 0:
		op = event.OpModify
	default:
		return out
	}
	p, ok := t.fullPath(r.ParentFRN, r.Name)
	if op == event.OpDelete && isDir {
		delete(t.dirs, r.FRN)
	}
	if !ok {
		return out
	}
	share, rel, ok := t.Map(p)
	if !ok {
		return out
	}
	return append(out, event.FileEvent{
		TS: r.TS, Source: "usn", System: t.System, Share: share, Op: op,
		Path: rel, FileID: r.FRN, IsDir: isDir,
	})
}

func (t *Tracker) rename(r Record, oldp, newp string) (event.FileEvent, bool) {
	oldShare, oldRel, okOld := t.Map(oldp)
	newShare, newRel, okNew := t.Map(newp)
	base := event.FileEvent{TS: r.TS, Source: "usn", System: t.System, FileID: r.FRN, IsDir: r.IsDir()}
	switch {
	case okOld && okNew && oldShare == newShare:
		base.Share, base.Op, base.Path, base.OldPath, base.Pair = newShare, event.OpRename, newRel, oldRel, event.PairExact
	case okNew: // chuyển vào share từ ngoài
		base.Share, base.Op, base.Path = newShare, event.OpCreate, newRel
	case okOld: // chuyển ra khỏi share
		base.Share, base.Op, base.Path = oldShare, event.OpDelete, oldRel
	default:
		return event.FileEvent{}, false
	}
	return base, true
}

// ExtCounter đếm đuôi file theo share khi duyệt MFT, để làm baseline.
type ExtCounter map[string]map[string]int

// CountExt đếm file name trong thư mục cha parent.
func (t *Tracker) CountExt(c ExtCounter, parent uint64, name string) {
	p, ok := t.fullPath(parent, name)
	if !ok {
		return
	}
	share, _, ok := t.Map(p)
	if !ok {
		return
	}
	m := c[share]
	if m == nil {
		m = map[string]int{}
		c[share] = m
	}
	m[event.Ext(name)]++
}
