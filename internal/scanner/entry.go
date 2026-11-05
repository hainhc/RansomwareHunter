package scanner

import (
	"sort"
	"strings"
	"time"

	"ransomwarehunter/internal/event"
)

// entry là metadata một mục trong thư mục. Không có nội dung file.
type entry struct {
	name  string
	id    uint64 // inode / FileId; 0 nếu nền tảng không cung cấp
	size  int64
	mtime int64
	dir   bool
}

func sortEntries(es []entry) {
	sort.Slice(es, func(i, j int) bool { return es[i].name < es[j].name })
}

// dirDiff là kết quả so sánh hai lần liệt kê một thư mục.
type dirDiff struct {
	events    []event.FileEvent
	newDirs   []string    // thư mục con mới (cần quét và phát CREATE cho nội dung)
	gone      []string    // thư mục con biến mất
	movedDirs [][2]string // thư mục con đổi tên: cũ → mới (quét lại im lặng)
}

// diffDir so sánh danh sách cũ và mới (đều đã sắp xếp theo tên) của thư mục rel.
// Ghép rename theo thứ tự: cùng file ID → tên mới chứa tên cũ / cùng stem → kích thước gần bằng.
func diffDir(rel string, old, cur []entry, base event.FileEvent) dirDiff {
	var removed, added []entry
	i, j := 0, 0
	var d dirDiff
	for i < len(old) || j < len(cur) {
		switch {
		case j >= len(cur) || (i < len(old) && old[i].name < cur[j].name):
			removed = append(removed, old[i])
			i++
		case i >= len(old) || cur[j].name < old[i].name:
			added = append(added, cur[j])
			j++
		default:
			o, c := old[i], cur[j]
			if !c.dir && (o.size != c.size || o.mtime != c.mtime) {
				d.events = append(d.events, mk(base, event.OpModify, event.Join(rel, c.name), "", c, o.size, event.PairNone))
			}
			i++
			j++
		}
	}
	if len(removed) == 0 && len(added) == 0 {
		return d
	}

	usedR := make([]bool, len(removed))
	usedA := make([]bool, len(added))
	pair := func(ri, ai int, conf event.PairConf) {
		usedR[ri], usedA[ai] = true, true
		o, c := removed[ri], added[ai]
		oldPath, newPath := event.Join(rel, o.name), event.Join(rel, c.name)
		ev := mk(base, event.OpRename, newPath, oldPath, c, o.size, conf)
		d.events = append(d.events, ev)
		if c.dir {
			d.movedDirs = append(d.movedDirs, [2]string{oldPath, newPath})
		}
	}

	// 1. Cùng file ID.
	byID := map[uint64]int{}
	for ri, r := range removed {
		if r.id != 0 {
			byID[r.id] = ri
		}
	}
	for ai, a := range added {
		if ri, ok := byID[a.id]; ok && a.id != 0 && !usedR[ri] && removed[ri].dir == a.dir {
			pair(ri, ai, event.PairExact)
		}
	}

	// 2. Tên mới = tên cũ + phần nối thêm, hoặc cùng stem khác đuôi (kiểu ghi bản mới rồi xóa bản cũ).
	byName := map[string]int{}
	byStem := map[string][]int{}
	for ri, r := range removed {
		if !usedR[ri] && !r.dir {
			byName[strings.ToLower(r.name)] = ri
			byStem[strings.ToLower(event.Stem(r.name))] = append(byStem[strings.ToLower(event.Stem(r.name))], ri)
		}
	}
	for ai, a := range added {
		if usedA[ai] || a.dir {
			continue
		}
		la := strings.ToLower(a.name)
		matched := false
		for k := len(la) - 1; k > 0 && !matched; k-- {
			// Phần nối thêm phải bắt đầu bằng ký tự phân cách (".lockbit", "_locked", "[id]"…).
			if isAlnum(la[k]) {
				continue
			}
			if ri, ok := byName[la[:k]]; ok && !usedR[ri] {
				pair(ri, ai, event.PairInferred)
				matched = true
			}
		}
		if matched {
			continue
		}
		var cand []int
		for _, ri := range byStem[strings.ToLower(event.Stem(a.name))] {
			if !usedR[ri] && event.Ext(removed[ri].name) != event.Ext(a.name) {
				cand = append(cand, ri)
			}
		}
		if len(cand) == 1 {
			pair(cand[0], ai, event.PairInferred)
		}
	}

	// 3. Kích thước gần bằng: bản mã hóa = bản gốc + header/padding (không nhỏ hơn bản gốc).
	// Chỉ xét file gốc ≥ 4 KiB và chỉ khi ứng viên duy nhất theo cả hai chiều.
	near := func(added, orig int64) bool {
		if orig < 4<<10 || added < orig {
			return false
		}
		tol := int64(64 << 10)
		if pct := orig / 50; pct > tol {
			tol = pct
		}
		return added-orig <= tol
	}
	candOf := func(ai int) (int, int) {
		n, last := 0, -1
		for ri, r := range removed {
			if !usedR[ri] && !r.dir && near(added[ai].size, r.size) {
				n, last = n+1, ri
			}
		}
		return n, last
	}
	for ai, a := range added {
		if usedA[ai] || a.dir {
			continue
		}
		n, ri := candOf(ai)
		if n != 1 {
			continue
		}
		back := 0
		for aj, b := range added {
			if !usedA[aj] && !b.dir && near(b.size, removed[ri].size) {
				back++
			}
		}
		if back == 1 {
			pair(ri, ai, event.PairWeak)
		}
	}

	for ri, r := range removed {
		if usedR[ri] {
			continue
		}
		p := event.Join(rel, r.name)
		if r.dir {
			d.gone = append(d.gone, p)
			continue
		}
		d.events = append(d.events, mk(base, event.OpDelete, p, "", r, 0, event.PairNone))
	}
	for ai, a := range added {
		if usedA[ai] {
			continue
		}
		p := event.Join(rel, a.name)
		if a.dir {
			d.newDirs = append(d.newDirs, p)
			continue
		}
		d.events = append(d.events, mk(base, event.OpCreate, p, "", a, 0, event.PairNone))
	}
	return d
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
}

func mk(base event.FileEvent, op event.Op, p, oldPath string, e entry, oldSize int64, conf event.PairConf) event.FileEvent {
	ev := base
	ev.Op = op
	ev.Path = p
	ev.OldPath = oldPath
	ev.FileID = e.id
	ev.Size = e.size
	ev.OldSize = oldSize
	ev.IsDir = e.dir
	ev.Pair = conf
	if e.mtime != 0 {
		ev.MTime = time.Unix(0, e.mtime)
	}
	return ev
}
