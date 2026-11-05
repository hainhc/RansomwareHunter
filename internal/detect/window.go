package detect

import (
	"strings"
	"time"

	"ransomwarehunter/internal/event"
)

// change là một lần đổi đuôi file (không thuộc mẫu hợp lệ).
type change struct {
	ts      time.Time
	dir     string
	oldPath string
	newPath string
	tr      event.Transition
	actor   *event.Actor
	pair    event.PairConf
	size    int64
	source  string
	unseen  bool
	known   bool
}

func (c *change) fileChange() FileChange {
	fc := FileChange{
		TS:      c.ts,
		OldPath: c.oldPath,
		NewPath: c.newPath,
		FromExt: c.tr.From,
		ToExt:   c.tr.Display(),
		Size:    c.size,
	}
	if c.actor != nil {
		fc.Actor = c.actor.String()
	}
	if c.pair != event.PairNone {
		fc.Pair = c.pair.String()
	}
	return fc
}

// bucket gom các thay đổi trong một giây.
type bucket struct {
	sec                   int64
	n, unseen, known      int
	from, to, dirs, pairs map[string]int
}

// window là cửa sổ trượt theo giây của một scope. Tổng hợp được cập nhật tăng dần:
// thêm khi có sự kiện, trừ khi bucket hết hạn → bộ nhớ chỉ phụ thuộc số khóa trong cửa sổ.
type window struct {
	span             int64
	cur              int64
	buckets          []bucket
	n, unseen, known int
	from, to, dirs   map[string]int
	pairs            map[string]int // to + "\x00" + from: đuôi mới đến từ những đuôi gốc nào
	evalSec          int64
	dirty            bool
}

func newWindow(span time.Duration) *window {
	s := int64(span / time.Second)
	if s < 1 {
		s = 1
	}
	return &window{
		span:    s,
		buckets: make([]bucket, s),
		from:    map[string]int{},
		to:      map[string]int{},
		dirs:    map[string]int{},
		pairs:   map[string]int{},
		evalSec: -1,
	}
}

// advance trượt cửa sổ tới giây sec, loại bỏ bucket hết hạn.
func (w *window) advance(sec int64) {
	if sec <= w.cur {
		return
	}
	w.cur = sec
	limit := sec - w.span
	for i := range w.buckets {
		if b := &w.buckets[i]; b.n > 0 && b.sec <= limit {
			w.drop(b)
		}
	}
}

func (w *window) drop(b *bucket) {
	w.n -= b.n
	w.unseen -= b.unseen
	w.known -= b.known
	subtract(w.from, b.from)
	subtract(w.to, b.to)
	subtract(w.dirs, b.dirs)
	subtract(w.pairs, b.pairs)
	*b = bucket{}
}

// add thêm một thay đổi; trả về false nếu sự kiện đã cũ hơn cửa sổ.
func (w *window) add(sec int64, c *change) bool {
	w.advance(sec)
	if sec <= w.cur-w.span {
		return false
	}
	b := &w.buckets[((sec%w.span)+w.span)%w.span]
	if b.sec != sec {
		if b.n > 0 {
			w.drop(b)
		}
		b.sec = sec
	}
	if b.from == nil {
		b.from, b.to, b.dirs, b.pairs = map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	}
	b.n++
	w.n++
	if c.unseen {
		b.unseen++
		w.unseen++
	}
	if c.known {
		b.known++
		w.known++
	}
	b.from[c.tr.From]++
	w.from[c.tr.From]++
	b.to[c.tr.To]++
	w.to[c.tr.To]++
	b.dirs[c.dir]++
	w.dirs[c.dir]++
	pk := c.tr.To + "\x00" + c.tr.From
	b.pairs[pk]++
	w.pairs[pk]++
	w.dirty = true
	return true
}

// sourcesOf đếm số đuôi gốc khác nhau đã đổi thành khóa đuôi mới to.
func (w *window) sourcesOf(to string) int {
	prefix := to + "\x00"
	n := 0
	for k := range w.pairs {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

func subtract(dst, src map[string]int) {
	for k, v := range src {
		if dst[k] -= v; dst[k] <= 0 {
			delete(dst, k)
		}
	}
}

func top(m map[string]int) (string, int) {
	var bk string
	bn := -1
	for k, v := range m {
		if v > bn || (v == bn && k < bk) {
			bk, bn = k, v
		}
	}
	return bk, bn
}
