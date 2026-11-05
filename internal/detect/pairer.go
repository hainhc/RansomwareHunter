package detect

import (
	"strings"
	"time"

	"ransomwarehunter/internal/event"
)

// pairer ghép DELETE + CREATE trong cùng thư mục thành RENAME suy luận, cho kiểu
// ransomware "ghi bản mã hóa mới rồi xóa bản gốc" (a.docx bị xóa, a.docx.lockbit được tạo).
// Chỉ dùng tên file: tên mới bắt đầu bằng tên cũ + ".", hoặc cùng stem nhưng khác đuôi.
type pairer struct {
	window time.Duration
	cap    int

	delByName map[string][]*pend // dir|tên cũ
	delByStem map[string][]*pend // dir|stem
	creByPref map[string][]*pend // dir|mỗi tiền tố của tên mới kết thúc trước dấu "."
	creByStem map[string][]*pend // dir|stem
	order     []*pend
}

type pend struct {
	ev   event.FileEvent
	keys []string // các khóa đã đăng ký, để gỡ khi hết hạn
	maps []map[string][]*pend
	used bool
}

func newPairer(cfg Config) *pairer {
	return &pairer{
		window:    cfg.PairWindow,
		cap:       cfg.PairCap,
		delByName: map[string][]*pend{},
		delByStem: map[string][]*pend{},
		creByPref: map[string][]*pend{},
		creByStem: map[string][]*pend{},
	}
}

func (p *pairer) create(ev event.FileEvent) (event.FileEvent, bool) {
	dir, name := event.Dir(ev.Path), lastElem(ev.Path)
	lname := strings.ToLower(name)
	for i := 1; i < len(lname); i++ {
		if lname[i] == '.' {
			if d := takeUnused(p.delByName[dir+"|"+lname[:i]]); d != nil {
				return synthRename(d.ev, ev), true
			}
		}
	}
	if d := takeMatching(p.delByStem[dir+"|"+strings.ToLower(event.Stem(name))], name); d != nil {
		return synthRename(d.ev, ev), true
	}
	if len(p.order) >= p.cap {
		return event.FileEvent{}, false
	}
	pe := &pend{ev: ev}
	for i := 1; i < len(lname); i++ {
		if lname[i] == '.' {
			p.register(pe, p.creByPref, dir+"|"+lname[:i])
		}
	}
	p.register(pe, p.creByStem, dir+"|"+strings.ToLower(event.Stem(name)))
	p.order = append(p.order, pe)
	return event.FileEvent{}, false
}

func (p *pairer) delete(ev event.FileEvent) (event.FileEvent, bool) {
	dir, name := event.Dir(ev.Path), lastElem(ev.Path)
	lname := strings.ToLower(name)
	if c := takeUnused(p.creByPref[dir+"|"+lname]); c != nil {
		return synthRename(ev, c.ev), true
	}
	if c := takeMatching(p.creByStem[dir+"|"+strings.ToLower(event.Stem(name))], name); c != nil {
		return synthRename(ev, c.ev), true
	}
	if len(p.order) >= p.cap {
		return event.FileEvent{}, false
	}
	pe := &pend{ev: ev}
	p.register(pe, p.delByName, dir+"|"+lname)
	p.register(pe, p.delByStem, dir+"|"+strings.ToLower(event.Stem(name)))
	p.order = append(p.order, pe)
	return event.FileEvent{}, false
}

func (p *pairer) register(pe *pend, m map[string][]*pend, key string) {
	m[key] = append(m[key], pe)
	pe.keys = append(pe.keys, key)
	pe.maps = append(pe.maps, m)
}

// expire gỡ các sự kiện chờ quá hạn hoặc đã được ghép.
func (p *pairer) expire(now time.Time) {
	i := 0
	for ; i < len(p.order); i++ {
		pe := p.order[i]
		if !pe.used && now.Sub(pe.ev.TS) <= p.window {
			break
		}
		for k, key := range pe.keys {
			m := pe.maps[k]
			lst := m[key][:0]
			for _, x := range m[key] {
				if x != pe {
					lst = append(lst, x)
				}
			}
			if len(lst) == 0 {
				delete(m, key)
			} else {
				m[key] = lst
			}
		}
	}
	if i > 0 {
		p.order = append(p.order[:0], p.order[i:]...)
	}
}

func takeUnused(lst []*pend) *pend {
	for _, pe := range lst {
		if !pe.used {
			pe.used = true
			return pe
		}
	}
	return nil
}

// takeMatching lấy mục cùng stem nhưng khác đuôi với name.
func takeMatching(lst []*pend, name string) *pend {
	ext := event.Ext(name)
	for _, pe := range lst {
		if !pe.used && event.Ext(lastElem(pe.ev.Path)) != ext {
			pe.used = true
			return pe
		}
	}
	return nil
}

func synthRename(del, cre event.FileEvent) event.FileEvent {
	r := cre
	r.Op = event.OpRename
	r.OldPath = del.Path
	r.OldSize = del.Size
	r.Pair = event.PairInferred
	if del.TS.After(r.TS) {
		r.TS = del.TS
	}
	if r.Actor == nil {
		r.Actor = del.Actor
	}
	return r
}

func lastElem(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
