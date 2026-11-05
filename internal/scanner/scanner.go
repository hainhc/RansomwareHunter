// Package scanner là connector Tầng C: quét metadata SMB/NFS tăng dần dựa trên mtime thư mục.
//
// Mỗi chu kỳ chỉ stat() các thư mục đã biết; thư mục nào đổi mtime (có file được tạo/xóa/
// đổi tên) mới được liệt kê lại và so sánh với trạng thái cũ. Không mở file, không đọc nội dung.
package scanner

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ransomwarehunter/internal/event"
)

// Config là cấu hình quét một share.
type Config struct {
	System      string
	Share       string
	Root        string        // đường dẫn đã mount: \\nas01\Finance hoặc /mnt/nas01/finance
	Interval    time.Duration // chu kỳ quét toàn bộ thư mục
	HotInterval time.Duration // chu kỳ quét thư mục nóng
	HotWindow   time.Duration // thư mục thay đổi trong khoảng này được coi là nóng
	Workers     int
	OpsPerSec   int      // giới hạn thao tác metadata/giây tới NAS (0 = không giới hạn)
	Exclude     []string // tên thư mục bỏ qua (snapshot, thùng rác…)
}

// DefaultExclude là các thư mục snapshot/hệ thống phải bỏ qua để không nhân tải quét.
var DefaultExclude = []string{".snapshot", "~snapshot", "#snapshot", ".zfs", "@eaDir", "#recycle",
	"$RECYCLE.BIN", "System Volume Information", ".ckpt", "@Recently-Snapshot"}

func (c *Config) setDefaults() {
	if c.Interval <= 0 {
		c.Interval = time.Minute
	}
	if c.HotInterval <= 0 {
		c.HotInterval = 10 * time.Second
	}
	if c.HotWindow <= 0 {
		c.HotWindow = 10 * time.Minute
	}
	if c.Workers <= 0 {
		c.Workers = 16
	}
	if c.Exclude == nil {
		c.Exclude = DefaultExclude
	}
}

// recentMTime: mtime thư mục gần thời điểm quét hơn khoảng này thì quét lại ở chu kỳ sau,
// phòng hệ thống file có độ phân giải thời gian thô (1–2 giây).
const recentMTime = 2 * time.Second

type dirState struct {
	mu      sync.Mutex // bảo vệ mtime, entries
	mtime   int64
	entries []entry
	// Đọc được mà không cần mu, để vòng quét nóng không phải chờ thư mục đang được xử lý.
	lastChange atomic.Int64 // UnixNano
	recheck    atomic.Bool
}

// Stats là số liệu vận hành của scanner.
type Stats struct {
	Dirs          int64
	Files         int64
	Cycles        int64
	LastCycle     time.Duration
	LastHot       time.Duration
	InitialScan   time.Duration
	Ops           int64
	Errors        int64
	DirsRescanned int64
}

// Scanner quét một share.
type Scanner struct {
	cfg      Config
	out      chan<- event.FileEvent
	baseline func(exts map[string]int)
	log      *slog.Logger
	lim      *limiter
	exclude  map[string]bool

	mu   sync.RWMutex
	dirs map[string]*dirState

	files, ops, errs, rescanned atomic.Int64
	cycles                      atomic.Int64
	lastCycle, lastHot, initial atomic.Int64
}

// New tạo scanner. baseline (có thể nil) nhận kho đuôi file sau lần quét đầu.
func New(cfg Config, out chan<- event.FileEvent, baseline func(map[string]int), log *slog.Logger) *Scanner {
	cfg.setDefaults()
	if log == nil {
		log = slog.Default()
	}
	ex := map[string]bool{}
	for _, n := range cfg.Exclude {
		ex[strings.ToLower(n)] = true
	}
	return &Scanner{
		cfg:      cfg,
		out:      out,
		baseline: baseline,
		log:      log.With("scanner", cfg.System+"|"+cfg.Share),
		lim:      newLimiter(cfg.OpsPerSec),
		exclude:  ex,
		dirs:     map[string]*dirState{},
	}
}

// Stats trả về số liệu hiện tại.
func (s *Scanner) Stats() Stats {
	s.mu.RLock()
	n := len(s.dirs)
	s.mu.RUnlock()
	return Stats{
		Dirs:          int64(n),
		Files:         s.files.Load(),
		Cycles:        s.cycles.Load(),
		LastCycle:     time.Duration(s.lastCycle.Load()),
		LastHot:       time.Duration(s.lastHot.Load()),
		InitialScan:   time.Duration(s.initial.Load()),
		Ops:           s.ops.Load(),
		Errors:        s.errs.Load(),
		DirsRescanned: s.rescanned.Load(),
	}
}

// Run quét lần đầu (không phát sự kiện), rồi chạy chu kỳ toàn bộ và chu kỳ thư mục nóng.
func (s *Scanner) Run(ctx context.Context) error {
	if _, err := os.Stat(s.cfg.Root); err != nil {
		return err
	}
	start := time.Now()
	exts := map[string]int{}
	var extMu sync.Mutex
	s.walk(ctx, []string{""}, false, func(local map[string]int) {
		extMu.Lock()
		for k, v := range local {
			exts[k] += v
		}
		extMu.Unlock()
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.initial.Store(int64(time.Since(start)))
	st := s.Stats()
	s.log.Info("quét lần đầu xong", "dirs", st.Dirs, "files", st.Files, "duration", time.Since(start).Round(time.Millisecond))
	if s.baseline != nil {
		s.baseline(exts)
	}

	go s.loop(ctx, s.cfg.HotInterval, true)
	s.loop(ctx, s.cfg.Interval, false)
	return ctx.Err()
}

func (s *Scanner) loop(ctx context.Context, every time.Duration, hot bool) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Cycle(ctx, hot)
		}
	}
}

// Cycle chạy một chu kỳ quét. hot=true chỉ xét thư mục nóng hoặc cần quét lại.
func (s *Scanner) Cycle(ctx context.Context, hot bool) {
	start := time.Now()
	now := start
	s.mu.RLock()
	keys := make([]string, 0, len(s.dirs))
	for k, d := range s.dirs {
		if hot {
			lc := d.lastChange.Load()
			if !d.recheck.Load() && (lc == 0 || now.Sub(time.Unix(0, lc)) >= s.cfg.HotWindow) {
				continue
			}
		}
		keys = append(keys, k)
	}
	s.mu.RUnlock()

	jobs := make(chan string, s.cfg.Workers*4)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rel := range jobs {
				s.check(ctx, rel)
			}
		}()
	}
loop:
	for _, k := range keys {
		select {
		case <-ctx.Done():
			break loop
		case jobs <- k:
		}
	}
	close(jobs)
	wg.Wait()
	if hot {
		s.lastHot.Store(int64(time.Since(start)))
	} else {
		s.cycles.Add(1)
		s.lastCycle.Store(int64(time.Since(start)))
	}
}

// check stat thư mục rel; nếu mtime đổi thì liệt kê lại và phát sự kiện.
func (s *Scanner) check(ctx context.Context, rel string) {
	s.mu.RLock()
	d := s.dirs[rel]
	s.mu.RUnlock()
	if d == nil || ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if s.lim.wait(ctx) != nil {
		return
	}
	s.ops.Add(1)
	abs := s.abs(rel)
	fi, err := os.Stat(abs)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.errs.Add(1)
			s.log.Debug("stat thư mục lỗi", "dir", abs, "err", err)
		}
		return // thư mục cha sẽ phát hiện việc xóa/đổi tên
	}
	mt := fi.ModTime().UnixNano()
	if mt == d.mtime && !d.recheck.Load() {
		return
	}
	cur, err := s.list(ctx, abs)
	if err != nil {
		s.errs.Add(1)
		s.log.Debug("liệt kê thư mục lỗi", "dir", abs, "err", err)
		return
	}
	s.rescanned.Add(1)
	now := time.Now()
	base := event.FileEvent{TS: now, Source: "scanner", System: s.cfg.System, Share: s.cfg.Share}
	diff := diffDir(rel, d.entries, cur, base)
	s.files.Add(countFiles(cur) - countFiles(d.entries))
	d.entries = cur
	d.mtime = mt
	d.recheck.Store(now.Sub(fi.ModTime()) < recentMTime)
	if len(diff.events) > 0 || len(diff.newDirs) > 0 || len(diff.gone) > 0 || len(diff.movedDirs) > 0 {
		d.lastChange.Store(now.UnixNano())
	}

	for _, ev := range diff.events {
		select {
		case s.out <- ev:
		case <-ctx.Done():
			return
		}
	}
	for _, g := range diff.gone {
		s.removeSubtree(g)
	}
	for _, m := range diff.movedDirs {
		s.removeSubtree(m[0])
		s.walk(ctx, []string{m[1]}, false, nil) // nội dung chỉ di chuyển theo, không phải tạo mới
	}
	if len(diff.newDirs) > 0 {
		s.walk(ctx, diff.newDirs, true, nil)
	}
}

// walk duyệt song song các cây con, ghi trạng thái; emit=true thì phát CREATE cho nội dung.
func (s *Scanner) walk(ctx context.Context, roots []string, emit bool, extSink func(map[string]int)) {
	q := newQueue(roots)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := map[string]int{}
			for {
				rel, ok := q.pop(ctx)
				if !ok {
					break
				}
				q.done(s.scanNew(ctx, rel, emit, local))
			}
			if extSink != nil {
				extSink(local)
			}
		}()
	}
	wg.Wait()
}

// scanNew liệt kê một thư mục chưa có trong trạng thái và trả về các thư mục con.
func (s *Scanner) scanNew(ctx context.Context, rel string, emit bool, exts map[string]int) []string {
	if s.lim.wait(ctx) != nil {
		return nil
	}
	abs := s.abs(rel)
	s.ops.Add(1)
	fi, err := os.Stat(abs)
	if err != nil {
		s.errs.Add(1)
		return nil
	}
	cur, err := s.list(ctx, abs)
	if err != nil {
		s.errs.Add(1)
		s.log.Debug("liệt kê thư mục lỗi", "dir", abs, "err", err)
		return nil
	}
	now := time.Now()
	d := &dirState{mtime: fi.ModTime().UnixNano(), entries: cur}
	d.recheck.Store(now.Sub(fi.ModTime()) < recentMTime)
	if emit {
		d.lastChange.Store(now.UnixNano())
	}
	s.mu.Lock()
	s.dirs[rel] = d
	s.mu.Unlock()
	s.files.Add(countFiles(cur))

	var children []string
	base := event.FileEvent{TS: now, Source: "scanner", System: s.cfg.System, Share: s.cfg.Share}
	for _, e := range cur {
		p := event.Join(rel, e.name)
		if e.dir {
			if !s.exclude[strings.ToLower(e.name)] {
				children = append(children, p)
			}
			continue
		}
		if exts != nil {
			exts[event.Ext(e.name)]++
		}
		if emit {
			select {
			case s.out <- mk(base, event.OpCreate, p, "", e, 0, event.PairNone):
			case <-ctx.Done():
				return nil
			}
		}
	}
	return children
}

func (s *Scanner) list(ctx context.Context, abs string) ([]entry, error) {
	if err := s.lim.wait(ctx); err != nil {
		return nil, err
	}
	s.ops.Add(1)
	cur, err := readDir(abs)
	if err != nil {
		return nil, err
	}
	// Bỏ thư mục loại trừ khỏi danh sách để không phát sự kiện cho chúng.
	out := cur[:0]
	for _, e := range cur {
		if e.dir && s.exclude[strings.ToLower(e.name)] {
			continue
		}
		out = append(out, e)
	}
	sortEntries(out)
	return out, nil
}

func (s *Scanner) removeSubtree(rel string) {
	prefix := rel + "/"
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, d := range s.dirs {
		if k == rel || strings.HasPrefix(k, prefix) {
			s.files.Add(-countFiles(d.entries))
			delete(s.dirs, k)
		}
	}
}

func (s *Scanner) abs(rel string) string {
	if rel == "" {
		return s.cfg.Root
	}
	return filepath.Join(s.cfg.Root, filepath.FromSlash(rel))
}

func countFiles(es []entry) int64 {
	var n int64
	for _, e := range es {
		if !e.dir {
			n++
		}
	}
	return n
}

// queue là hàng đợi BFS song song: kết thúc khi rỗng và không còn worker nào đang xử lý.
type queue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []string
	active int
}

func newQueue(seed []string) *queue {
	q := &queue{items: append([]string(nil), seed...)}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queue) pop(ctx context.Context) (string, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && q.active > 0 && ctx.Err() == nil {
		q.cond.Wait()
	}
	if len(q.items) == 0 || ctx.Err() != nil {
		q.cond.Broadcast()
		return "", false
	}
	it := q.items[len(q.items)-1]
	q.items = q.items[:len(q.items)-1]
	q.active++
	return it, true
}

func (q *queue) done(children []string) {
	q.mu.Lock()
	q.items = append(q.items, children...)
	q.active--
	q.mu.Unlock()
	q.cond.Broadcast()
}

// limiter là token bucket đơn giản giới hạn thao tác metadata/giây.
type limiter struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

func newLimiter(perSec int) *limiter {
	if perSec <= 0 {
		return nil
	}
	return &limiter{rate: float64(perSec), tokens: float64(perSec), last: time.Now()}
}

func (l *limiter) wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.rate {
			l.tokens = l.rate
		}
		l.last = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		need := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()
		t := time.NewTimer(need)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
