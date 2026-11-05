package syslogconn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ransomwarehunter/internal/event"
)

// Device là một NAS gửi log tới receiver.
type Device struct {
	Address     string // IP nguồn của gói syslog; "*" khớp mọi nguồn chưa khai báo
	System      string // tên hệ thống trong cảnh báo
	Format      *Format
	SharePrefix string         // share = SharePrefix + thành phần đầu của path, vd `\\syno01\`
	Strip       *regexp.Regexp // bỏ tiền tố khỏi path trước khi tách share (vd /share/CACHEDEV1_DATA/)
}

// Config là cấu hình receiver.
type Config struct {
	ListenUDP   string // vd ":514"; rỗng = tắt
	ListenTCP   string
	CaptureFile string // ghi các dòng không đọc được để hiệu chỉnh định dạng
	CaptureMax  int    // số dòng tối đa ghi vào CaptureFile (mặc định 1000)
	Devices     []Device
}

// Stats là bộ đếm của receiver.
type Stats struct {
	Lines, Matched, Ignored, Unmatched, Incomplete, UnknownDevice uint64
}

// Receiver nhận syslog qua UDP/TCP và chuyển thành FileEvent.
type Receiver struct {
	cfg     Config
	out     chan<- event.FileEvent
	log     *slog.Logger
	devices map[string]*Device
	any     *Device

	lines, matched, ignored, unmatched, incomplete, unknown atomic.Uint64

	capMu   sync.Mutex
	capFile *os.File
	capN    int
}

// New tạo receiver.
func New(cfg Config, out chan<- event.FileEvent, log *slog.Logger) (*Receiver, error) {
	if cfg.CaptureMax <= 0 {
		cfg.CaptureMax = 1000
	}
	r := &Receiver{cfg: cfg, out: out, log: log.With("syslog", cfg.ListenUDP+cfg.ListenTCP), devices: map[string]*Device{}}
	for i := range cfg.Devices {
		d := &cfg.Devices[i]
		if d.Format == nil {
			return nil, fmt.Errorf("thiết bị %s chưa có định dạng", d.Address)
		}
		if !d.Format.Verified {
			r.log.Warn("định dạng log chưa được đối chiếu với log thật; bật capture_file để hiệu chỉnh",
				"device", d.Address, "format", d.Format.Name)
		}
		if d.Address == "*" {
			r.any = d
		} else {
			r.devices[d.Address] = d
		}
	}
	if cfg.CaptureFile != "" {
		f, err := os.OpenFile(cfg.CaptureFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		r.capFile = f
	}
	return r, nil
}

// Stats trả về bộ đếm hiện tại.
func (r *Receiver) Stats() Stats {
	return Stats{Lines: r.lines.Load(), Matched: r.matched.Load(), Ignored: r.ignored.Load(),
		Unmatched: r.unmatched.Load(), Incomplete: r.incomplete.Load(), UnknownDevice: r.unknown.Load()}
}

// Run lắng nghe cho tới khi ctx bị hủy.
func (r *Receiver) Run(ctx context.Context) error {
	defer func() {
		if r.capFile != nil {
			r.capFile.Close()
		}
	}()
	errc := make(chan error, 2)
	n := 0
	if r.cfg.ListenUDP != "" {
		pc, err := net.ListenPacket("udp", r.cfg.ListenUDP)
		if err != nil {
			return err
		}
		if uc, ok := pc.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(8 << 20) // chịu được đợt log dồn dập khi bị tấn công
		}
		go func() { <-ctx.Done(); pc.Close() }()
		n++
		go func() { errc <- r.serveUDP(ctx, pc) }()
	}
	if r.cfg.ListenTCP != "" {
		ln, err := net.Listen("tcp", r.cfg.ListenTCP)
		if err != nil {
			return err
		}
		go func() { <-ctx.Done(); ln.Close() }()
		n++
		go func() { errc <- r.serveTCP(ctx, ln) }()
	}
	if n == 0 {
		return errors.New("syslog: cần listen_udp hoặc listen_tcp")
	}
	r.log.Info("đang nhận syslog", "udp", r.cfg.ListenUDP, "tcp", r.cfg.ListenTCP)
	var first error
	for i := 0; i < n; i++ {
		if err := <-errc; err != nil && first == nil && ctx.Err() == nil {
			first = err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return first
}

func (r *Receiver) serveUDP(ctx context.Context, pc net.PacketConn) error {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		host, _, _ := net.SplitHostPort(addr.String())
		// Một gói có thể chứa nhiều dòng.
		for _, line := range strings.Split(strings.TrimRight(string(buf[:n]), "\r\n\x00"), "\n") {
			if err := r.Handle(ctx, host, line); err != nil {
				return nil
			}
		}
	}
}

func (r *Receiver) serveTCP(ctx context.Context, ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			br := bufio.NewReaderSize(c, 64<<10)
			for {
				line, err := readFrame(br)
				if line != "" {
					if r.Handle(ctx, host, line) != nil {
						return
					}
				}
				if err != nil {
					if !errors.Is(err, io.EOF) && ctx.Err() == nil {
						r.log.Debug("kết nối syslog TCP lỗi", "peer", host, "err", err)
					}
					return
				}
			}
		}()
	}
}

// readFrame đọc một bản ghi syslog TCP: octet-counting (RFC 6587 "123 <34>…") hoặc theo dòng.
func readFrame(br *bufio.Reader) (string, error) {
	b, err := br.Peek(1)
	if err != nil {
		return "", err
	}
	if b[0] >= '1' && b[0] <= '9' {
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return "", err
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil || n <= 0 || n > 1<<20 {
			return "", fmt.Errorf("độ dài khung syslog không hợp lệ: %q", lenStr)
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(br, msg); err != nil {
			return "", err
		}
		return strings.TrimRight(string(msg), "\r\n"), nil
	}
	line, err := br.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// Handle xử lý một dòng log từ host; trả về lỗi khi ctx bị hủy.
func (r *Receiver) Handle(ctx context.Context, host, line string) error {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	r.lines.Add(1)
	d := r.devices[host]
	if d == nil {
		d = r.any
	}
	if d == nil {
		r.unknown.Add(1)
		return nil
	}
	p, st := d.Format.Parse(line)
	switch st {
	case Ignored:
		r.ignored.Add(1)
		return nil
	case Unmatched:
		r.unmatched.Add(1)
		r.capture("UNMATCHED", host, line)
		return nil
	case Incomplete:
		r.incomplete.Add(1)
		r.capture("INCOMPLETE", host, line)
		return nil
	}
	ev, ok := d.toEvent(p)
	if !ok {
		r.incomplete.Add(1)
		r.capture("NOSHARE", host, line)
		return nil
	}
	r.matched.Add(1)
	select {
	case r.out <- ev:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Device) toEvent(p Parsed) (event.FileEvent, bool) {
	share, rel, ok := d.mapPath(p.Path)
	if !ok {
		return event.FileEvent{}, false
	}
	ev := event.FileEvent{
		TS: time.Now(), Source: "syslog-" + d.Format.Name, System: d.System, Share: share,
		Op: p.Op, Path: rel, Size: p.Size, IsDir: p.IsDir,
	}
	if p.User != "" || p.IP != "" {
		ev.Actor = &event.Actor{User: p.User, ClientIP: p.IP}
	}
	if p.Op == event.OpRename {
		oldShare, oldRel, ok := d.mapPath(p.OldPath)
		switch {
		case ok && oldShare == share:
			ev.OldPath, ev.Pair = oldRel, event.PairExact
		default: // di chuyển giữa các share: coi như tạo mới ở share đích
			ev.Op = event.OpCreate
		}
	}
	return ev, true
}

// mapPath tách "/Finance/2026/a.xlsx" thành share `\\syno01\Finance` và "2026/a.xlsx".
func (d *Device) mapPath(p string) (share, rel string, ok bool) {
	if d.Strip != nil {
		p = normPath(d.Strip.ReplaceAllString("/"+p, ""))
	}
	first, rest, _ := strings.Cut(p, "/")
	if first == "" {
		return "", "", false
	}
	return d.SharePrefix + first, rest, true
}

func (r *Receiver) capture(kind, host, line string) {
	if r.capFile == nil {
		return
	}
	r.capMu.Lock()
	defer r.capMu.Unlock()
	if r.capN >= r.cfg.CaptureMax {
		return
	}
	r.capN++
	fmt.Fprintf(r.capFile, "%s\t%s\t%s\t%s\n", time.Now().Format(time.RFC3339), kind, host, line)
}
