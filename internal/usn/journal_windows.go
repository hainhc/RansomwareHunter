//go:build windows

package usn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"ransomwarehunter/internal/event"
)

const (
	fsctlQueryUSNJournal = 0x000900f4
	fsctlEnumUSNData     = 0x000900b3
	fsctlReadUSNJournal  = 0x000900bb

	errHandleEOF           = syscall.Errno(38)
	errJournalNotActive    = syscall.Errno(1179)
	errJournalEntryDeleted = syscall.Errno(1181)

	fileReadAttributes = 0x80
	bufSize            = 1 << 20
)

// Journal là handle tới USN Journal của một volume.
type Journal struct {
	h   syscall.Handle
	buf []byte
}

// JournalData là USN_JOURNAL_DATA_V0.
type JournalData struct {
	ID             uint64
	FirstUSN       int64
	NextUSN        int64
	LowestValidUSN int64
	MaxUSN         int64
	MaximumSize    uint64
}

// Open mở volume (vd "D:"). Cần quyền Administrator (đọc journal là quyền cấp volume,
// không phải quyền đọc nội dung file).
func Open(volume string) (*Journal, error) {
	p, err := syscall.UTF16PtrFromString(`\\.\` + strings.TrimSuffix(volume, `\`))
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("mở volume %s: %w (cần chạy với quyền Administrator)", volume, err)
	}
	raw := make([]uint64, bufSize/8) // căn lề 8 byte
	return &Journal{h: h, buf: unsafe.Slice((*byte)(unsafe.Pointer(&raw[0])), bufSize)}, nil
}

// Close đóng handle.
func (j *Journal) Close() error { return syscall.CloseHandle(j.h) }

func (j *Journal) ioctl(code uint32, in []byte) (int, error) {
	var n uint32
	var inPtr *byte
	if len(in) > 0 {
		inPtr = &in[0]
	}
	err := syscall.DeviceIoControl(j.h, code, inPtr, uint32(len(in)), &j.buf[0], uint32(len(j.buf)), &n, nil)
	return int(n), err
}

// Query đọc thông tin journal.
func (j *Journal) Query() (JournalData, error) {
	n, err := j.ioctl(fsctlQueryUSNJournal, nil)
	if err != nil {
		if errors.Is(err, errJournalNotActive) {
			return JournalData{}, fmt.Errorf("USN Journal chưa bật; chạy: fsutil usn createjournal m=4294967296 a=536870912 <volume>: %w", err)
		}
		return JournalData{}, err
	}
	if n < 56 {
		return JournalData{}, fmt.Errorf("USN_JOURNAL_DATA quá ngắn: %d", n)
	}
	b := j.buf
	return JournalData{
		ID:             binary.LittleEndian.Uint64(b[0:]),
		FirstUSN:       int64(binary.LittleEndian.Uint64(b[8:])),
		NextUSN:        int64(binary.LittleEndian.Uint64(b[16:])),
		LowestValidUSN: int64(binary.LittleEndian.Uint64(b[24:])),
		MaxUSN:         int64(binary.LittleEndian.Uint64(b[32:])),
		MaximumSize:    binary.LittleEndian.Uint64(b[40:]),
	}, nil
}

// Enum duyệt toàn bộ MFT (chỉ metadata) qua FSCTL_ENUM_USN_DATA.
func (j *Journal) Enum(ctx context.Context, highUSN int64, fn func(Record)) error {
	in := make([]byte, 24) // MFT_ENUM_DATA_V0
	binary.LittleEndian.PutUint64(in[16:], uint64(highUSN))
	for ctx.Err() == nil {
		n, err := j.ioctl(fsctlEnumUSNData, in)
		if errors.Is(err, errHandleEOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n < 8 {
			return nil
		}
		recs, _, err := ParseRecords(j.buf[8:n])
		if err != nil {
			return err
		}
		for _, r := range recs {
			fn(r)
		}
		copy(in[0:8], j.buf[0:8]) // StartFileReferenceNumber tiếp theo
	}
	return ctx.Err()
}

// Read đọc bản ghi từ start; trả về USN tiếp theo.
func (j *Journal) Read(start int64, journalID uint64) (int64, []Record, int, error) {
	in := make([]byte, 40) // READ_USN_JOURNAL_DATA_V0
	binary.LittleEndian.PutUint64(in[0:], uint64(start))
	binary.LittleEndian.PutUint32(in[8:], 0xFFFFFFFF) // ReasonMask: mọi lý do
	binary.LittleEndian.PutUint64(in[32:], journalID)
	n, err := j.ioctl(fsctlReadUSNJournal, in)
	if err != nil {
		return start, nil, 0, err
	}
	if n < 8 {
		return start, nil, 0, nil
	}
	next := int64(binary.LittleEndian.Uint64(j.buf[0:]))
	recs, skipped, err := ParseRecords(j.buf[8:n])
	return next, recs, skipped, err
}

// RootFRN trả về FRN thư mục gốc của volume.
func RootFRN(volume string) (uint64, error) {
	p, err := syscall.UTF16PtrFromString(strings.TrimSuffix(volume, `\`) + `\`)
	if err != nil {
		return 0, err
	}
	h, err := syscall.CreateFile(p, fileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return 0, err
	}
	return uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), nil
}

// Run đọc journal liên tục và gọi emit với các sự kiện. Lần đầu duyệt MFT để nạp cache
// thư mục và baseline đuôi file theo share.
func Run(ctx context.Context, cfg SourceConfig, emit func([]event.FileEvent) error,
	baseline func(share string, exts map[string]int), log *slog.Logger) error {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	log = log.With("usn", cfg.Volume)
	j, err := Open(cfg.Volume)
	if err != nil {
		return err
	}
	defer j.Close()
	jd, err := j.Query()
	if err != nil {
		return err
	}
	root, err := RootFRN(cfg.Volume)
	if err != nil {
		return fmt.Errorf("lấy FRN thư mục gốc: %w", err)
	}
	tr := NewTracker(cfg.System, cfg.Volume, cfg.Roots, root)

	// Hai lượt duyệt MFT: lượt 1 nạp thư mục, lượt 2 đếm đuôi file (cần đường dẫn đầy đủ).
	start := time.Now()
	if err := j.Enum(ctx, jd.NextUSN, func(r Record) {
		if r.IsDir() {
			tr.AddDir(r.FRN, r.ParentFRN, r.Name)
		}
	}); err != nil {
		return fmt.Errorf("duyệt MFT: %w", err)
	}
	exts := ExtCounter{}
	files := 0
	if err := j.Enum(ctx, jd.NextUSN, func(r Record) {
		if !r.IsDir() {
			files++
			tr.CountExt(exts, r.ParentFRN, r.Name)
		}
	}); err != nil {
		return fmt.Errorf("duyệt MFT: %w", err)
	}
	log.Info("duyệt MFT xong", "dirs", tr.Dirs(), "files", files, "duration", time.Since(start).Round(time.Millisecond))
	if baseline != nil {
		for share, m := range exts {
			baseline(share, m)
		}
	}

	next := jd.NextUSN
	if st, ok := loadState(cfg.StateFile); ok && st.JournalID == jd.ID && st.NextUSN >= jd.LowestValidUSN {
		next = st.NextUSN
		log.Info("tiếp tục từ USN đã lưu", "usn", next)
	}
	lastSave, saved := time.Now(), next
	defer func() { _ = saveState(cfg.StateFile, sourceState{JournalID: jd.ID, NextUSN: next}) }()

	for ctx.Err() == nil {
		n, recs, skipped, err := j.Read(next, jd.ID)
		switch {
		case errors.Is(err, errJournalEntryDeleted):
			// Journal đã ghi vòng qua vị trí đang đọc: mất một phần sự kiện.
			if jd, err = j.Query(); err != nil {
				return err
			}
			log.Warn("USN Journal bị ghi vòng, mất sự kiện; tăng kích thước journal", "from", next, "to", jd.FirstUSN)
			next = jd.FirstUSN
			continue
		case err != nil:
			return fmt.Errorf("đọc USN Journal: %w", err)
		}
		if skipped > 0 {
			log.Warn("bỏ qua bản ghi USN không phải V2", "count", skipped)
		}
		var evs []event.FileEvent
		for _, r := range recs {
			evs = append(evs, tr.Handle(r)...)
		}
		if len(evs) > 0 {
			if err := emit(evs); err != nil {
				return err
			}
		}
		next = n
		if next != saved && time.Since(lastSave) > 5*time.Second {
			if err := saveState(cfg.StateFile, sourceState{JournalID: jd.ID, NextUSN: next}); err != nil {
				log.Warn("lưu trạng thái USN lỗi", "err", err)
			}
			lastSave, saved = time.Now(), next
		}
		if len(recs) == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(cfg.PollInterval):
			}
		}
	}
	return ctx.Err()
}
