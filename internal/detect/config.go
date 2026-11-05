package detect

import (
	"time"

	"ransomwarehunter/internal/event"
)

// Config là tham số phát hiện. Giá trị mặc định theo thiết kế §5.3.
type Config struct {
	Window           time.Duration // cửa sổ trượt cho R1–R4, R6
	MinRenames       int           // R1: số file đổi đuôi tối thiểu trong cửa sổ
	ConvergenceRatio float64       // R2: tỷ lệ đuôi mới phổ biến nhất
	MinSourceExts    int           // R2: số đuôi gốc khác nhau tối thiểu
	RandomExtRatio   float64       // R2b: số đuôi mới khác nhau / số file
	UnseenRatio      float64       // R3: tỷ lệ đuôi mới chưa từng thấy
	NewExtAge        time.Duration // R3: đuôi xuất hiện lần đầu trong khoảng này coi là "lạ"
	MinDirs          int           // R4: số thư mục bị ảnh hưởng

	NoteWindow  time.Duration // R5: cửa sổ đếm ransom note
	NoteMinDirs int           // R5: số thư mục tối thiểu có cùng tên file
	NoteExts    []string      // R5: chỉ xét file có đuôi này ("" = không đuôi)
	NoteIgnore  []string      // R5: tên file hợp lệ hay xuất hiện ở nhiều thư mục

	KnownExts []string    // R6: đuôi ransomware đã biết
	Canaries  []CanaryRef // R7: file mồi

	Benign *event.BenignRules

	IncidentQuiet  time.Duration // đóng incident sau thời gian yên lặng
	UpdateInterval time.Duration // chu kỳ gửi cập nhật khi incident tiếp diễn
	PairWindow     time.Duration // ghép DELETE + CREATE thành RENAME trong khoảng này

	SampleSize  int // số file mẫu trong cảnh báo
	RecentCap   int // số thay đổi gần đây giữ lại mỗi share trước khi mở incident
	InvCap      int // số đuôi tối đa trong kho đuôi mỗi share
	NoteCap     int // số tên file tối đa đang theo dõi cho R5
	PairCap     int // số sự kiện chờ ghép tối đa mỗi share
	FlushEvery  int // ghi danh sách file khi đủ số này (ngoài chu kỳ Tick)
	SnapshotTop int // số dòng tối đa trong bảng chuyển đổi đuôi của ảnh chụp
}

// DefaultConfig trả về cấu hình mặc định.
func DefaultConfig() Config {
	return Config{
		Window:           60 * time.Second,
		MinRenames:       50,
		ConvergenceRatio: 0.8,
		MinSourceExts:    3,
		RandomExtRatio:   0.8,
		UnseenRatio:      0.9,
		NewExtAge:        24 * time.Hour,
		MinDirs:          10,

		NoteWindow:  5 * time.Minute,
		NoteMinDirs: 10,
		NoteExts:    []string{"txt", "html", "htm", "hta", "rtf", "mht", "url", ""},
		NoteIgnore:  []string{"desktop.ini", "thumbs.db", ".ds_store", "readme.txt", "license.txt", "index.html", "index.htm"},

		KnownExts: event.DefaultKnownExts(),
		Benign:    event.DefaultBenign(),

		IncidentQuiet:  10 * time.Minute,
		UpdateInterval: 2 * time.Minute,
		PairWindow:     60 * time.Second,

		SampleSize:  20,
		RecentCap:   200_000,
		InvCap:      100_000,
		NoteCap:     100_000,
		PairCap:     200_000,
		FlushEvery:  5_000,
		SnapshotTop: 50,
	}
}
