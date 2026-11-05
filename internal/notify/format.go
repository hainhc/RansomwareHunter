package notify

import (
	"fmt"
	"strings"
	"time"

	"ransomwarehunter/internal/detect"
)

// Alert là một cảnh báo gửi đi.
type Alert struct {
	Kind     detect.AlertKind `json:"kind"`
	Incident detect.Incident  `json:"incident"`
}

var kindTitle = map[detect.AlertKind]string{
	detect.KindOpened:    "Nghi ngờ ransomware",
	detect.KindEscalated: "Tăng mức độ – nghi ngờ ransomware",
	detect.KindUpdate:    "Cập nhật – nghi ngờ ransomware",
	detect.KindClosed:    "Đã kết thúc – nghi ngờ ransomware",
}

// Subject là dòng tiêu đề ngắn.
func Subject(a Alert) string {
	inc := a.Incident
	return fmt.Sprintf("[%s] %s – %s (%s)", inc.Severity, kindTitle[a.Kind], inc.Share, inc.ID)
}

// FormatText định dạng cảnh báo dạng văn bản theo mẫu thiết kế §5.6.
func FormatText(a Alert) string {
	inc := a.Incident
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("%s  (điểm %d)\n", Subject(a), inc.Score)
	w("Hệ thống       : %s", inc.System)
	if len(inc.Sources) > 0 {
		w("  (nguồn: %s)", strings.Join(inc.Sources, ", "))
	}
	w("\n")
	state := "đang diễn ra"
	if !inc.Active {
		state = "đã kết thúc " + fmtTime(inc.Closed)
	}
	w("Thời gian      : %s → %s (%s)\n", fmtTime(inc.Opened), fmtTime(inc.LastEvent), state)
	if len(inc.Actors) > 0 {
		var as []string
		for _, a := range inc.Actors {
			as = append(as, fmt.Sprintf("%s [%s file]", a.Actor.String(), num(a.Count)))
		}
		w("Tác nhân       : %s\n", strings.Join(as, "; "))
	} else {
		w("Tác nhân       : (nguồn sự kiện không cung cấp)\n")
	}
	if inc.Total > 0 {
		w("Quy mô         : %s file bị đổi đuôi trong %s, %s thư mục\n",
			num(inc.Total), dur(inc.LastEvent.Sub(inc.Opened)), num(inc.DirCount))
	}
	if len(inc.NewExts) > 0 && inc.Total > 0 {
		var parts []string
		for i, k := range inc.NewExts {
			if i == 3 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s (%s)", k.Key, pct(k.Count, inc.Total)))
		}
		w("Đuôi mới       : %s\n", strings.Join(parts, ", "))
	}
	if len(inc.Transitions) > 0 {
		w("Chuyển đổi chính:\n")
		for i, t := range inc.Transitions {
			if i == 10 {
				rest := 0
				for _, r := range inc.Transitions[10:] {
					rest += r.Count
				}
				w("   %-28s %8s\n", "(khác)", num(rest))
				break
			}
			if t.To == "" {
				w("   %-28s %8s\n", t.From, num(t.Count))
				continue
			}
			w("   %-28s %8s\n", t.From+" → "+t.To, num(t.Count))
		}
	}
	for _, n := range inc.Notes {
		w("Ransom note    : %q xuất hiện ở %s thư mục\n", n.Name, num(n.Dirs))
	}
	for _, c := range inc.Canaries {
		w("Canary         : %s bị %s lúc %s\n", c.Path, c.Verb, fmtTime(c.TS))
	}
	if len(inc.Rules) > 0 {
		w("Luật kích hoạt :\n")
		for _, r := range inc.Rules {
			w("   %-4s +%-3d %s\n", r.ID, r.Points, r.Desc)
		}
	}
	if len(inc.Samples) > 0 {
		w("File mẫu       :\n")
		for i, s := range inc.Samples {
			if i == 5 {
				break
			}
			w("   %s  →  %s\n", s.OldPath, lastElem(s.NewPath))
		}
	}
	if inc.FilesURL != "" {
		w("Danh sách đầy đủ: %s\n", inc.FilesURL)
	}
	if a.Kind != detect.KindClosed {
		w("Khuyến nghị    : 1) Ngắt phiên SMB / khóa tài khoản của tác nhân\n")
		w("                 2) Cô lập máy trạm nguồn\n")
		w("                 3) Giữ nguyên snapshot hiện có, tạm dừng job xóa snapshot\n")
	}
	return b.String()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func dur(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}

func pct(n, total int) string {
	return strings.Replace(fmt.Sprintf("%.1f%%", 100*float64(n)/float64(total)), ".", ",", 1)
}

// num định dạng số kiểu Việt Nam: 3.214
func num(n int) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return s
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "." + s[i:]
	}
	return s
}

func lastElem(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
