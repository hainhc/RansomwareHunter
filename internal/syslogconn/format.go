// Package syslogconn là connector Tầng A cho NAS gửi log thao tác file qua syslog
// (Synology DSM, QNAP QTS/QuTS hero, Samba full_audit…). Chỉ phân tích dòng log, không đụng tới file.
package syslogconn

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ransomwarehunter/internal/event"
)

// Format mô tả cách đọc một loại dòng log. Regex dùng nhóm có tên:
// op (bắt buộc); path, hoặc old + new nếu nguồn tách sẵn tên cũ/mới; user, ip, kind, size (tùy chọn).
type Format struct {
	Name      string
	Re        *regexp.Regexp
	Ops       map[string]event.Op // op (lowercase) → Op; op không có trong bảng thì bỏ qua (vd read)
	RenameSep string              // tách "cũ<sep>mới" trong path khi op là rename
	DirKinds  []string            // giá trị kind (lowercase) nghĩa là thư mục
	Verified  bool                // định dạng đã đối chiếu với log thật
}

// Parsed là kết quả đọc một dòng.
type Parsed struct {
	Op      event.Op
	Path    string // đường dẫn trên NAS, phân tách '/'
	OldPath string
	User    string
	IP      string
	IsDir   bool
	Size    int64
}

// Status là kết quả phân tích.
type Status int

const (
	Matched    Status = iota
	Ignored           // đúng định dạng nhưng thao tác không cần (read, login…)
	Unmatched         // không khớp định dạng
	Incomplete        // khớp nhưng thiếu dữ liệu (vd rename không có tên mới)
)

// Builtin là các định dạng có sẵn.
//
// synology: dòng "WinFileService Event: rename, Path: /share/a -> /share/b, File/Folder: File,
// Size: 1.41 KB, User: u, IP: 1.2.3.4" của SMB transfer log trên DSM 7, đối chiếu với log mẫu
// thật công khai (Splunk TA cộng đồng). Path bắt đầu bằng tên share.
//
// qnap: CHƯA đối chiếu với log thật — dựng theo bố cục khóa/giá trị của access log QTS
// ("Users: …, Source IP: …, Connection type: …, Accessed resources: …, Action: …").
// Phải bật capture_file, thu vài dòng thật rồi hiệu chỉnh (hoặc khai báo custom format).
var Builtin = map[string]*Format{
	"synology": {
		Name: "synology",
		Re: regexp.MustCompile(`\b\w+ Event: (?P<op>[A-Za-z_]+), Path: (?P<path>.+?), File/Folder: (?P<kind>File|Folder), ` +
			`Size: (?P<size>[^,]*), User: (?P<user>.*?), IP: (?P<ip>[0-9A-Fa-f.:]+)`),
		Ops: map[string]event.Op{
			"create": event.OpCreate, "mkdir": event.OpCreate,
			"delete": event.OpDelete,
			"rename": event.OpRename, "move": event.OpRename,
			"write": event.OpModify,
		},
		RenameSep: " -> ",
		DirKinds:  []string{"folder"},
		Verified:  true,
	},
	"qnap": {
		Name: "qnap",
		Re: regexp.MustCompile(`Users?: (?P<user>[^,]*), Source IP: (?P<ip>[^,]*),.*?Connection type: (?P<proto>[^,]*), ` +
			`Accessed resources: (?P<path>.+?), Action: (?P<op>[A-Za-z ]+?)\s*$`),
		Ops: map[string]event.Op{
			// QTS ghi file mới dưới dạng "Write": coi là CREATE để không bỏ sót ransom note.
			"write": event.OpCreate, "add": event.OpCreate, "create": event.OpCreate, "mkdir": event.OpCreate,
			"delete": event.OpDelete,
			"rename": event.OpRename, "move": event.OpRename,
		},
		RenameSep: " -> ",
		Verified:  false,
	},
}

// NewCustom tạo định dạng do người dùng khai báo trong cấu hình.
func NewCustom(name, re string, ops map[string]string, renameSep string, dirKinds []string) (*Format, error) {
	r, err := regexp.Compile(re)
	if err != nil {
		return nil, fmt.Errorf("format %s: regex: %w", name, err)
	}
	if r.SubexpIndex("op") < 0 {
		return nil, fmt.Errorf("format %s: regex thiếu nhóm (?P<op>…)", name)
	}
	if r.SubexpIndex("path") < 0 && r.SubexpIndex("old") < 0 {
		return nil, fmt.Errorf("format %s: regex cần nhóm (?P<path>…) hoặc (?P<old>…)(?P<new>…)", name)
	}
	f := &Format{Name: name, Re: r, Ops: map[string]event.Op{}, RenameSep: renameSep}
	for k, v := range ops {
		var op event.Op
		if err := op.UnmarshalText([]byte(strings.ToUpper(v))); err != nil {
			return nil, fmt.Errorf("format %s: ops[%q]: %w", name, k, err)
		}
		f.Ops[strings.ToLower(k)] = op
	}
	for _, k := range dirKinds {
		f.DirKinds = append(f.DirKinds, strings.ToLower(k))
	}
	return f, nil
}

// Parse đọc một dòng log.
func (f *Format) Parse(line string) (Parsed, Status) {
	m := f.Re.FindStringSubmatch(line)
	if m == nil {
		return Parsed{}, Unmatched
	}
	get := func(name string) string {
		if i := f.Re.SubexpIndex(name); i >= 0 {
			return strings.TrimSpace(m[i])
		}
		return ""
	}
	op, ok := f.Ops[strings.ToLower(get("op"))]
	if !ok {
		return Parsed{}, Ignored
	}
	p := Parsed{Op: op, User: get("user"), IP: get("ip"), Size: parseSize(get("size"))}
	kind := strings.ToLower(get("kind"))
	for _, k := range f.DirKinds {
		p.IsDir = p.IsDir || kind == k
	}
	path, oldp, newp := get("path"), get("old"), get("new")
	if op == event.OpRename {
		if oldp == "" || newp == "" {
			i := -1
			if f.RenameSep != "" {
				i = strings.Index(path, f.RenameSep)
			}
			if i < 0 {
				return Parsed{}, Incomplete
			}
			oldp, newp = path[:i], path[i+len(f.RenameSep):]
		}
		p.OldPath, p.Path = normPath(oldp), normPath(newp)
		return p, Matched
	}
	if path == "" { // định dạng chỉ có old/new: thao tác một file nằm ở old
		path = oldp
	}
	p.Path = normPath(path)
	if p.Path == "" {
		return Parsed{}, Incomplete
	}
	return p, Matched
}

func normPath(p string) string {
	return strings.Trim(strings.ReplaceAll(strings.TrimSpace(p), `\`, "/"), "/")
}

// parseSize đọc "34.81 MB", "0 Bytes", "1.41 KB" (đơn vị 1024).
func parseSize(s string) int64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	mult := 1.0
	if len(f) > 1 {
		switch strings.ToUpper(f[1]) {
		case "KB":
			mult = 1 << 10
		case "MB":
			mult = 1 << 20
		case "GB":
			mult = 1 << 30
		case "TB":
			mult = 1 << 40
		}
	}
	return int64(v * mult)
}
