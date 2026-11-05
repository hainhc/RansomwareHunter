package event

import (
	"regexp"
	"strings"
)

// NoExt là nhãn hiển thị cho file không có đuôi.
const NoExt = "(không đuôi)"

// Ext trả về đuôi file (lowercase, không có dấu chấm).
// File không có đuôi, hoặc file ẩn kiểu ".bashrc", trả về "".
func Ext(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[i+1:])
}

// Stem trả về tên file đã bỏ đuôi cuối cùng.
func Stem(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return name
	}
	return name[:i]
}

// Dotted trả về đuôi dạng ".docx", hoặc NoExt nếu rỗng.
func Dotted(ext string) string {
	if ext == "" {
		return NoExt
	}
	return "." + ext
}

// AppendedSuffix trả về phần được nối thêm nếu newName = oldName + suffix
// (so sánh không phân biệt hoa thường, như trên SMB/NTFS).
func AppendedSuffix(oldName, newName string) (string, bool) {
	if oldName == "" || len(newName) <= len(oldName) || !strings.EqualFold(newName[:len(oldName)], oldName) {
		return "", false
	}
	return newName[len(oldName):], true
}

// Transition mô tả một lần đổi đuôi file.
type Transition struct {
	From     string // đuôi gốc: ".docx" hoặc NoExt
	To       string // khóa đuôi mới đã chuẩn hóa mẫu: ".lockbit", ".id-{HEX}.[{EMAIL}].wallet"
	NewExt   string // đuôi cuối của tên mới (lowercase, không dấu chấm) — dùng cho kho đuôi
	Appended bool   // To là phần nối thêm vào tên cũ
}

// Display trả về đuôi mới để hiển thị, ví dụ ".xlsx.lockbit".
func (t Transition) Display() string {
	if t.Appended && t.From != NoExt {
		return t.From + t.To
	}
	return t.To
}

// Classify phân loại việc đổi tên oldName → newName. ok=false nếu đuôi không đổi.
func Classify(oldName, newName string) (t Transition, ok bool) {
	oldExt, newExt := Ext(oldName), Ext(newName)
	if oldExt == newExt {
		return Transition{}, false
	}
	t = Transition{From: Dotted(oldExt), NewExt: newExt}
	if suf, app := AppendedSuffix(oldName, newName); app {
		t.To = Template(strings.ToLower(suf))
		t.Appended = true
	} else {
		t.To = Template(Dotted(newExt))
	}
	return t, true
}

var (
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reUUID  = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	reHex   = regexp.MustCompile(`[0-9a-fA-F]{8,}`)
	reNum   = regexp.MustCompile(`[0-9]{4,}`)
	reRnd   = regexp.MustCompile(`[a-zA-Z0-9]{10,}`)
)

// Template chuẩn hóa đuôi thành mẫu: thay email, UUID, chuỗi hex/số dài và chuỗi
// ngẫu nhiên bằng placeholder, để các biến thể chứa ID nạn nhân gộp về một nhóm.
func Template(s string) string {
	s = reEmail.ReplaceAllString(s, "{EMAIL}")
	s = reUUID.ReplaceAllString(s, "{UUID}")
	// Chuỗi ngẫu nhiên: có cả chữ số và chữ cái ngoài a-f (không phải hex).
	s = reRnd.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsAny(m, digits) && strings.IndexFunc(m, isNonHexLetter) >= 0 {
			return "{RND}"
		}
		return m
	})
	// Hex: có cả chữ số và chữ cái a-f; chuỗi toàn số để reNum xử lý.
	s = reHex.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsAny(m, digits) && strings.ContainsAny(m, "abcdefABCDEF") {
			return "{HEX}"
		}
		return m
	})
	return reNum.ReplaceAllString(s, "{NUM}")
}

const digits = "0123456789"

func isNonHexLetter(r rune) bool { return (r >= 'g' && r <= 'z') || (r >= 'G' && r <= 'Z') }

// BenignRules là các kiểu đổi tên hợp lệ không tính vào phát hiện.
type BenignRules struct {
	FromExts     map[string]bool // đuôi gốc là file tạm: tmp → docx khi lưu file
	ToExts       map[string]bool // đuôi đích là file tạm/backup: docx → bak
	NamePrefixes []string        // file tạm Office, LibreOffice…
}

// DefaultBenign trả về bộ luật mặc định.
func DefaultBenign() *BenignRules {
	return &BenignRules{
		FromExts:     setOf("tmp", "temp", "part", "partial", "crdownload", "download", "filepart", "!ut", "opdownload", "swp"),
		ToExts:       setOf("tmp", "temp", "bak", "old", "orig", "backup"),
		NamePrefixes: []string{"~$", "~wr", ".~lock"},
	}
}

// IsBenign cho biết đổi tên oldName → newName có thuộc mẫu hợp lệ hay không.
func (b *BenignRules) IsBenign(oldName, newName string) bool {
	if b == nil {
		return false
	}
	if b.FromExts[Ext(oldName)] || b.ToExts[Ext(newName)] {
		return true
	}
	for _, p := range b.NamePrefixes {
		if hasPrefixFold(oldName, p) || hasPrefixFold(newName, p) {
			return true
		}
	}
	return false
}

// DefaultKnownExts là danh sách khởi đầu các đuôi ransomware đã biết (không dấu chấm).
// Chỉ là tín hiệu bổ sung (R6); phát hiện chính không phụ thuộc danh sách này.
// Bản đầy đủ thay bằng feed cập nhật được.
func DefaultKnownExts() []string {
	return []string{
		"lockbit", "locky", "zepto", "odin", "thor", "aesir", "osiris", "cerber", "cerber3",
		"wncry", "wncryt", "wcry", "ryk", "conti", "akira", "basta", "royal", "play",
		"xtbl", "crinf", "r5a", "vvv", "ccc", "micro", "zzz", "xxx", "ttt", "ecc", "ezz", "exx",
		"cryp1", "crypt", "crypted", "encrypted", "locked",
	}
}

// commonExts là các định dạng file hợp lệ phổ biến. Đổi sang một trong các đuôi này
// (vd chuẩn hóa .jpg → .jpeg) không bị coi là "đuôi lạ" ở R3, kể cả khi share chưa từng có.
var commonExts = setOf(
	// văn phòng, văn bản
	"doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx", "ppt", "pptx", "pptm",
	"pps", "ppsx", "pot", "potx", "odt", "ods", "odp", "odg", "rtf", "txt", "csv", "tsv", "md", "log", "pdf",
	"xps", "epub", "vsd", "vsdx", "pub", "one", "msg", "eml", "pst", "ost",
	// ảnh, thiết kế
	"jpg", "jpeg", "jpe", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "heif", "raw", "cr2", "nef",
	"arw", "dng", "psd", "ai", "eps", "svg", "ico", "emf", "wmf", "indd",
	// âm thanh, video
	"mp3", "wav", "flac", "aac", "m4a", "ogg", "wma", "mp4", "m4v", "mov", "avi", "mkv", "wmv", "flv",
	"webm", "mpg", "mpeg", "3gp",
	// nén, ảnh đĩa
	"zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "cab", "iso",
	// kỹ thuật, CAD
	"dwg", "dxf", "dgn", "step", "stp", "iges", "igs", "stl", "skp", "rvt", "ifc",
	// dữ liệu, mã nguồn, cấu hình
	"xml", "json", "yaml", "yml", "ini", "cfg", "conf", "sql", "mdb", "accdb", "db", "sqlite", "dbf",
	"html", "htm", "css", "js", "ts", "py", "java", "c", "cpp", "h", "cs", "go", "php", "sh", "bat", "ps1",
	"lnk", "url", "exe", "dll", "msi",
)

// IsCommonExt cho biết ext (lowercase, không dấu chấm) là định dạng hợp lệ phổ biến.
func IsCommonExt(ext string) bool { return commonExts[ext] }

func setOf(v ...string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
