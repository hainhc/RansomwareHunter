# RansomwareHunter — PoC giai đoạn 0

Phát hiện ransomware trên SAN/NAS bằng **metadata** (tên file, thư mục, kích thước, thời gian, file ID). Không đọc nội dung file.
Thiết kế đầy đủ: [docs/DESIGN.md](docs/DESIGN.md). Phạm vi PoC: §12.
Video giới thiệu và demo (4 phút, không có tiếng): [docs/RansomwareHunter-demo.mp4](docs/RansomwareHunter-demo.mp4).

## Thành phần

| Chương trình | Vai trò |
|---|---|
| `rh-server` | Detection engine, scanner Tầng C (SMB/NFS), giám sát canary, nhận syslog từ Synology/QNAP, USN Journal (nếu chạy trên Windows file server), API, cảnh báo |
| `rh-agent-win` | Agent đọc USN Journal trên Windows File Server / host mount LUN SAN, gửi sự kiện về `rh-server` |
| `rh-simulator` | Tạo dữ liệu thử và mô phỏng đổi đuôi hàng loạt / thao tác hợp lệ trên **thư mục test** |

| Gói | Nội dung |
|---|---|
| `internal/event` | Mô hình `FileEvent`, phân tích đuôi, chuẩn hóa mẫu đuôi (`.id-{HEX}.[{EMAIL}].wallet`), luật đổi tên hợp lệ |
| `internal/detect` | Cửa sổ trượt theo scope (share / cây thư mục / tác nhân), luật R1–R7, ghép DELETE+CREATE, incident |
| `internal/scanner` | Quét tăng dần theo mtime thư mục; Windows dùng `FileIdBothDirectoryInfo` (một handle thư mục, lấy FileId theo lô) |
| `internal/usn` | Đọc USN Journal (`FSCTL_ENUM_USN_DATA`, `FSCTL_READ_USN_JOURNAL`), cache chỉ thư mục |
| `internal/canary` | stat() file mồi định kỳ, tạo file mồi |
| `internal/syslogconn` | Nhận syslog UDP/TCP (RFC 3164/5424, octet-counting), đọc log thao tác file Synology/QNAP hoặc định dạng tự khai báo, gán user + IP |
| `internal/notify` | Console, Email (SMTP), Telegram, Syslog CEF, Webhook |
| `internal/store`, `internal/api` | Lưu incident (JSON) + danh sách file (CSV), HTTP API |

## Build

```bash
go build -o bin/ ./cmd/...
```

```bash
go test ./...
```

Cần Go 1.24+. Không có thư viện ngoài.

## Chạy

1. Sao chép `configs/rh-server.example.json` thành `configs/rh-server.json`, sửa `scanners` / `usn` / `canaries` / `notify`. Bí mật (mật khẩu SMTP, token Telegram, token agent) đặt bằng biến môi trường có tên ghi trong cấu hình.
2. Tạo file mồi trên share (ghi vào share, cần quyền ghi):

```bash
bin/rh-server.exe canary-deploy -root "\\nas01\Finance" -dirs ".,Phong KeToan,Phong NhanSu"
```

3. Chạy server:

```bash
bin/rh-server.exe run -config configs/rh-server.json
```

4. Trên Windows File Server (quyền Administrator, journal đã bật bằng `fsutil usn createjournal m=4294967296 a=536870912 D:`):

```bash
bin/rh-agent-win.exe -config configs/rh-agent.json
```

API (mặc định chỉ nghe `127.0.0.1`; đặt `ui_user` + `ui_password_env` khi mở ra mạng):

| Đường dẫn | |
|---|---|
| `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}` | Danh sách / chi tiết incident |
| `GET /api/v1/incidents/{id}/files.csv` | Danh sách đầy đủ file bị đổi đuôi (UTF-8 BOM, mở được bằng Excel) |
| `GET /api/v1/status` | Số liệu engine, scanner |
| `POST /api/v1/events`, `POST /api/v1/baseline` | Agent gửi sự kiện (Bearer token) |

### Yêu cầu khi mount share cho scanner

- NFS: `actimeo=0` (hoặc `noac`), `lookupcache=none`, `nconnect=8`.
- SMB trên Linux: `cache=none`, `actimeo=0`, `serverino`. Scanner Windows: đặt `DirectoryCacheLifetime=0`, `FileNotFoundCacheLifetime=0` (LanmanWorkstation\Parameters).
- Tài khoản quét chỉ cần quyền **List folder / Read attributes**.

## Synology / QNAP qua syslog

NAS gửi log thao tác file (tạo, xóa, đổi tên…) kèm **user và IP máy trạm** tới `rh-server` qua syslog. Nhờ vậy cảnh báo chỉ ra được tài khoản và máy đang đổi đuôi file, độ trễ khoảng 1 giây. Dữ liệu chỉ là dòng log, không đọc file.

Log này chỉ có cho **SMB**. Share NFS trên Synology/QNAP vẫn cần `scanners` (Tầng C) + `canaries`.

### Synology DSM 7

1. Control Panel › File Services › SMB › Advanced Settings (Log Settings): bật transfer log, chọn đủ các loại thao tác (create, delete, rename, move, write).
2. Log Center › Log Sending: máy chủ = IP của `rh-server`, cổng 514, giao thức **TCP** (UDP có thể rơi gói khi bị tấn công dồn dập), định dạng IETF (RFC 5424) hoặc BSD (RFC 3164) đều được.
3. Trong cấu hình `rh-server`: `syslog.devices[]` với `format: "synology"`, `address` = IP của NAS, `share_prefix` = `\\tên-nas\`.

Định dạng `synology` đã đối chiếu với log mẫu thật công khai của DSM 7.0 (dòng `WinFileService Event: rename, Path: /share/a -> /share/b, File/Folder: File, Size: …, User: …, IP: …`). Bật transfer log có thể sinh nhiều log vì cả thao tác `read` cũng được ghi; `rh-server` bỏ qua `read` ngay khi nhận.

### QNAP QTS / QuTS hero

1. QuLog Center › Access Log Settings: bật ghi log cho kết nối **SMB**.
2. QuLog Center › Log Sender › Send to Syslog Server: IP của `rh-server`, cổng 514, TCP.
3. Cấu hình: `format: "qnap"`, `strip_prefix: "^/share/(CACHEDEV[0-9]+_DATA|MD0_DATA|HDA_DATA)/"`.

**Định dạng `qnap` chưa được đối chiếu với log thật** (chưa tìm được mẫu log thao tác file công khai). Trước khi dùng thật:

1. Bật `capture_file`, thao tác thử trên NAS: tạo, đổi tên, xóa vài file qua SMB.
2. Kiểm tra parser trên các dòng thu được:

```bash
bin/rh-server.exe syslog-test -format qnap -file data/syslog-unmatched.log
```

3. Nếu dòng nào "KHÔNG KHỚP" hoặc "THIẾU DỮ LIỆU", khai báo `custom_formats` (regex có nhóm `op`, `path` hoặc `old`/`new`, `user`, `ip`) rồi chạy lại `syslog-test -config … -format <tên>`. Gửi vài dòng log thật để cập nhật định dạng có sẵn.

`custom_formats` cũng dùng được cho Samba `full_audit` hoặc NAS khác (xem ví dụ trong `configs/rh-server.example.json`).

## Kiểm thử bằng mô phỏng

`rh-simulator` chỉ chạy `attack`/`benign`/`office` trên thư mục có file đánh dấu do lệnh `seed` tạo.

```bash
bin/rh-simulator.exe seed -dir D:/rh-test -files 20000 -dirs 400
```

```bash
bin/rh-simulator.exe attack -dir D:/rh-test -mode append -ext .dmr64 -rate 3000 -limit 3000
```

Chế độ `attack`: `append` (a.docx → a.docx.ext), `replace` (a.docx → a.ext), `random` (đuôi ngẫu nhiên từng file), `copydelete` (ghi file mới ngẫu nhiên rồi xóa file gốc).
Thao tác hợp lệ để kiểm tra báo động giả: `benign -from jpg -to jpeg`, `office -limit 500` (mô phỏng cách Word lưu file).

Mô phỏng NAS gửi syslog (không cần NAS thật, không chạm file nào):

```bash
bin/rh-simulator.exe syslog -target 127.0.0.1:514 -format synology -host syno01 -files 1500 -rate 3000
```

## Kết quả đã kiểm chứng (2026-10-30, ổ NTFS cục bộ, 20.000 file / 441 thư mục)

| Kịch bản | Kết quả |
|---|---|
| Quét lần đầu | 0,25–0,3 s |
| 500 lần lưu kiểu Office | Không mở incident |
| 2.000 file `.jpg → .jpeg` | Chỉ MEDIUM (ghi nhận, không gửi cảnh báo) |
| Tấn công `append`, đuôi lạ `.dmr64`, 3.000 file/phút | Cảnh báo HIGH sau ~4,5 s, CRITICAL sau ~10 s; CSV đủ 3.000 dòng |
| Tấn công `copydelete` 1.500 file | Cảnh báo sau ~2,3 s; cả 1.500 file ghép cặp đúng (`INFERRED`); ransom note ở 30 thư mục |
| Đổi tên file mồi | CRITICAL sau ~1,5 s |
| Engine (benchmark) | ~3,5 µs/sự kiện ≈ 285.000 sự kiện/giây trên một luồng |
| Syslog Synology mô phỏng: 1.500 file đổi đuôi + 7.500 dòng read/write của người khác, UDP | CRITICAL sau ~1 s, nêu đúng `CORP\user01 từ 10.10.5.23`; nhận đủ 9.072/9.072 dòng, không dòng nào sai định dạng |
| USN Journal thật (`TestLiveJournal`, Administrator, 2026-10-31) | PASS: liệt kê toàn bộ thư mục của volume, đọc journal, nhận đúng sự kiện RENAME `BaoCao.xlsx → BaoCao.xlsx.lockbit` kèm đường dẫn đầy đủ; 7,3 s (phần lớn là bước liệt kê thư mục) |
| Syslog QNAP mô phỏng qua IPv6 | CRITICAL, đúng share `\\qnap01\NhanSu` và tác nhân — chỉ chứng minh luồng xử lý, vì dòng giả lập dùng chính định dạng giả định |

## Chưa kiểm chứng / giới hạn của PoC

- USN Journal thật mới kiểm chứng ở mức `TestLiveJournal` (một lần đổi tên trên ổ hệ thống); chưa chạy `rh-agent-win` liên tục dưới tải tấn công mô phỏng trên ổ có journal.
- Chưa đo trên NAS thật qua SMB/NFS và ở quy mô 10M file (tiêu chí PoC §10). Con số trên là ổ cục bộ.
- Chỉ hỗ trợ bản ghi USN V2 (NTFS); ReFS (V3) chưa hỗ trợ.
- Chưa gán tác nhân (user/IP) cho nguồn USN và scanner; agent sẽ bổ sung qua phiên SMB ở MVP. Nguồn syslog Synology/QNAP đã có user/IP.
- Định dạng log QNAP chưa đối chiếu với log thật; định dạng Synology mới đối chiếu với log mẫu DSM 7.0 công khai, chưa với NAS của mình. Chưa rõ thao tác "move" sang thư mục khác được DSM ghi thế nào (đã ánh xạ `move` → RENAME phòng khi có).
- Syslog UDP có thể rơi gói khi tải rất cao; nên cấu hình NAS gửi TCP.
- Trạng thái scanner trong RAM (~80–100 byte/file); MVP thay bằng Pebble. Incident lưu file JSON/CSV; MVP thay bằng PostgreSQL.
- Chưa có Web UI, responder (phản ứng có phê duyệt) và các connector FPolicy, CEE, ZFS diff.
