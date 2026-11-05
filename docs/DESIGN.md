# RansomwareHunter — Thiết kế hệ thống & Đánh giá khả thi

> Phiên bản: 1.0 (đã chốt) · Ngày chốt: 2026-10-30
> Phạm vi: phát hiện ransomware trên SAN/NAS dựa **hoàn toàn trên metadata** (tên file, đường dẫn, kích thước, thời gian, file ID), **không đọc nội dung file**.

**Các quyết định đã chốt**

| # | Quyết định |
|---|-----------|
| Q1 | Thiết kế **connector riêng cho từng hệ thống lưu trữ** (§4) |
| Q2 | Giám sát cả **SMB và NFS** |
| Q3 | Quy mô **trên 100 triệu file / hệ thống** — mục tiêu thiết kế 500M file (§7) |
| Q4 | **Phản ứng có phê duyệt**: hệ thống đề xuất hành động, người trực xác nhận mới thực thi (§6) |
| Q5–Q9 | Theo giá trị mặc định ở §11 |

---

## 1. Mục tiêu & phạm vi

### 1.1 Yêu cầu chức năng

| # | Yêu cầu | Cách đáp ứng |
|---|---------|--------------|
| F1 | Monitor danh sách file trên SAN/NAS liên tục | Connector riêng từng nền tảng, mỗi connector dùng nguồn tốt nhất nền tảng đó có: sự kiện thời gian thực → snapshot diff → quét metadata |
| F2 | Tự động phát hiện đổi đuôi file hàng loạt | Detection engine theo cửa sổ trượt, chấm điểm nhiều tín hiệu (số lượng, hội tụ đuôi, đuôi lạ, ransom note, canary) |
| F3 | Không đọc file | Chỉ dùng event metadata / `readdir` / `stat` / snapshot diff. Tài khoản thu thập **chỉ có quyền List Folder + Read Attributes** (hoặc quyền audit/event tương đương), không có Read Data |
| F4 | Chịu tải số lượng file lớn | 500M file/hệ thống, 50k sự kiện/giây khi bị tấn công; với hệ thống > 100M file bắt buộc dùng nguồn sự kiện hoặc snapshot diff làm nguồn chính |
| F5 | Cảnh báo rõ ràng | Incident gồm: share, tác nhân (user/IP), bảng `đuôi cũ → đuôi mới` kèm số lượng, danh sách đầy đủ file bị đổi (xem/xuất CSV), ransom note |
| F6 | Phản ứng có phê duyệt | Đề xuất hành động theo nền tảng (snapshot, ngắt phiên, khóa tài khoản, chặn IP…), thực thi sau khi người có quyền phê duyệt, ghi audit đầy đủ |

### 1.2 Ngoài phạm vi

- Phân tích nội dung/entropy file (vi phạm F3).
- Phản ứng tự động **không qua phê duyệt**.
- Khôi phục dữ liệu (dựa vào snapshot/backup của hệ thống lưu trữ; hệ thống chỉ hỗ trợ tạo snapshot và chỉ ra file cần khôi phục).

### 1.3 Lưu ý quan trọng về SAN

SAN cung cấp **block storage** — ở tầng SAN không tồn tại khái niệm "file", chỉ có LUN và block. Danh sách file chỉ nhìn thấy tại **host đang mount LUN** (Windows NTFS/ReFS, Linux ext4/XFS…). Vì vậy SAN được giám sát qua **agent trên host mount LUN** (§4.1, §4.2). Không giám sát được trên SAN controller/switch.

---

## 2. Kiến trúc tổng thể

```
 ┌───────────────────────────── CONNECTOR THEO NỀN TẢNG (§4) ─────────────────────────────┐
 │ Windows FS / host LUN │ Linux host / Samba / NFS │ NetApp ONTAP │ Dell PowerScale/Unity  │
 │   USN Journal agent   │   fanotify agent          │   FPolicy     │   CEE / audit syslog   │
 │ Synology DSM / QNAP   │ TrueNAS / ZFS             │ NAS khác (generic)                     │
 │   transfer log syslog │   zfs diff                │   quét metadata SMB/NFS + canary       │
 └───────────────┬────────────────────────────────────────────────────────────────────────┘
                 ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │ CHUẨN HÓA → FileEvent (CREATE/DELETE/RENAME/MODIFY) + Actor (user/IP)    │
 │ Ghép cặp rename · Tiền tổng hợp khi bão sự kiện                          │
 └───────────────────────────────┬─────────────────────────────────────────┘
                                 ▼
                  NATS JetStream cluster (subject theo hệ thống/share)
                     │                                  │
                     ▼                                  ▼
 ┌──────────────────────────────────┐     ┌──────────────────────────────┐
 │ DETECTION ENGINE (phân vùng)     │     │ Event archive (ClickHouse)   │
 │ cửa sổ trượt · luật · điểm        │     │ lịch sử 30 ngày, điều tra     │
 │ → Incident                        │     └──────────────────────────────┘
 └───────┬───────────────────────────┘
         ▼
 Incident store (PostgreSQL) ──► Notifier: Email, Telegram, Teams/Slack, Syslog CEF, Webhook
         │
         ▼
 Web UI + API ──(người trực phê duyệt)──► RESPONDER (§6) ──► API của từng nền tảng / AD / firewall
```

### 2.1 Thành phần

| Thành phần | Vai trò |
|-----------|---------|
| `rh-agent-win` | Agent Windows: USN Journal (file server, host mount LUN SAN) |
| `rh-agent-linux` | Agent Linux: fanotify / auditd, Samba full_audit |
| `rh-conn-ontap` | FPolicy external engine cho NetApp ONTAP |
| `rh-conn-dell` | Nhận sự kiện CEE (HTTP) / audit syslog từ PowerScale, Unity, PowerStore |
| `rh-conn-syslog` | Nhận và parse transfer log từ Synology, QNAP, Samba |
| `rh-conn-zfs` | Snapshot định kỳ + `zfs diff` cho TrueNAS / ZFS |
| `rh-scanner` | Quét metadata SMB/NFS tăng dần + giám sát canary (lưới an toàn cho mọi nền tảng) |
| `rh-server` | Detection engine, Incident, Notifier, API, Web UI |
| `rh-responder` | Thực thi hành động phản ứng sau phê duyệt; tách biệt, giữ credential có quyền ghi |
| `rh-simulator` | Công cụ kiểm thử: tạo file mẫu và đổi tên hàng loạt trên share test (không mã hóa) |

---

## 3. Cơ chế thu thập dùng chung

### 3.1 Ba tầng nguồn dữ liệu

| Tầng | Cơ chế | Độ trễ | Phụ thuộc số file? | Dùng khi |
|------|--------|--------|--------------------|----------|
| **A** | Sự kiện thời gian thực từ OS/NAS | giây | Không | Nguồn chính nếu nền tảng hỗ trợ |
| **B** | So sánh 2 snapshot (diff metadata) | 1–5 phút | Không (chỉ phụ thuộc lượng thay đổi) | Nền tảng không có sự kiện, hoặc làm nguồn đối soát |
| **C** | Quét metadata SMB/NFS tăng dần | phút | Có (theo số thư mục) | Lưới an toàn, NAS không có A/B |

Với hệ thống > 100M file: **A hoặc B là bắt buộc**; C chỉ chạy như lưới an toàn (canary + thư mục nóng + quét đầy đủ chu kỳ dài).

### 3.2 Tầng C — Quét metadata tăng dần

**Ý tưởng then chốt:** khi file trong thư mục bị tạo / xóa / **đổi tên**, `mtime` của **thư mục cha** thay đổi:

```
Mỗi chu kỳ:
  1. stat() toàn bộ thư mục đã biết (số thư mục ≈ 1–5% số file)
  2. Chỉ readdir() thư mục có mtime thay đổi
     (SMB QUERY_DIRECTORY / NFS READDIRPLUS trả attributes theo lô → không stat từng file)
  3. Diff với trạng thái cũ (Pebble) → sinh FileEvent
  4. Thư mục con mới → thêm vào danh sách theo dõi
```

**Ghép cặp rename từ diff một thư mục:**
1. Cùng `file_id` (inode NFS / FileId SMB), khác tên → `RENAME` (chính xác).
2. Kiểu "ghi bản mã hóa mới rồi xóa bản gốc": ghép `DELETE a` + `CREATE b` nếu `b` bắt đầu bằng tên `a` hoặc cùng stem → `RENAME_INFERRED`.
3. Còn lại: ghép theo kích thước gần bằng khi chỉ có 1 ứng viên → `RENAME_WEAK` (trọng số thấp).

**Ưu tiên:** thư mục nóng (vừa thay đổi, home/profile, share quan trọng) chu kỳ 10–15 s; thư mục lạnh theo chu kỳ đầy đủ; giới hạn ops/s theo hệ thống.

**Mount bắt buộc** (tránh cache metadata):
- NFS: `actimeo=0` hoặc `noac`, `lookupcache=none`, `nconnect=8`.
- SMB (Linux): `cache=none`, `actimeo=0`, `serverino`. SMB (Windows scanner): `DirectoryCacheLifetime=0`, `FileNotFoundCacheLifetime=0`.

**Hạn chế:** ghi đè nội dung không đổi mtime thư mục → Tầng C không thấy mã hóa tại chỗ không đổi tên.

### 3.3 Canary / honeyfile

- File mồi đặt ở đầu mỗi share và thư mục quan trọng, tên đứng đầu alphabet (`!000_Do_Not_Delete.docx`, `000_Budget.xlsx`).
- `rh-scanner` `stat` canary mỗi 5 s; với nền tảng có Tầng A thì sự kiện trên canary được nhận ngay.
- Canary bị đổi tên/xóa/đổi size/mtime → **CRITICAL ngay lập tức**.

### 3.4 Mô hình dữ liệu chuẩn hóa

```go
type FileEvent struct {
    TS        time.Time
    SourceID  string     // connector/agent
    System    string     // định danh hệ thống lưu trữ
    Share     string     // \\nas01\Finance hoặc nas01:/export/finance
    Protocol  string     // SMB | NFS | LOCAL
    Op        Op         // CREATE | DELETE | RENAME | MODIFY
    Path      string
    OldPath   string     // với RENAME
    FileID    uint64     // inode / FileId / FRN (0 nếu không có)
    Size      int64
    OldSize   int64
    MTime     time.Time
    Actor     *Actor     // user (SID/UID), client IP, session ID — nil nếu nguồn không có
    PairConf  PairConf   // EXACT | INFERRED | WEAK
}
```

---

## 4. Thiết kế riêng cho từng hệ thống lưu trữ

### 4.0 Ma trận tổng hợp

| Nền tảng | Nguồn chính | Nguồn phụ | Rename old→new | User / IP | MODIFY (R8) | Độ trễ mục tiêu | Khả thi |
|----------|-------------|-----------|----------------|-----------|-------------|-----------------|---------|
| Windows File Server / host mount LUN | USN Journal (A) | Tầng C | Có | Có (tra phiên SMB) | Có | ≤ 10 s | **Cao** |
| Linux host / Samba / NFS server | fanotify (A) | auditd, Samba full_audit | Có | Samba: có; NFS: hạn chế | Có | ≤ 10 s | **Cao** (kernel ≥ 5.17) |
| NetApp ONTAP | FPolicy async (A) | ARP alert, Tầng C | Có | Có | Có | ≤ 15 s | **Cao** |
| Dell PowerScale (OneFS) | Protocol audit → CEE/syslog (A) | ChangelistCreate (B) | Có | Có | Có | ≤ 30 s | **Cao** |
| Dell Unity / PowerStore (NAS) | CEPA → CEE (A) | Tầng C | Có | Có | Có | ≤ 30 s | **TB–Cao** |
| Synology DSM | SMB transfer log → syslog (A) | Tầng C (NFS) | Có (SMB) | Có (SMB) | Hạn chế | SMB ≤ 30 s, NFS phút | **Trung bình** |
| QNAP QTS / QuTS hero | File access log → syslog (A) | `zfs diff` (QuTS hero), Tầng C | Có (SMB) | Có (SMB) | Hạn chế | SMB ≤ 30 s, NFS phút | **Trung bình** |
| TrueNAS / ZFS | Snapshot + `zfs diff` (B) | Samba audit (A), Tầng C | Có | Qua Samba audit | Có (M) | 1–2 phút | **Cao** |
| NAS khác (HPE, Hitachi, Huawei…) | Tầng C + canary | Syslog audit nếu có | Suy luận | Không | Không | phút | **Trung bình** |

> Các điểm ghi "(xác minh PoC)" bên dưới là chi tiết phụ thuộc phiên bản firmware/license cần kiểm tra trên thiết bị thật.

### 4.1 Windows File Server & host Windows mount LUN SAN

**Thu thập — `rh-agent-win` (Windows service):**
- Đọc USN Journal bằng `FSCTL_READ_USN_JOURNAL` trên từng volume NTFS/ReFS. Bản ghi có sẵn `RENAME_OLD_NAME` / `RENAME_NEW_NAME`, `FILE_CREATE`, `FILE_DELETE`, `DATA_OVERWRITE/EXTEND/TRUNCATION` (→ có MODIFY cho R8), kèm `FileReferenceNumber` và `ParentFileReferenceNumber`. Không mở file.
- Dựng đường dẫn: bản ghi USN đã có tên file + FRN thư mục cha → agent **chỉ cache thư mục** (FRN → tên, cha). Khởi tạo nhanh bằng `FSCTL_ENUM_USN_DATA` (duyệt MFT, chỉ metadata). 5M thư mục ≈ 500 MB RAM/đĩa, thay vì cache toàn bộ file.
- Cấu hình journal đủ lớn để không bị ghi vòng khi agent tạm dừng: `fsutil usn createjournal m=4294967296 a=536870912 <vol>` (4 GB). Agent lưu USN cuối đã xử lý → khởi động lại không mất sự kiện.
- **Gán tác nhân:** USN không có user. Khi một scope vượt ngưỡng, agent truy vấn `MSFT_SmbOpenFile` / `MSFT_SmbSession` (CIM) để tìm phiên SMB đang mở file trong thư mục bị ảnh hưởng → user + client IP. Tùy chọn: ETW provider `Microsoft-Windows-SMBServer` cho gán tác nhân liên tục (xác minh PoC về overhead).
- Failover cluster / SOFS: agent trên mọi node, theo dõi volume theo owner hiện tại.
- Host mount LUN SAN không chia sẻ (ứng dụng ghi trực tiếp): tác nhân là tiến trình cục bộ → bổ sung ETW `Microsoft-Windows-Kernel-File` khi có incident (tùy chọn).

**Phản ứng:** tạo VSS shadow copy (`Win32_ShadowCopy.Create`), `Close-SmbSession`, `Block-SmbShareAccess` (chặn user trên share), khóa tài khoản AD.

**Quyền:** agent chạy LocalSystem (đọc journal là quyền volume, không đọc dữ liệu file). Phản ứng thực thi qua WinRM bằng tài khoản riêng của responder.

### 4.2 Linux host (mount LUN SAN), Samba, NFS server (knfsd)

**Thu thập — `rh-agent-linux`:**
- **fanotify** `FAN_MARK_FILESYSTEM` với `FAN_REPORT_DFID_NAME` + `FAN_RENAME` (kernel ≥ 5.17), `FAN_CREATE`, `FAN_DELETE`, `FAN_MODIFY`. Một mark cho cả filesystem, không cần watch từng thư mục như inotify. Đường dẫn dựng từ handle thư mục cha (cache thư mục) + tên.
- Kernel cũ (RHEL 8 / Ubuntu 20.04): fallback **auditd** rule trên syscall `rename/renameat/renameat2/unlinkat` giới hạn theo thư mục export (overhead TB, xác minh PoC).
- **Samba:** bật VFS `full_audit` (`full_audit:success = renameat unlinkat create_file`, prefix `%u|%I|%S`) → syslog → `rh-conn-syslog`. Cho user + IP + share chính xác.
- **NFS server (knfsd):** fanotify thấy thao tác do nfsd thực hiện nhưng tiến trình là luồng kernel → **không có client IP/UID trực tiếp**. Gán tác nhân bằng đối chiếu `/proc/fs/nfsd/clients` (NFSv4) — hạn chế, xác minh PoC.

**Phản ứng:** snapshot LVM/ZFS/btrfs; Samba: `smbstatus` + `smbcontrol <pid> close-share` / kill phiên; NFS: `exportfs -u` client hoặc rule firewall chặn IP; khóa tài khoản AD/LDAP.

### 4.3 NetApp ONTAP

**Thu thập — `rh-conn-ontap` (FPolicy external engine):**
- Tạo FPolicy policy **async, non-mandatory** (`is-mandatory false`) → nếu engine ngừng, I/O người dùng không bị ảnh hưởng.
- Event: CIFS `create, rename, delete, close(modified)`; NFSv3/v4 `create, rename, delete, write`. Sự kiện có đường dẫn cũ/mới, SID/UID, client IP.
- Bộ lọc tại ONTAP: chỉ gửi các thao tác trên, loại trừ volume/đường dẫn không cần → giảm tải.
- ONTAP 9.14.1+: bật **FPolicy persistent store** để đệm sự kiện khi engine mất kết nối (xác minh PoC).
- Chạy ≥ 2 engine server (FPolicy phân phối theo node/engine) cho HA và thông lượng.
- Bổ sung: đọc cảnh báo **Autonomous Ransomware Protection** (nếu được bật) qua REST/EMS làm tín hiệu thêm.
- Tầng B: SnapDiff (cần kiểm tra license/quyền truy cập API — xác minh PoC). Tầng C chạy làm lưới an toàn.

**Phản ứng (REST API ONTAP):** tạo snapshot volume; đóng phiên CIFS; thêm rule chặn client IP vào export policy (NFS); khóa tài khoản AD.

**Quyền:** role ONTAP riêng cho collector (cấu hình FPolicy, đọc), role riêng cho responder (snapshot, cifs session, export policy).

### 4.4 Dell PowerScale (OneFS)

**Thu thập — `rh-conn-dell`:**
- Bật **Protocol Auditing** cho các access zone; chọn sự kiện create/rename/delete/write. Đẩy sự kiện qua **CEE** (HTTP tới `rh-conn-dell` đóng vai CEE endpoint) hoặc **syslog forwarding** (OneFS 9.x). Sự kiện có user SID, client IP, đường dẫn cũ/mới.
- Bật audit trên **mọi node** của cluster; connector nhận song song.
- Tầng B: job **ChangelistCreate** giữa 2 snapshot SnapshotIQ làm nguồn đối soát (job-based, 5–15 phút).

**Phản ứng (PAPI):** tạo snapshot SnapshotIQ; đóng phiên SMB; chặn user trên share/đổi quyền share; khóa tài khoản AD.

### 4.5 Dell Unity / PowerStore (file/NAS server)

- Bật **CEPA** trên NAS server, trỏ tới `rh-conn-dell` (CEE). Sự kiện SMB/NFS rename/create/delete kèm user/IP (danh sách event type xác minh PoC theo phiên bản).
- Tầng C làm lưới an toàn.
- **Phản ứng:** snapshot qua REST API của Unity/PowerStore; khóa tài khoản AD; chặn IP qua firewall webhook.

### 4.6 Synology DSM

- **SMB:** bật *transfer log* của dịch vụ SMB (create, delete, rename, write) → Log Center gửi syslog tới `rh-conn-syslog`. Có user + IP.
- **NFS:** DSM không cung cấp log thao tác NFS tương đương (xác minh PoC) → dùng **Tầng C** + canary cho share NFS.
- Tùy chọn Tầng B: snapshot Btrfs (Snapshot Replication) + `btrfs send --no-data` để lấy rename/unlink — cần SSH root, không khuyến nghị mặc định.
- **Phản ứng (DSM Web API):** tạo snapshot share; vô hiệu tài khoản cục bộ/AD. DSM không có API đóng phiên SMB tin cậy → dùng khóa tài khoản + chặn IP qua firewall webhook.

### 4.7 QNAP QTS / QuTS hero

- **SMB:** bật *File access log* (QuLog Center), gửi syslog tới `rh-conn-syslog`; có user + IP.
- **QuTS hero (ZFS):** có thể dùng snapshot + diff tương tự TrueNAS nếu truy cập được (xác minh PoC).
- **NFS:** Tầng C + canary.
- **Phản ứng:** tạo snapshot qua API; vô hiệu tài khoản; chặn IP qua firewall webhook.

### 4.8 TrueNAS (CORE/SCALE) & hệ thống ZFS

- **Tầng B là nguồn chính:** `rh-conn-zfs` tạo snapshot mỗi 1–2 phút (giữ ~30 bản, tự xoay vòng — chỉ xóa snapshot do chính hệ thống tạo) rồi chạy `zfs diff -FHt snapA snapB`. Kết quả có loại thay đổi (`M`, `R`, `+`, `-`) và đường dẫn cũ → mới cho rename. Chi phí tỷ lệ với **lượng thay đổi**, không phụ thuộc tổng số file → rất phù hợp > 100M file.
- Snapshot dùng để phát hiện đồng thời là **điểm khôi phục** sát thời điểm tấn công.
- Gán tác nhân: bật SMB audit của TrueNAS SCALE (bản mới) hoặc Samba `full_audit` → syslog (xác minh PoC theo phiên bản).
- **Phản ứng (TrueNAS API):** giữ snapshot (đặt hold, ngừng xoay vòng); đóng phiên SMB; khóa tài khoản; chặn IP.

### 4.9 NAS khác (generic)

- `rh-scanner` Tầng C qua SMB/NFS + canary dày đặc.
- Nếu thiết bị gửi được audit syslog: viết parser cấu hình được (regex/template) trong `rh-conn-syslog`.
- Phản ứng: khóa tài khoản AD, chặn IP qua firewall/NAC webhook.

### 4.10 Giao diện connector chung

Mỗi connector cài đặt cùng interface để engine và responder không phụ thuộc nền tảng:

```go
type Connector interface {
    Start(ctx context.Context, out chan<- FileEvent) error
    Health() HealthStatus            // heartbeat, độ trễ, backlog
    Capabilities() Caps              // HasActor, HasModify, HasExactRename, LatencyClass
}

type ResponseProvider interface {
    Actions() []ActionSpec           // các hành động nền tảng hỗ trợ
    Execute(ctx context.Context, a ApprovedAction) (Result, error)
    Revert(ctx context.Context, a ExecutedAction) (Result, error)   // nếu hành động đảo ngược được
}
```

`Capabilities()` được engine dùng để bật/tắt luật (vd R8 chỉ bật khi `HasModify`) và hiển thị độ tin cậy trên cảnh báo.

---

## 5. Detection engine

### 5.1 Phân tích tên file

- `ext`: phần sau dấu chấm cuối, lowercase.
- `appended_suffix`: nếu tên mới bắt đầu bằng tên cũ → phần nối thêm (vd `.id-1A2B3C4D.[x@mail.cc].wallet`).
- **Suffix template**: thay chuỗi hex/số dài, email, UUID bằng placeholder → `.id-{HEX8}.[{EMAIL}].wallet`, để gộp các biến thể chứa ID nạn nhân vào **một nhóm**.

### 5.2 Scope theo dõi

Mỗi sự kiện cập nhật bộ đếm ở 3 scope: **tác nhân** (user + IP, khi có) · **cây thư mục** (share + 2 cấp đầu) · **toàn share**. Bộ đếm cửa sổ 60 s, 10 phút, 24 h dạng ring buffer → bộ nhớ cố định.

### 5.3 Luật phát hiện

| Luật | Tín hiệu | Mặc định | Điểm |
|------|----------|----------|------|
| R1 | Số file đổi đuôi (loại trừ chuyển đổi lành tính) | ≥ 50 file / 60 s | 30 |
| R2 | **Hội tụ đuôi**: nhiều đuôi gốc → một đuôi/mẫu mới | mẫu top ≥ 80% & **chính mẫu đó** đến từ ≥ 3 đuôi gốc | +30 |
| R2b | **Đuôi ngẫu nhiên**: nhiều đuôi mới khác nhau, mỗi đuôi ~1 file, đều chưa từng thấy | ≥ 50 / 60 s | +30 |
| R3 | **Đuôi lạ**: chưa có trong kho đuôi của share (24 h) **và không phải định dạng phổ biến** (docx, jpeg, zip…) | ≥ 90% sự kiện | +15 |
| R4 | Phân tán thư mục | ≥ 10 thư mục | +10 |
| R5 | **Ransom note**: cùng một tên file mới ở nhiều thư mục | ≥ 10 thư mục / 5 phút | +30 |
| R6 | Đuôi khớp danh sách ransomware đã biết (feed) | ≥ 1 trùng + R1 | +40 |
| R7 | **Canary** bị đổi tên/xóa/sửa | 1 lần | 100 |
| R8 | Bão MODIFY không đổi tên (chỉ khi connector `HasModify`) | ≥ 500 / 60 s, lệch baseline > 10σ | 25 |
| R9 | Tấn công chậm: R2/R3 trên cửa sổ 24 h | ≥ 200 file / 24 h | 35 (MEDIUM) |

**Mức độ:** ≥ 80 CRITICAL · 50–79 HIGH · 30–49 MEDIUM (ghi nhận, không gửi khẩn).

### 5.4 Giảm báo động giả

- Chuyển đổi lành tính mặc định: `*.tmp → *`, `*.part/*.crdownload → *`, `* → *.bak/*.old`, file tạm Office (`~$*`, `~WRL*.tmp`).
- Allowlist: tài khoản dịch vụ (backup, migration), đường dẫn, khung giờ bảo trì.
- Học baseline 7–14 ngày ở chế độ quan sát: kho đuôi theo share, tốc độ rename/giờ (EWMA) → ngưỡng thích ứng.

### 5.5 Incident

- Sự kiện thỏa luật gộp vào **incident đang mở** theo scope; tiếp tục cập nhật, đóng sau 10 phút yên lặng.
- Gửi cảnh báo ngay khi đạt HIGH/CRITICAL, cập nhật tóm tắt mỗi 2 phút.
- Danh sách file bị ảnh hưởng ghi stream (COPY theo lô) vào PostgreSQL phân vùng; engine chỉ giữ bộ đếm + reservoir 100 file mẫu.

### 5.6 Mẫu cảnh báo

```
[CRITICAL] Nghi ngờ ransomware – \\nas01\Finance  (Incident #1234, điểm 100)
Hệ thống       : NetApp ONTAP cluster01 / SVM svm_fin  (nguồn: FPolicy, độ tin cậy cao)
Thời gian      : 2026-10-29 14:02:11 → 14:03:40 (đang diễn ra)
Tác nhân       : CORP\user01 từ 10.10.5.23 (SMB session 0x4a1f)
Quy mô         : 3.214 file bị đổi đuôi trong 1m29s, 187 thư mục
Đuôi mới       : .lockbit (99,6%) — chưa từng xuất hiện trên share này
Chuyển đổi chính:
   .xlsx → .xlsx.lockbit    1.402
   .docx → .docx.lockbit      988
   .pdf  → .pdf.lockbit       611
   (khác)                     213
Ransom note    : "Restore-My-Files.txt" xuất hiện ở 187 thư mục
Canary         : \Finance\!000_Do_Not_Delete.docx bị đổi tên lúc 14:02:13
File mẫu       :
   \Finance\2026\Q3\BaoCao.xlsx  →  BaoCao.xlsx.lockbit
   \Finance\2026\Q3\HopDong.docx →  HopDong.docx.lockbit
Danh sách đầy đủ: https://rh.local/incidents/1234   (xuất CSV)

Hành động đề xuất (chờ phê duyệt):
   [1] Tạo snapshot volume vol_finance
   [2] Đóng phiên SMB 0x4a1f của CORP\user01
   [3] Khóa tài khoản AD CORP\user01
   [4] Chặn IP 10.10.5.23 (firewall)
Phê duyệt tại  : https://rh.local/incidents/1234/respond
```

Kênh gửi: Email, Telegram, Teams/Slack, Syslog CEF/LEEF → SIEM, Webhook (SOAR).

---

## 6. Phản ứng có phê duyệt

### 6.1 Luồng xử lý

```
Incident HIGH/CRITICAL
   → Engine sinh "kế hoạch phản ứng": danh sách hành động phù hợp nền tảng + phạm vi (user, IP, share, volume)
   → Gửi cảnh báo kèm liên kết phê duyệt
   → Người trực đăng nhập Web UI (AD/LDAP SSO), xem chi tiết, chọn hành động → Phê duyệt
   → rh-responder thực thi tuần tự, ghi kết quả từng bước
   → Cập nhật incident + gửi thông báo kết quả
   → (sau điều tra) nút "Hoàn tác" cho hành động đảo ngược được
```

### 6.2 Danh mục hành động

| Hành động | Windows | Linux/Samba | ONTAP | PowerScale | Unity/PowerStore | Synology | QNAP | TrueNAS | Generic | Đảo ngược |
|-----------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Tạo / giữ snapshot | VSS | LVM/ZFS/btrfs | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | – | Có (xóa thủ công) |
| Đóng phiên SMB | ✓ | ✓ | ✓ | ✓ | xác minh | – | – | ✓ | – | Tự hết |
| Chặn user trên share | ✓ | ✓ | ✓ | ✓ | – | – | – | – | – | Có |
| Chặn client NFS | – | ✓ | ✓ | ✓ | xác minh | – | – | ✓ | – | Có |
| Khóa tài khoản AD/LDAP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Có |
| Chặn IP qua firewall/NAC/EDR (webhook) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Có |

### 6.3 Nguyên tắc an toàn

- **Không có hành động nào chạy khi chưa phê duyệt.** Tùy chọn cấu hình duy nhất: cho phép "tạo snapshot" tự động (không phá hủy) — mặc định **tắt**.
- **Không bao giờ xóa dữ liệu** hay xóa snapshot (trừ snapshot xoay vòng do chính `rh-conn-zfs` tạo, và việc xoay vòng tự dừng khi có incident mở).
- RBAC: `Viewer` (xem) · `Responder` (phê duyệt hành động mức thường) · `Admin` (cấu hình, phê duyệt hành động mức cao như chặn share, khóa tài khoản đặc quyền).
- Tài khoản/IP thuộc danh sách bảo vệ (admin, tài khoản dịch vụ, máy chủ hạ tầng) → yêu cầu **2 người phê duyệt**.
- Phê duyệt hết hạn sau 15 phút; thực thi ghi lại tham số đã được duyệt, không thay đổi phạm vi sau khi duyệt.
- Nút trên Telegram/Teams chỉ là **liên kết tới trang phê duyệt** (không phê duyệt trực tiếp trong chat) → tránh lạm dụng tài khoản chat.
- Audit log bất biến (append-only) cho mọi đề xuất, phê duyệt, thực thi, hoàn tác.

### 6.4 Cô lập credential

- `rh-responder` là tiến trình/máy riêng, đặt ở VLAN quản trị; là thành phần **duy nhất** giữ credential có quyền ghi (snapshot, session, AD).
- Collector chỉ có quyền đọc metadata/nhận sự kiện.
- Credential lưu mã hóa (Vault hoặc file mã hóa + khóa từ DPAPI/TPM), mỗi nền tảng một tài khoản quyền tối thiểu.
- `rh-server` gửi lệnh đã phê duyệt sang responder qua kênh mTLS, có chữ ký; responder kiểm tra chữ ký và hạn phê duyệt trước khi thực thi.

---

## 7. Thiết kế chịu tải (> 100M file / hệ thống)

### 7.1 Giả định tải

| Thông số | Giá trị thiết kế |
|----------|-----------------|
| Số file / hệ thống | 500M |
| Số thư mục | ~15M |
| Thay đổi thường ngày | ~3% file/ngày ≈ 15M sự kiện/ngày ≈ 175/s trung bình, đỉnh 10k/s |
| Khi bị tấn công | đỉnh 50k sự kiện/s mỗi hệ thống |

### 7.2 Biện pháp

| Hạng mục | Thiết kế |
|----------|----------|
| Nguồn chính | Bắt buộc Tầng A/B cho hệ thống > 100M file → chi phí theo **lượng thay đổi**, không theo tổng số file |
| Agent USN / fanotify | Chỉ cache **thư mục** (15M × ~100 B ≈ 1,5 GB), không cache file |
| Tầng C (lưới an toàn) | Chia theo cây con cho nhiều `rh-scanner`; ước tính `stat` 15M thư mục ở 30k ops/s ≈ **8–10 phút/chu kỳ**; thư mục nóng + canary 5–15 s; trạng thái Pebble ~100 B/entry → 50 GB, chia theo scanner |
| Phân vùng | Subject NATS theo `hệ thống.share`; engine nhiều instance, mỗi instance sở hữu một tập phân vùng (consumer group) |
| Bộ nhớ engine | Ring buffer + reservoir → O(số scope hoạt động), không phụ thuộc số file |
| Bão sự kiện | Connector tiền tổng hợp theo (thư mục, đuôi, giây) khi vượt ngưỡng; engine phát hiện trên bộ đếm; chi tiết file ghi bất đồng bộ, JetStream lưu đĩa → không mất sự kiện |
| Lưu trữ | PostgreSQL: incident + file bị ảnh hưởng (COPY theo lô, phân vùng ngày). ClickHouse: lịch sử sự kiện 30 ngày (hàng tỷ dòng) cho điều tra |
| Tải lên NAS | Tầng C giới hạn ops/s; quét đầy đủ lần đầu chạy ngoài giờ (có thể mất nhiều giờ) |

### 7.3 Topology triển khai

```
VLAN quản trị
 ├─ NATS JetStream: 3 node
 ├─ rh-server: ≥ 2 node (engine phân vùng + API/UI)
 ├─ PostgreSQL HA (primary + replica) · ClickHouse (1–3 node)
 ├─ Connector: rh-conn-ontap ×2, rh-conn-dell ×2, rh-conn-syslog ×2, rh-conn-zfs, rh-scanner ×N
 └─ rh-responder: 1 node riêng (active/standby)
Trên host lưu trữ: rh-agent-win / rh-agent-linux
```

### 7.4 Tự bảo vệ

- Cảnh báo **im lặng**: connector/agent mất heartbeat hoặc một share hoạt động bình thường đột nhiên không còn sự kiện → cảnh báo HIGH (ransomware thường tắt agent bảo mật).
- Tầng C chạy từ server ngoài, độc lập với agent trên host → vẫn còn khả năng phát hiện nếu agent bị tắt.
- Máy chủ giám sát không dùng chung domain/credential với người dùng nếu có thể.

---

## 8. Công nghệ

| Lớp | Lựa chọn | Lý do |
|-----|----------|-------|
| Ngôn ngữ | **Go** | Đồng thời tốt, binary đơn lẻ Windows/Linux, gọi được `DeviceIoControl` (USN), fanotify, CIM/WinRM |
| KV trạng thái | Pebble | Thuần Go, LSM, chịu ghi lớn |
| Bus | NATS JetStream | Nhẹ, persistent, cluster, phân vùng theo subject |
| DB | PostgreSQL (incident) + ClickHouse (lịch sử sự kiện) | |
| Web | Go API + React (Vite); SSO AD/LDAP | |
| Đóng gói | Docker Compose / Kubernetes (server, connector); MSI (agent Windows); deb/rpm (agent Linux) | |

### 8.1 Cấu trúc mã nguồn dự kiến

```
cmd/
  rh-server/ rh-responder/ rh-scanner/ rh-simulator/
  rh-agent-win/ rh-agent-linux/
  rh-conn-ontap/ rh-conn-dell/ rh-conn-syslog/ rh-conn-zfs/
internal/
  event/          # FileEvent, chuẩn hóa, phân tích đuôi, suffix template
  connector/      # interface Connector + ResponseProvider
  platform/
    windows/ linux/ ontap/ powerscale/ unity/ synology/ qnap/ truenas/ generic/
  scanner/        # Tầng C
  canary/
  detect/         # cửa sổ trượt, luật, điểm, baseline
  incident/
  response/       # kế hoạch phản ứng, phê duyệt, RBAC, audit
  notify/
  api/
web/
docs/
```

---

## 9. Đánh giá khả thi

### 9.1 Kết luận

**Khả thi — nên triển khai.** Với quyết định "connector riêng từng nền tảng" + "> 100M file", khả thi của từng hệ thống phụ thuộc chủ yếu vào việc nền tảng đó có nguồn sự kiện hoặc snapshot diff hay không (ma trận §4.0). Rủi ro lớn nhất **không nằm ở kỹ thuật** mà ở **việc có thiết bị lab thật** của từng hãng để phát triển và kiểm thử connector.

### 9.2 Đánh giá theo tiêu chí

| Tiêu chí | Mức | Nhận xét |
|----------|-----|----------|
| Thu thập metadata không đọc file | **Cao** | Mọi cơ chế dùng đều là API/tính năng chính thức của OS/hãng |
| Phát hiện đổi đuôi hàng loạt | **Cao** | Phần lớn họ ransomware phổ biến nối/đổi đuôi và để lại ransom note |
| Phát hiện đuôi chưa biết | **Cao** | R2/R2b/R3 không cần danh sách đen |
| Chịu tải > 100M file | **Cao** với Tầng A/B · **Trung bình** nếu chỉ Tầng C (chu kỳ 8–10 phút) | |
| Phản ứng có phê duyệt | **Cao** | Khóa tài khoản AD + snapshot áp dụng cho mọi nền tảng; đóng phiên tùy hãng |
| Giám sát SAN | **Cao** qua agent Windows/Linux trên host mount LUN | Không giám sát được ở tầng block |
| Báo động giả | **Trung bình → Tốt** | Cần baseline 7–14 ngày + allowlist |
| Chi phí phát triển connector | **Trung bình** | 9 nền tảng × 2–4 tuần/nền tảng, cần lab |

### 9.3 Giới hạn không vượt qua được (do ràng buộc "không đọc file")

1. **Mã hóa tại chỗ không đổi tên/đuôi**: chỉ giảm thiểu bằng R8 (cần connector có MODIFY), canary, ransom note.
2. **Ransomware chạy trên hypervisor/host mã hóa file ảo hóa**: chỉ thấy `.vmdk`/`.vhdx` đổi đuôi (nếu có), không thấy file bên trong VM.
3. **Ransomware trên chính host chạy agent** có thể tắt agent → giảm thiểu bằng cảnh báo im lặng + Tầng C độc lập.
4. Hệ thống **phát hiện và hỗ trợ phản ứng**, không thay thế backup/snapshot bất biến.

### 9.4 So sánh với giải pháp sẵn có

| Giải pháp | Hạn chế | Khác biệt của RansomwareHunter |
|-----------|---------|-------------------------------|
| Windows FSRM File Screen | Chỉ Windows, dựa danh sách đuôi đã biết | Đa nền tảng, phát hiện đuôi chưa biết |
| NetApp ARP | Chỉ ONTAP, có phân tích entropy nội dung | Trung lập hãng, chỉ metadata; dùng ARP làm tín hiệu bổ sung |
| Varonis, Superna Ransomware Defender… | Chi phí bản quyền cao, triển khai nặng | Tự chủ, nhẹ, cảnh báo rõ danh sách file, phản ứng có phê duyệt |

### 9.5 Rủi ro & biện pháp

| Rủi ro | Xác suất | Ảnh hưởng | Biện pháp |
|--------|----------|-----------|-----------|
| Không có thiết bị lab cho từng hãng | **Cao** | Không kiểm thử được connector | Ưu tiên nền tảng đang có; dùng bản ảo hóa của hãng nếu có (ONTAP Select/simulator, OneFS simulator); TrueNAS/Windows/Linux dựng VM |
| Firmware/license không hỗ trợ nguồn sự kiện | TB | Phải dùng Tầng C, độ trễ cao | Kiểm tra từng hệ thống thực tế ở PoC; khuyến nghị bật snapshot định kỳ |
| Bật audit/FPolicy gây tải NAS | TB | Ảnh hưởng người dùng | Async non-mandatory, lọc sự kiện tại nguồn, đo ở PoC |
| Phản ứng nhầm (khóa nhầm tài khoản) | Thấp | Gián đoạn công việc | Bắt buộc phê duyệt, 2 người cho tài khoản bảo vệ, nút hoàn tác |
| Lộ credential của responder | Thấp | Kẻ tấn công lạm dụng | Cô lập responder, quyền tối thiểu, lệnh có chữ ký, audit |
| Báo động giả giai đoạn đầu | Cao | "Nhờn" cảnh báo | Chế độ quan sát 7–14 ngày, allowlist |

---

## 10. Kế hoạch triển khai (nhóm 3 kỹ sư)

| Giai đoạn | Thời lượng | Nội dung | Tiêu chí hoàn thành |
|-----------|-----------|----------|---------------------|
| **0. PoC** | 3 tuần | Lõi engine (R1–R5, R7), `rh-scanner` + canary, `rh-agent-win` (USN), 1 connector NAS ưu tiên, `rh-simulator`, cảnh báo email/Telegram | Phát hiện mô phỏng 1.000 rename/phút ≤ 30 s (USN) và ≤ 3 phút (Tầng C, share 10M file); đo tải gây ra trên NAS |
| **1. MVP** | 8–10 tuần | Connector Linux, ONTAP, TrueNAS/ZFS; Web UI; incident store; **responder** (snapshot, khóa AD, đóng phiên SMB) + phê duyệt/RBAC/audit; baseline, allowlist; syslog CEF | Phát hiện ≤ 30 s với Tầng A; FP ≤ 1/tuần/share sau baseline; diễn tập phản ứng thành công |
| **2. Mở rộng** | 8–10 tuần | Connector Dell (PowerScale, Unity/PowerStore), Synology, QNAP, generic syslog; HA multi-node; ClickHouse; kiểm thử tải 500M file | Chạy ổn định 500M file/hệ thống; đầy đủ ma trận §4.0 |

Tổng: ~5 tháng. Thứ tự connector ở giai đoạn 1–2 sẽ điều chỉnh theo hệ thống thực tế đang có (Q8).

---

## 11. Quyết định đã chốt (Q5–Q9)

| # | Câu hỏi | Quyết định |
|---|---------|-----------|
| Q5 | Kênh cảnh báo chính | Email + Telegram + Syslog CEF |
| Q6 | Stack | Go + PostgreSQL + NATS + ClickHouse |
| Q7 | Canary file trên share production | Được phép |
| Q8 | Nền tảng làm PoC | Windows File Server + 1 NAS đang chạy (qua connector generic Tầng C cho tới khi xác định hãng) |
| Q9 | Xác thực Web UI & người phê duyệt | AD/LDAP, nhóm AD `RH-Responders`, `RH-Admins` |

## 12. Phạm vi PoC (giai đoạn 0) — đơn giản hóa có chủ đích

PoC kiểm chứng thuật toán phát hiện và hiệu năng thu thập, nên tạm thay một số hạ tầng của bản đầy đủ:

| Bản đầy đủ | PoC | Lý do |
|------------|-----|-------|
| NATS JetStream | Channel trong tiến trình + HTTP ingest cho agent | Một tiến trình `rh-server` là đủ để đo |
| Pebble | Trạng thái scanner trong bộ nhớ (interface `Store`, thay Pebble ở MVP) | Share PoC ~10M file vừa RAM |
| PostgreSQL / ClickHouse | Incident ghi file JSON Lines + CSV danh sách file | Không cần DB để kiểm chứng phát hiện |
| Web UI, responder | Chưa có (MVP) | Cảnh báo qua console, email, Telegram, syslog CEF, webhook |
| Connector theo hãng NAS | Generic Tầng C (SMB/NFS) + canary + **syslog Synology/QNAP** (`internal/syslogconn`) | PoC chạy trên Synology/QNAP (chốt 2026-10-30); FPolicy/CEE/ZFS diff để MVP |
