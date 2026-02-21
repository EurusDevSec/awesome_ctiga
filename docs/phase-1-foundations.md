# 📘 Giai đoạn 1: Nắm vững Nền tảng Lý thuyết & Frameworks

> **Chứng chỉ:** Certified Threat Intelligence & Governance Analyst (CTIGA)
> **Mục tiêu:** Hiểu sâu cấu trúc dữ liệu, quy trình phân tích sự cố, và các framework cốt lõi — KHÔNG phải học thuộc lòng công cụ.
> **Thời gian khuyến nghị:** 2–3 tuần tập trung

---

## 📑 Mục lục

1. [Vòng đời Tình báo Mạng (CTI Lifecycle)](#1-vòng-đời-tình-báo-mạng-cti-lifecycle)
2. [Diamond Model of Intrusion Analysis](#2-diamond-model-of-intrusion-analysis)
3. [Cyber Kill Chain (Lockheed Martin)](#3-cyber-kill-chain-lockheed-martin)
4. [MITRE ATT&CK Framework](#4-mitre-attck-framework)
5. [Tích hợp 3 Framework: Diamond + Kill Chain + ATT&CK](#5-tích-hợp-3-framework-diamond--kill-chain--attck)
6. [Tiêu chuẩn Chia sẻ: STIX/TAXII](#6-tiêu-chuẩn-chia-sẻ-stixtaxii)
7. [Traffic Light Protocol (TLP)](#7-traffic-light-protocol-tlp)
8. [Best Practices & Mẹo thi CTIGA cho Giai đoạn 1](#8-best-practices--mẹo-thi-ctiga-cho-giai-đoạn-1)
9. [Câu hỏi Tự đánh giá (Self-Assessment)](#9-câu-hỏi-tự-đánh-giá-self-assessment)
10. [Tài liệu Tham khảo Cốt lõi](#10-tài-liệu-tham-khảo-cốt-lõi)

---

## 1. Vòng đời Tình báo Mạng (CTI Lifecycle)

### 1.1 Tổng quan

Vòng đời CTI là **xương sống** của mọi chương trình Threat Intelligence. Nó gồm **6 bước tuần hoàn**, mỗi bước có đầu vào/đầu ra rõ ràng. Bài thi CTIGA sẽ yêu cầu bạn xác định đúng bước trong một tình huống cụ thể.

```
┌─────────────┐
│  1. Direction │ ◄── Nhận yêu cầu từ stakeholder
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ 2. Collection │ ◄── Thu thập dữ liệu thô
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ 3. Processing │ ◄── Làm sạch, chuẩn hóa dữ liệu
└──────┬───────┘
       │
       ▼
┌─────────────┐
│ 4. Analysis  │ ◄── Phân tích → tạo Intelligence
└──────┬──────┘
       │
       ▼
┌────────────────────┐
│ 5. Dissemination   │ ◄── Phân phối → đúng người, đúng format
└──────┬─────────────┘
       │
       ▼
┌─────────────┐
│ 6. Feedback  │ ◄── Phản hồi → điều chỉnh vòng tiếp theo
└──────┬──────┘
       │
       └──────► Quay lại bước 1 (Direction)
```

### 1.2 Chi tiết từng bước

#### 🔹 Bước 1: Direction (Định hướng)

| Tiêu chí | Nội dung |
|---|---|
| **Mục đích** | Xác định **nhu cầu tình báo** (Intelligence Requirements) từ stakeholder |
| **Đầu vào** | Rủi ro kinh doanh, yêu cầu từ CISO/Board, sự cố gần đây |
| **Đầu ra** | PIRs (Priority Intelligence Requirements), SIRs (Specific Intelligence Requirements) |
| **Vai trò CTI Analyst** | Tham gia xây dựng SIRs kỹ thuật, đề xuất nguồn thu thập |
| **Vai trò CTI Manager** | Làm việc với leadership để xác định PIRs, phân bổ nguồn lực |

**🏆 Best Practice:**
- PIRs phải xuất phát từ **rủi ro kinh doanh thực tế** (business risk), không phải từ công nghệ
- Mỗi PIR cần có **tiêu chí đo lường** rõ ràng (measurable criteria)
- Xem xét lại PIRs **ít nhất mỗi quý** hoặc sau mỗi sự cố lớn

**📝 Ví dụ PIR:**
> *"Những nhóm APT nào đang nhắm mục tiêu vào ngành tài chính tại Đông Nam Á trong 6 tháng qua, và TTPs chính của họ là gì?"*

**📝 Ví dụ SIR (phân rã từ PIR trên):**
> - *"Danh sách IoCs (IP, domain, hash) liên quan đến APT41 trong Q3/2025"*
> - *"Kỹ thuật lateral movement phổ biến nhất trong các chiến dịch nhắm đến Financial Services"*

---

#### 🔹 Bước 2: Collection (Thu thập)

| Tiêu chí | Nội dung |
|---|---|
| **Mục đích** | Thu thập **dữ liệu thô** (raw data) từ nhiều nguồn khác nhau |
| **Đầu vào** | PIRs/SIRs đã xác định, kế hoạch thu thập (Collection Plan) |
| **Đầu ra** | Dữ liệu thô chưa qua xử lý |
| **Vai trò CTI Analyst** | Thực hiện thu thập OSINT, quản lý feed, query dark web |
| **Vai trò CTI Manager** | Phê duyệt ngân sách mua feed, đảm bảo tuân thủ pháp luật |

**Các nguồn thu thập chính:**

| Loại nguồn | Ví dụ | Ghi chú |
|---|---|---|
| **OSINT** (Open Source) | Blog bảo mật, Twitter/X, VirusTotal, Shodan | Miễn phí, dễ tiếp cận |
| **HUMINT** (Human) | Liên hệ ISAC/ISAO, mạng lưới cá nhân | Giá trị cao nhưng khó scale |
| **SIGINT** (Signals) | Honeypots, IDS/IPS logs, network traffic | Dữ liệu nội bộ |
| **Commercial Feeds** | Recorded Future, Mandiant, CrowdStrike | Tốn chi phí nhưng chất lượng cao |
| **Dark Web** | Forum ngầm, marketplace | Cần cẩn trọng về pháp lý |

**🏆 Best Practice:**
- Luôn có **Collection Plan** rõ ràng trước khi thu thập
- Ghi nhận **nguồn gốc** (provenance) và **độ tin cậy** (confidence) của mỗi nguồn
- Thu thập phải **tuân thủ pháp luật** — không xâm nhập hệ thống để lấy dữ liệu

---

#### 🔹 Bước 3: Processing (Xử lý)

| Tiêu chí | Nội dung |
|---|---|
| **Mục đích** | Chuyển dữ liệu thô → **thông tin có cấu trúc** (structured information) |
| **Đầu vào** | Dữ liệu thô từ bước Collection |
| **Đầu ra** | Dữ liệu đã chuẩn hóa, được phân loại và loại bỏ nhiễu |
| **Vai trò CTI Analyst** | Chuẩn hóa format (STIX), loại bỏ trùng lặp, enrichment |
| **Vai trò CTI Manager** | Thiết lập quy trình xử lý, đảm bảo chất lượng |

**Các hoạt động chính:**
- **Normalization:** Chuẩn hóa format dữ liệu (ví dụ: chuyển IP từ nhiều nguồn về cùng format)
- **Deduplication:** Loại bỏ dữ liệu trùng lặp
- **Enrichment:** Bổ sung ngữ cảnh (ví dụ: tra GeoIP, WHOIS cho một IP đáng ngờ)
- **Correlation:** Liên kết dữ liệu từ nhiều nguồn khác nhau
- **Filtering:** Loại bỏ dữ liệu không liên quan (noise)

**🏆 Best Practice:**
- Tự động hóa xử lý bằng SOAR/TIP platform khi có thể
- Áp dụng **confidence scoring** cho mỗi dữ liệu
- Lưu trữ dữ liệu thô song song với dữ liệu đã xử lý để audit

---

#### 🔹 Bước 4: Analysis (Phân tích)

| Tiêu chí | Nội dung |
|---|---|
| **Mục đích** | Biến thông tin → **tình báo có thể hành động** (actionable intelligence) |
| **Đầu vào** | Dữ liệu đã xử lý từ bước Processing |
| **Đầu ra** | Threat Intelligence sản phẩm (reports, briefings, IoC packages) |
| **Vai trò CTI Analyst** | Áp dụng framework phân tích, viết báo cáo kỹ thuật |
| **Vai trò CTI Manager** | Review chất lượng, đảm bảo đáp ứng PIRs |

**⚠️ TRỌNG TÂM THI: Phân biệt 3 cấp độ Intelligence**

| Cấp độ | Đối tượng | Nội dung | Thời hạn |
|---|---|---|---|
| **Strategic** | CEO, CISO, Board | Xu hướng, rủi ro tài chính, động cơ geopolitical | Dài hạn (6–12 tháng) |
| **Operational** | SOC Manager, IR Team | TTPs, chiến dịch, nhóm đe dọa cụ thể | Trung hạn (tuần–tháng) |
| **Tactical** | SOC Analyst, SIEM | IoCs: IP, domain, hash, email | Ngắn hạn (giờ–ngày) |

**Các kỹ thuật phân tích quan trọng:**
- **Analysis of Competing Hypotheses (ACH):** Đánh giá nhiều giả thuyết, loại bỏ dần
- **Structured Analytic Techniques (SATs):** Brainstorming, Devil's Advocacy, Red Team
- **Diamond Model Analysis:** Phân tích mối liên hệ 4 yếu tố (xem [mục 2](#2-diamond-model-of-intrusion-analysis))
- **Kill Chain Mapping:** Ánh xạ hoạt động vào các phase (xem [mục 3](#3-cyber-kill-chain-lockheed-martin))

**🏆 Best Practice:**
- Luôn trả lời câu hỏi **"So What?"** — Intelligence phải dẫn đến hành động cụ thể
- Phân biệt rõ giữa **fact** (sự kiện) và **assessment** (đánh giá/nhận định)
- Ghi rõ **mức độ tin cậy** (confidence level) cho mỗi nhận định: Low / Medium / High

---

#### 🔹 Bước 5: Dissemination (Phân phối)

| Tiêu chí | Nội dung |
|---|---|
| **Mục đích** | Phân phối intelligence đến **đúng người, đúng format, đúng thời điểm** |
| **Đầu vào** | Intelligence sản phẩm đã hoàn thiện |
| **Đầu ra** | Báo cáo/briefing đã gửi, IoCs đã push vào hệ thống |
| **Vai trò CTI Analyst** | Viết báo cáo kỹ thuật, push IoCs vào SIEM/TIP |
| **Vai trò CTI Manager** | Trình bày strategic briefing cho leadership |

**Format phân phối theo đối tượng:**

| Đối tượng | Format phù hợp | Ví dụ |
|---|---|---|
| Board/CEO | Executive Summary (1–2 trang) | PDF/Slide deck |
| SOC Manager | Operational Report | Wiki/Confluence |
| SOC Analyst | Tactical Alert + IoC Feed | STIX/JSON → SIEM |
| Bên ngoài (ISAC) | Threat Advisory | TLP-tagged report |

**🏆 Best Practice:**
- Áp dụng **TLP** (xem [mục 7](#7-traffic-light-protocol-tlp)) cho MỌI sản phẩm intelligence
- Tailor format theo **audience** — CEO không cần xem hash MD5
- **Timeliness** là yếu tố sống còn — intelligence trễ = intelligence vô giá trị

---

#### 🔹 Bước 6: Feedback (Phản hồi)

| Tiêu chí | Nội dung |
|---|---|
| **Mục đích** | Thu thập phản hồi → cải thiện chất lượng vòng tiếp theo |
| **Đầu vào** | Phản hồi từ stakeholder, metrics đo lường |
| **Đầu ra** | Điều chỉnh PIRs, nguồn thu thập, quy trình phân tích |
| **Vai trò CTI Analyst** | Ghi nhận feedback kỹ thuật từ SOC |
| **Vai trò CTI Manager** | Tổ chức review meeting, điều chỉnh chiến lược |

**Các metrics đo lường hiệu quả CTI:**
- **Time to Detect (TTD):** Thời gian từ lúc mối đe dọa xuất hiện → phát hiện
- **Time to Respond (TTR):** Thời gian từ phát hiện → phản ứng
- **Intel Utilization Rate:** Tỷ lệ intelligence được SOC thực sự sử dụng
- **False Positive Rate:** Tỷ lệ cảnh báo sai từ IoC feeds
- **PIR Coverage:** Tỷ lệ PIRs được trả lời đầy đủ

**🏆 Best Practice:**
- Feedback phải là **2 chiều**: CTI team → stakeholder VÀ stakeholder → CTI team
- Tổ chức **After Action Review (AAR)** sau mỗi sự cố lớn
- Sử dụng feedback để liên tục **tinh chỉnh Collection Plan**

---

## 2. Diamond Model of Intrusion Analysis

### 2.1 Tổng quan

Diamond Model là framework phân tích **sự kiện xâm nhập (intrusion event)** bằng cách liên kết 4 yếu tố cốt lõi. Nó giúp analyst hiểu **bức tranh toàn cảnh** của một cuộc tấn công thay vì chỉ nhìn vào từng IoC riêng lẻ.

### 2.2 Bốn yếu tố cốt lõi (Core Features)

```
                    ┌──────────────┐
                    │   ADVERSARY  │
                    │  (Kẻ tấn công)│
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
    ┌─────────▼────┐       │     ┌──────▼────────┐
    │  CAPABILITY  │◄──────┼────►│INFRASTRUCTURE │
    │ (Khả năng)   │       │     │ (Hạ tầng)     │
    └─────────┬────┘       │     └──────┬────────┘
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────▼───────┐
                    │    VICTIM    │
                    │ (Nạn nhân)   │
                    └──────────────┘
```

| Yếu tố | Mô tả | Ví dụ |
|---|---|---|
| **Adversary** | Kẻ tấn công hoặc nhóm đe dọa | APT28 (Fancy Bear), Lazarus Group |
| **Capability** | Công cụ, kỹ thuật, malware được sử dụng | Cobalt Strike, phishing kit, zero-day exploit |
| **Infrastructure** | Hạ tầng hỗ trợ tấn công | C2 server, domain phishing, VPN, bulletproof hosting |
| **Victim** | Mục tiêu bị tấn công | Công ty tài chính X, nhân viên phòng HR |

### 2.3 Meta-features (Đặc tính bổ sung)

Ngoài 4 yếu tố chính, Diamond Model còn có các **meta-features** quan trọng:

| Meta-feature | Mô tả | Tại sao quan trọng? |
|---|---|---|
| **Timestamp** | Thời điểm sự kiện xảy ra | Giúp xây dựng timeline |
| **Phase** | Giai đoạn trong Kill Chain | Liên kết với Cyber Kill Chain |
| **Result** | Kết quả: thành công/thất bại | Đánh giá mức độ nghiêm trọng |
| **Direction** | Hướng tấn công: Adversary→Victim | Xác định luồng tấn công |
| **Methodology** | Phương pháp luận (phishing, watering hole...) | Phân loại kiểu tấn công |
| **Resources** | Tài nguyên cần thiết (tiền, kiến thức, thời gian) | Đánh giá sophistication |

### 2.4 Activity Threads & Activity Groups

- **Activity Thread:** Chuỗi các sự kiện Diamond Model có liên kết theo thời gian → giúp theo dõi **một chiến dịch** cụ thể
- **Activity Group:** Tập hợp các Activity Thread có đặc điểm chung → giúp **gom nhóm** hoạt động và **attribution** cho một threat actor

### 2.5 Ví dụ thực chiến

> **Tình huống:** Phát hiện email phishing nhắm vào phòng Tài chính của công ty

| Yếu tố | Phân tích |
|---|---|
| **Adversary** | Chưa attribution, nghi ngờ nhóm tội phạm tài chính |
| **Capability** | Email phishing chứa macro VBA → tải Cobalt Strike beacon |
| **Infrastructure** | Domain giả mạo: `finance-update[.]com`, C2: `185.x.x.x` |
| **Victim** | Nhân viên kế toán công ty ABC |
| **Phase** | Delivery → Exploitation (Kill Chain) |
| **Methodology** | Spear-phishing with attachment |

**🏆 Best Practice cho Diamond Model:**
- Luôn cố gắng **điền đầy đủ** cả 4 yếu tố, kể cả khi chưa chắc chắn (ghi nhận confidence level)
- Sử dụng Diamond Model để **pivot** — từ 1 yếu tố đã biết, tìm kiếm các yếu tố khác
- Liên kết nhiều Diamond events để xây dựng **Activity Thread** → nhìn thấy Campaign

---

## 3. Cyber Kill Chain (Lockheed Martin)

### 3.1 Tổng quan

Cyber Kill Chain mô tả **7 giai đoạn** mà kẻ tấn công phải hoàn thành để đạt mục tiêu. Nếu defender **phá vỡ bất kỳ giai đoạn nào**, cuộc tấn công sẽ thất bại.

### 3.2 Bảy giai đoạn

```
  ┌─ 1. Reconnaissance ─── Thu thập thông tin mục tiêu
  │
  ├─ 2. Weaponization ──── Tạo payload/malware
  │
  ├─ 3. Delivery ────────── Gửi payload đến mục tiêu
  │
  ├─ 4. Exploitation ────── Khai thác lỗ hổng để thực thi
  │
  ├─ 5. Installation ────── Cài đặt backdoor/persistence
  │
  ├─ 6. Command & Control ─ Thiết lập kênh điều khiển
  │
  └─ 7. Actions on         Thực hiện mục tiêu cuối cùng
     Objectives           (đánh cắp dữ liệu, phá hoại...)
```

### 3.3 Chi tiết từng giai đoạn + Hành động phòng thủ

| # | Giai đoạn | Mô tả | Ví dụ hoạt động | Hành động phòng thủ |
|---|---|---|---|---|
| 1 | **Reconnaissance** | Thu thập thông tin công khai về mục tiêu | OSINT, scan port, social engineering | Web analytics, phát hiện scan, hạn chế thông tin công khai |
| 2 | **Weaponization** | Kết hợp exploit + payload thành weapon | Tạo macro document, build RAT | Không thể phòng thủ trực tiếp - tập trung vào giai đoạn khác |
| 3 | **Delivery** | Gửi weapon đến mục tiêu | Phishing email, watering hole, USB | Email security, web proxy, awareness training |
| 4 | **Exploitation** | Khai thác lỗ hổng | Buffer overflow, macro execution | Patch management, DEP, endpoint protection |
| 5 | **Installation** | Cài đặt persistence | Registry key, scheduled task, rootkit | HIPS, file integrity, behavioral analysis |
| 6 | **C2** | Thiết lập kênh điều khiển | DNS tunneling, HTTPS beaconing | Network monitoring, DNS analytics, proxy logs |
| 7 | **Actions on Obj.** | Thực hiện mục tiêu | Data exfiltration, ransomware, sabotage | DLP, network segmentation, backup |

### 3.4 Hạn chế của Kill Chain

> ⚠️ **Quan trọng cho bài thi:** Bạn cần biết cả **ưu và nhược điểm** của mỗi framework

| Hạn chế | Giải thích |
|---|---|
| **Tuyến tính quá mức** | Thực tế, cuộc tấn công không luôn đi theo thứ tự 1→7 |
| **Thiên về perimeter** | Tập trung vào giai đoạn xâm nhập ban đầu, ít chi tiết về post-exploitation |
| **Thiếu chi tiết nội bộ** | Không mô tả rõ lateral movement, privilege escalation bên trong mạng |
| **Insider threat** | Không phù hợp cho phân tích mối đe dọa từ nội bộ |

→ Đây là lý do cần **kết hợp** với MITRE ATT&CK (chi tiết ở [mục 5](#5-tích-hợp-3-framework-diamond--kill-chain--attck))

---

## 4. MITRE ATT&CK Framework

### 4.1 Tổng quan

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) là **knowledge base toàn cầu** về hành vi của kẻ tấn công. Nó bổ sung cho Kill Chain bằng cách cung cấp **chi tiết granular** về TTPs.

### 4.2 Cấu trúc ATT&CK

```
ATT&CK Matrix
├── Tactics (MỤC TIÊU chiến thuật - "Tại sao" kẻ tấn công làm điều đó)
│   ├── Technique 1 (CÁCH kẻ tấn công đạt mục tiêu)
│   │   ├── Sub-technique 1.1
│   │   └── Sub-technique 1.2
│   ├── Technique 2
│   └── ...
├── Tactic tiếp theo
└── ...
```

### 4.3 Danh sách 14 Tactics (Enterprise ATT&CK)

| # | Tactic ID | Tactic | Mô tả |
|---|---|---|---|
| 1 | TA0043 | **Reconnaissance** | Thu thập thông tin trước tấn công |
| 2 | TA0042 | **Resource Development** | Xây dựng hạ tầng tấn công |
| 3 | TA0001 | **Initial Access** | Xâm nhập ban đầu vào hệ thống |
| 4 | TA0002 | **Execution** | Thực thi mã độc |
| 5 | TA0003 | **Persistence** | Duy trì quyền truy cập |
| 6 | TA0004 | **Privilege Escalation** | Leo thang đặc quyền |
| 7 | TA0005 | **Defense Evasion** | Tránh bị phát hiện |
| 8 | TA0006 | **Credential Access** | Đánh cắp thông tin xác thực |
| 9 | TA0007 | **Discovery** | Thăm dò môi trường nội bộ |
| 10 | TA0008 | **Lateral Movement** | Di chuyển ngang trong mạng |
| 11 | TA0009 | **Collection** | Thu thập dữ liệu mục tiêu |
| 12 | TA0011 | **Command and Control** | Thiết lập kênh điều khiển |
| 13 | TA0010 | **Exfiltration** | Đánh cắp dữ liệu ra ngoài |
| 14 | TA0040 | **Impact** | Phá hoại, ransomware |

### 4.4 Ví dụ Technique & Sub-technique

**Tactic: Initial Access (TA0001)**

| Technique ID | Technique | Sub-techniques |
|---|---|---|
| T1566 | **Phishing** | `.001 Spearphishing Attachment` `.002 Spearphishing Link` `.003 Spearphishing via Service` |
| T1190 | **Exploit Public-Facing Application** | — |
| T1078 | **Valid Accounts** | `.001 Default Accounts` `.002 Domain Accounts` `.003 Local Accounts` `.004 Cloud Accounts` |

### 4.5 Ứng dụng ATT&CK trong CTI

| Use Case | Cách sử dụng |
|---|---|
| **Threat Profiling** | Map TTPs của một APT group → hiểu "style" của họ |
| **Detection Gap Analysis** | So sánh coverage hiện tại vs. techniques đã biết |
| **SOC Reporting** | Báo cáo sự cố bằng ngôn ngữ ATT&CK thống nhất |
| **Red Team / Purple Team** | Mô phỏng kỹ thuật cụ thể để test defense |
| **Intelligence Sharing** | Trao đổi thông tin bằng taxonomy chung |

### 4.6 ATT&CK Navigator

ATT&CK Navigator là công cụ trực quan hóa giúp:
- **Highlight** các techniques mà SOC đã có detection
- **So sánh** nhiều threat actors trên cùng một ma trận
- **Đánh giá coverage** — khoảng trống nào cần bổ sung

**🏆 Best Practice cho ATT&CK:**
- Không cố gắng cover **100%** ATT&CK — hãy ưu tiên techniques **relevant** với ngành của bạn
- Sử dụng ATT&CK để **communicate** với SOC, IR team bằng ngôn ngữ chung
- Kết hợp ATT&CK với **threat intelligence feeds** để biết techniques nào đang trending

---

## 5. Tích hợp 3 Framework: Diamond + Kill Chain + ATT&CK

### 5.1 Tại sao phải tích hợp?

Mỗi framework có **thế mạnh riêng**:

| Framework | Thế mạnh | Hạn chế |
|---|---|---|
| **Kill Chain** | Nhìn tổng thể luồng tấn công tuyến tính | Thiếu chi tiết post-exploitation |
| **Diamond Model** | Liên kết Adversary – Capability – Infrastructure – Victim | Không mô tả trình tự |
| **ATT&CK** | Chi tiết TTPs granular | Quá nhiều thông tin, khó nhìn bức tranh tổng thể |

### 5.2 Cách tích hợp thực tế

```
Kill Chain Phase    ──►  ATT&CK Tactic(s)    ──►  Diamond Model Event
─────────────────────────────────────────────────────────────────────
Reconnaissance      →   Reconnaissance         →   Adv discovers Victim info
Weaponization       →   Resource Development    →   Adv develops Capability  
Delivery            →   Initial Access          →   Capability → Infrastructure → Victim
Exploitation        →   Execution               →   Capability exploits Victim
Installation        →   Persistence             →   Capability installed at Victim
C2                  →   Command and Control      →   Adv ↔ Infrastructure ↔ Victim
Actions on Obj.     →   Collection, Exfil, Impact→  Adv achieves objective via Victim
```

### 5.3 Workflow phân tích tích hợp

```
1. Nhận IoC/Alert
       │
       ▼
2. Tạo Diamond Model Event
   (xác định 4 yếu tố + meta-features)
       │
       ▼
3. Map vào Kill Chain Phase
   (sự kiện này ở giai đoạn nào?)
       │
       ▼
4. Xác định ATT&CK Technique
   (kỹ thuật cụ thể nào được sử dụng?)
       │
       ▼
5. Pivot & Enrich
   (dùng Diamond Model để tìm thêm liên kết)
       │
       ▼
6. Tạo Intelligence Product
   (báo cáo với đầy đủ context)
```

**🏆 Best Practice:**
- Sử dụng Kill Chain cho **bức tranh tổng thể** khi brief leadership
- Sử dụng ATT&CK cho **chi tiết kỹ thuật** khi report cho SOC
- Sử dụng Diamond Model để **pivot và mở rộng** phân tích từ IOC ban đầu
- Ghi nhận **Phase meta-feature** trong Diamond Model = Kill Chain stage = ATT&CK Tactic

---

## 6. Tiêu chuẩn Chia sẻ: STIX/TAXII

### 6.1 STIX (Structured Threat Information eXpression)

#### STIX là gì?

STIX là **ngôn ngữ chuẩn** (standardized language) để mô tả thông tin về mối đe dọa mạng. Nó sử dụng format **JSON** để đảm bảo cả máy và người đều có thể đọc hiểu.

#### STIX 2.1 Domain Objects (SDOs)

| Object Type | Mô tả | Ví dụ |
|---|---|---|
| **Attack Pattern** | Kỹ thuật tấn công (thường map với ATT&CK) | Phishing, SQL Injection |
| **Campaign** | Tập hợp các hoạt động có chung mục tiêu | Operation Aurora |
| **Course of Action** | Hành động phòng thủ/khắc phục | Block IP range, patch CVE |
| **Grouping** | Nhóm logic các STIX objects | Tập hợp IoCs liên quan |
| **Identity** | Cá nhân/tổ chức | Công ty ABC, Sector Tài chính |
| **Indicator** | Pattern phát hiện mối đe dọa | `[file:hashes.MD5 = 'abc123']` |
| **Infrastructure** | Hạ tầng (tấn công hoặc phòng thủ) | C2 server, Botnet |
| **Intrusion Set** | Tập hợp hành vi tấn công gom nhóm | APT28 TTPs |
| **Location** | Vị trí địa lý | Đông Nam Á, Việt Nam |
| **Malware** | Phần mềm độc hại | Emotet, Cobalt Strike |
| **Malware Analysis** | Kết quả phân tích malware | Sandbox report |
| **Note** | Ghi chú bổ sung | Analyst assessment |
| **Observed Data** | Dữ liệu đã quan sát | Network traffic log entry |
| **Opinion** | Ý kiến về object khác | Agreement/Disagreement |
| **Report** | Tập hợp intelligence thành báo cáo | APT monthly report |
| **Threat Actor** | Tác nhân đe dọa | Lazarus Group |
| **Tool** | Công cụ (hợp pháp bị lạm dụng) | PsExec, Mimikatz |
| **Vulnerability** | Lỗ hổng | CVE-2024-XXXX |

#### STIX Relationship Objects (SROs)

Kết nối các SDOs:
- **Relationship:** Mối quan hệ giữa 2 objects (ví dụ: Threat Actor `uses` Malware)
- **Sighting:** Xác nhận đã nhìn thấy indicator/object trong thực tế

#### Ví dụ STIX JSON

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2025-12-01T00:00:00.000Z",
  "modified": "2025-12-01T00:00:00.000Z",
  "name": "Malicious domain - finance-update.com",
  "description": "Domain used for phishing campaign targeting financial sector",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'finance-update.com']",
  "pattern_type": "stix",
  "valid_from": "2025-11-15T00:00:00.000Z",
  "labels": ["phishing"],
  "confidence": 85
}
```

### 6.2 TAXII (Trusted Automated eXchange of Indicator Information)

#### TAXII là gì?

TAXII là **giao thức truyền tải** (transport protocol) để tự động chia sẻ dữ liệu STIX giữa các tổ chức.

#### Mô hình TAXII 2.1

| Thành phần | Mô tả |
|---|---|
| **API Root** | Điểm truy cập gốc cho TAXII service |
| **Collection** | Tập hợp STIX objects được chia sẻ (tương tự "folder") |
| **Channel** | Kênh publish/subscribe cho STIX objects |

#### Hai mô hình chia sẻ

```
┌──────────────────────────────────────────┐
│  1. Collection (Pull Model)              │
│                                          │
│  Consumer ───► TAXII Server              │
│              (Consumer chủ động request)  │
└──────────────────────────────────────────┘

┌──────────────────────────────────────────┐
│  2. Channel (Push Model)                 │
│                                          │
│  TAXII Server ───► Subscriber            │
│              (Server push khi có mới)    │
└──────────────────────────────────────────┘
```

### 6.3 Mối quan hệ STIX + TAXII

> **STIX = Ngôn ngữ** (Nói GÌ)
> **TAXII = Giao thức** (Nói NHƯ THẾ NÀO)

```
Tổ chức A                    Tổ chức B
┌──────┐    STIX data       ┌──────┐
│ TIP  │ ──── TAXII ────►  │ TIP  │
│      │    (truyền tải)    │      │
└──────┘                    └──────┘
```

**🏆 Best Practice cho STIX/TAXII:**
- Sử dụng **STIX 2.1** (phiên bản mới nhất) thay vì STIX 1.x
- Khi tạo STIX objects, luôn bao gồm **confidence score** và **TLP marking**
- Kết hợp STIX indicators với **ATT&CK references** để tăng ngữ cảnh
- Chọn Pull (Collection) hay Push (Channel) phụ thuộc vào **nhu cầu timeliness**

---

## 7. Traffic Light Protocol (TLP)

### 7.1 Tổng quan

TLP là hệ thống **phân loại mức độ chia sẻ** thông tin nhạy cảm. Được quản lý bởi **FIRST.org** và được sử dụng rộng rãi trong cộng đồng CTI.

### 7.2 Bốn nhãn TLP (TLP 2.0)

> ⚠️ **BẮT BUỘC THUỘC LÒNG** — Đây là một trong những chủ đề xuất hiện nhiều nhất trong bài thi CTIGA

| Nhãn | Màu | Phạm vi chia sẻ | Khi nào sử dụng? |
|---|---|---|---|
| 🔴 **TLP:RED** | Đỏ | **Chỉ** những người tham gia trực tiếp (named recipients only) | Thông tin cực kỳ nhạy cảm, rò rỉ gây tổn hại nghiêm trọng |
| 🟡 **TLP:AMBER** | Vàng | Tổ chức nhận + **clients/partners trên cơ sở need-to-know** | Cần chia sẻ hạn chế để hỗ trợ hành động |
| 🟡 **TLP:AMBER+STRICT** | Vàng | **Chỉ** tổ chức nhận (không share ra clients) | Như AMBER nhưng nghiêm ngặt hơn |
| 🟢 **TLP:GREEN** | Xanh lá | **Cộng đồng** (community) nhưng không công khai | Hữu ích cho cộng đồng nhưng không nên public |
| ⚪ **TLP:CLEAR** | Trắng | **Không giới hạn** — có thể public | Thông tin chung, không gây hại khi phát tán |

### 7.3 Sơ đồ quyết định chọn TLP

```
Thông tin này có thể công khai?
├── CÓ ──► TLP:CLEAR
└── KHÔNG
    │
    Chia sẻ cho cộng đồng rộng được không?
    ├── CÓ ──► TLP:GREEN
    └── KHÔNG
        │
        Cần chia sẻ cho clients/partners?
        ├── CÓ ──► TLP:AMBER
        ├── KHÔNG, chỉ trong nội bộ tổ chức ──► TLP:AMBER+STRICT
        └── Chỉ cho người được chỉ định ──► TLP:RED
```

### 7.4 Tình huống ứng dụng TLP (Exam-style)

| Tình huống | TLP phù hợp | Giải thích |
|---|---|---|
| Báo cáo APT chung cho ISAC | 🟢 **GREEN** | Hữu ích cho cộng đồng, không chứa IoC nhạy cảm |
| IoCs cụ thể từ sự cố nội bộ | 🟡 **AMBER** | Cần chia sẻ cho peers/partners để phòng thủ |
| Thông tin về kẻ tấn công đang nhắm mục tiêu CEO | 🔴 **RED** | Cực kỳ nhạy cảm, chỉ security team biết |
| CVE advisory công khai | ⚪ **CLEAR** | Thông tin đã public, không giới hạn |
| IoCs nội bộ chưa muốn share ra clients | 🟡 **AMBER+STRICT** | Giữ trong tổ chức, chưa chia sẻ bên ngoài |

### 7.5 Vi phạm TLP (TLP Breach)

> ⚠️ **Trọng tâm thi:** Bài thi CTIGA thường đưa ra tình huống **vi phạm TLP** và hỏi cách xử lý

**Quy trình xử lý vi phạm TLP:**

1. **Xác nhận** vi phạm và đánh giá phạm vi
2. **Thông báo** cho bên cung cấp thông tin gốc
3. **Đánh giá tác động** — thông tin bị rò rỉ gây hại gì?
4. **Khắc phục** — thu hồi/hạn chế phát tán thêm
5. **Xem xét lại** quy trình và đào tạo nhân viên
6. **Ghi nhận** bài học kinh nghiệm (lessons learned)

**🏆 Best Practice cho TLP:**
- **Mọi** sản phẩm intelligence phải có nhãn TLP rõ ràng
- Khi nghi ngờ, chọn TLP **cao hơn** (restrictive hơn) — better safe than sorry
- Không bao giờ **hạ cấp TLP** mà không có sự đồng ý của bên cung cấp gốc
- TLP áp dụng cho **toàn bộ nội dung** — không chỉ một phần

---

## 8. Best Practices & Mẹo thi CTIGA cho Giai đoạn 1

### 8.1 Tổng hợp Best Practices

| Chủ đề | Best Practice quan trọng nhất |
|---|---|
| **CTI Lifecycle** | PIRs xuất phát từ business risk, không phải technology |
| **Collection** | Luôn ghi nhận provenance + confidence của nguồn |
| **Analysis** | Phân biệt fact vs. assessment, ghi confidence level |
| **Dissemination** | Tailor format theo audience + đúng thời điểm |
| **Diamond Model** | Dùng để pivot — từ 1 yếu tố tìm các yếu tố khác |
| **Kill Chain** | Hiểu hạn chế (tuyến tính, thiên perimeter) |
| **ATT&CK** | Ưu tiên techniques relevant với ngành thay vì cover tất cả |
| **STIX/TAXII** | STIX = language, TAXII = transport, luôn kèm confidence + TLP |
| **TLP** | Khi nghi ngờ → chọn TLP cao hơn, không hạ cấp khi chưa được phép |

### 8.2 Mẹo thi cụ thể cho Giai đoạn 1

1. **Đọc câu hỏi cuối trước** — trong tình huống dài, biết câu hỏi trước sẽ giúp bạn biết cần tìm gì
2. **Tìm keyword framework** — nếu thấy từ "pivot", "liên kết adversary" → Diamond Model. Nếu thấy "giai đoạn tấn công" → Kill Chain. Nếu thấy "technique specific" → ATT&CK
3. **TLP là câu dễ ăn điểm** — thuộc bảng TLP là bạn có thể trả lời nhanh
4. **CTI Lifecycle** — khi không chắc chắn, quay lại câu hỏi *"Bước này nằm ở đâu trong lifecycle?"*
5. **Decision Support Mindset** — đáp án tốt nhất LUÔN hướng đến **giảm thiểu rủi ro kinh doanh**

### 8.3 Common Pitfalls (Lỗi thường gặp)

| ❌ Sai | ✅ Đúng |
|---|---|
| Nhầm lẫn Processing với Analysis | Processing = chuẩn hóa dữ liệu, Analysis = tạo intelligence |
| Nghĩ Kill Chain là toàn diện | Kill Chain cần bổ sung bằng ATT&CK cho chi tiết nội bộ |
| Dùng TLP:RED cho mọi thứ nhạy cảm | Chỉ dùng RED khi thực sự cần giới hạn recipients cụ thể |
| Quên feedback loop trong lifecycle | Feedback là bước **BẮT BUỘC** — CTI là vòng tuần hoàn |
| STIX = giao thức truyền tải | STIX = ngôn ngữ/format, TAXII = giao thức truyền tải |
| Attribution chắc chắn khi chưa đủ evidence | Luôn ghi confidence level cho attribution |

---

## 9. Câu hỏi Tự đánh giá (Self-Assessment)

### 📋 Kiểm tra nhanh (Quick Check)

Trả lời các câu hỏi sau mà KHÔNG nhìn tài liệu. Nếu không trả lời được ≥ 80%, hãy ôn lại phần tương ứng.

#### Phần A: CTI Lifecycle

1. Liệt kê 6 bước trong CTI Lifecycle theo đúng thứ tự.
2. PIRs viết tắt của gì? PIRs nên xuất phát từ đâu?
3. Sự khác biệt giữa Processing và Analysis là gì?
4. Kể 3 metrics đo lường hiệu quả CTI program.
5. Vai trò CTI Manager và CTI Analyst khác nhau như thế nào trong bước Dissemination?

#### Phần B: Frameworks

6. Kể tên 4 yếu tố cốt lõi của Diamond Model.
7. Activity Thread khác Activity Group như thế nào?
8. Liệt kê 7 giai đoạn Cyber Kill Chain theo thứ tự.
9. Kill Chain có hạn chế gì? Cần framework nào bổ sung?
10. ATT&CK có bao nhiêu Tactics (Enterprise)? Kể ít nhất 7 tactic.
11. Phân biệt Tactic vs. Technique vs. Procedure trong ATT&CK.

#### Phần C: Tiêu chuẩn chia sẻ

12. STIX là gì? TAXII là gì? Mối quan hệ giữa chúng?
13. Kể 5 STIX Domain Objects (SDOs).
14. Hai mô hình chia sẻ TAXII là gì?
15. Liệt kê 5 nhãn TLP và phạm vi chia sẻ tương ứng.
16. Khi nhận thông tin TLP:AMBER, bạn có thể chia sẻ với ai?
17. Nếu phát hiện vi phạm TLP, quy trình xử lý gồm mấy bước?

#### Phần D: Tình huống (Scenario-based)

18. *Bạn phát hiện một domain phishing mới `banklogin-secure[.]com` nhắm vào khách hàng. Hãy tạo Diamond Model event cho sự kiện này.*

19. *SOC report cho thấy kẻ tấn công đã: (a) gửi email chứa macro độc hại, (b) chạy PowerShell download Cobalt Strike, (c) tạo scheduled task để persistence, (d) sử dụng DNS tunneling để exfiltrate dữ liệu. Map từng hoạt động vào Kill Chain phase VÀ ATT&CK tactic.*

20. *Bạn nhận một báo cáo từ ISAC đánh dấu TLP:AMBER về một chiến dịch ransomware mới. Đồng nghiệp ở công ty partner hỏi bạn chia sẻ. Bạn xử lý thế nào?*

---

## 10. Tài liệu Tham khảo Cốt lõi

### 📚 Đọc bắt buộc

| # | Tài liệu | Nguồn | Mức ưu tiên |
|---|---|---|---|
| 1 | **CTI Lifecycle** — SANS CTI Reading List & Whitepapers | [SANS.org](https://www.sans.org) | 🔴 Cao |
| 2 | **Diamond Model of Intrusion Analysis** — Caltagirone, Pendergast, Betz (2013) | Whitepaper gốc | 🔴 Cao |
| 3 | **MITRE ATT&CK** — Enterprise Matrix | [attack.mitre.org](https://attack.mitre.org) | 🔴 Cao |
| 4 | **Cyber Kill Chain** — Lockheed Martin | [lockheedmartin.com](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) | 🟡 Trung bình |
| 5 | **STIX/TAXII Documentation** — OASIS Open | [oasis-open.github.io/cti-documentation](https://oasis-open.github.io/cti-documentation/) | 🟡 Trung bình |
| 6 | **TLP 2.0** — FIRST.org | [first.org/tlp](https://www.first.org/tlp/) | 🔴 Cao |
| 7 | **A Practitioner's Guide to Developing Intelligence Requirements** | Recorded Future | 🟡 Trung bình |
| 8 | **CREST Cyber Threat Intelligence Maturity Model** | CREST | 🟡 Trung bình |

### 🔗 Tham khảo bổ sung

- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence) — Kho tổng hợp tài nguyên CTI
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — Trực quan hóa ATT&CK matrix
- [STIX Visualizer](https://oasis-open.github.io/cti-stix-visualization/) — Trực quan hóa STIX objects

---

> 📌 **Ghi nhớ:** Giai đoạn 1 là **nền móng**. Nếu bạn hiểu vững CTI Lifecycle + 3 Framework + STIX/TAXII + TLP, bạn đã sẵn sàng 40–50% cho bài thi CTIGA.
>
> **Bước tiếp theo:** Chuyển sang [Giai đoạn 2: Quản trị, Đạo đức & Chiến lược](./phase-2-governance.md) để hoàn thiện kiến thức.

---

*Cập nhật lần cuối: 2026-02-21*
*Phiên bản: 1.0*
