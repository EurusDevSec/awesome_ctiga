**Kế hoạch Ôn tập Toàn diện (Master Study Plan)** cho chứng chỉ CTIGA, được tổng hợp từ lý thuyết chuẩn đến kỹ năng thực chiến, thiết kế đặc biệt để đối phó với bài thi dài 5 tiếng dạng tình huống (Scenario-based).

Kế hoạch này chia làm 4 giai đoạn cốt lõi:

---

### Giai đoạn 1: Nắm vững Nền tảng Lý thuyết & Frameworks (Tối ưu hóa kho GitHub)

Mục tiêu ở đây không phải là học thuộc lòng công cụ, mà là hiểu cách cấu trúc dữ liệu và phân tích sự cố.

* **Vòng đời Tình báo (CTI Lifecycle):** Nắm chắc 6 bước (Direction -> Collection -> Processing -> Analysis -> Dissemination -> Feedback). Bạn cần biết ở mỗi bước, vai trò của CTI Analyst và CTI Manager là gì.
* **Các Framework Phân tích:** * **Diamond Model:** Cách liên kết 4 yếu tố (Adversary, Capability, Infrastructure, Victim).

```
* **MITRE ATT&CK & Cyber Kill Chain:** Hiểu cách ánh xạ (mapping) các kỹ thuật của kẻ tấn công vào framework để báo cáo cho SOC.

```

* **Tiêu chuẩn Chia sẻ & Phân phối:** * **STIX/TAXII:** Cấu trúc dữ liệu và cách truyền tải.
* **TLP (Traffic Light Protocol):** Bắt buộc phải thuộc lòng quy tắc chia sẻ thông tin theo các nhãn (RED, AMBER, GREEN, CLEAR) để xử lý các tình huống vi phạm chính sách.



### Giai đoạn 2: Quản trị, Đạo đức & Chiến lược (Governance & Strategy)

Đây là phần tạo nên chữ "G" (Governance) trong CTIGA. Bạn phải tư duy như một nhà quản lý rủi ro.

* **Thiết lập Yêu cầu (PIRs/SIRs):** Học cách viết Yêu cầu Tình báo Ưu tiên (PIRs) xuất phát từ rủi ro kinh doanh (Business Risks), sau đó phân rã xuống các yêu cầu kỹ thuật (SIRs).
* **Đo lường Mức độ Trưởng thành (Maturity):** Đọc kỹ tài liệu **CREST Cyber Threat Intelligence Maturity Model**. Bạn cần biết cách đánh giá xem một tổ chức đang ở level nào và cần đầu tư gì để nâng cấp năng lực CTI.
* **Đạo đức & Tuân thủ (Ethics & Legal):** Nắm các nguyên tắc thu thập OSINT hợp pháp, tránh xâm phạm quyền riêng tư (GDPR) và quy trình xử lý dữ liệu nhạy cảm.

### Giai đoạn 3: Thực hành Quy trình & "Dịch ngược" Báo cáo (Process Hands-on)

Không có bài lab kỹ thuật, nhưng bạn phải "thực hành tư duy" bằng cách làm việc với các báo cáo tình báo thực tế (Threat Intel Reports).

* **Đọc báo cáo APT thực tế:** Tải các báo cáo từ Mandiant, CrowdStrike hoặc Red Canary.
* **Thực hành Phân luồng:** Lấy bút highlight rạch ròi: Đoạn nào trong báo cáo là **Strategic** (dành cho CEO/CISO, nói về rủi ro tài chính, động cơ), đoạn nào là **Operational** (TTPs của kẻ tấn công), đoạn nào là **Tactical** (IoCs: IP, Hash).
* **Mapping thực chiến:** Tự vẽ lại Diamond Model cho chiến dịch được nêu trong báo cáo. Nếu bạn vẽ được sự liên kết, bạn đã sẵn sàng cho bài thi.

### Giai đoạn 4: Chiến thuật Phòng thi (5 Tiếng Sinh Tồn)

Bài thi 5 tiếng với các câu hỏi tình huống dài sẽ làm bạn cạn kiệt thể lực và sự tỉnh táo.

* **Tư duy "Hỗ trợ Quyết định" (Decision Support):** Khi đối mặt với 4 đáp án có vẻ đều đúng, hãy chọn đáp án trả lời được câu hỏi: *"Hành động nào giúp tổ chức giảm thiểu rủi ro kinh doanh và hỗ trợ Ban Giám đốc ra quyết định tốt nhất?"*.
* **Đừng sa đà vào kỹ thuật:** Nếu câu hỏi hỏi về cách xử lý một luồng tình báo bị rò rỉ, hãy tìm đáp án liên quan đến "Quy trình/Chính sách/TLP" thay vì "Chạy script để xóa file".
* **Quản lý thời gian:** Đọc câu hỏi cuối cùng của đoạn tình huống trước, sau đó mới quay lại đọc toàn bộ ngữ cảnh. Việc này giúp bạn biết mình cần tìm dữ kiện gì trong một đoạn văn dài.

---

**Tài liệu Cốt lõi cần tập trung (Thay vì đọc cả kho GitHub):**

1. SANS CTI Reading List & Whitepapers.
2. *A Practitioner's Guide to Developing Intelligence Requirements* (Recorded Future).
3. Tài liệu thiết kế của MITRE ATT&CK và CREST Maturity Model.

---

** Reference **

https://github.com/hslatman/awesome-threat-intelligence?tab=readme-ov-file

