# นโยบายและสถาปัตยกรรมความปลอดภัย (`docs/SECURITY.md`)

## 1. มาตรการความปลอดภัยหลัก (Core Security Controls)

1. **SQL Injection Prevention:**
   - ชั้นฐานข้อมูล `sentinel_x/core/database.py` ใช้ Parameterized Queries (`?`) 100% ทุกคำสั่ง SQL
2. **Path Traversal & File Handling Protection:**
   - `LogIngestionService.ingest_file` ปฏิเสธไฟล์ที่เป็น Symlink, ตรวจสอบ Canonical Path (`Path.resolve().relative_to(...)`) และจำกัดขนาดไฟล์สูงสุดตาม `SENTINEL_MAX_INGEST_FILE_BYTES`
3. **Output Encoding (XSS Prevention):**
   - ทั้ง `DashboardService.render_dashboard_html` และ `IncidentReportExporter.export_html` ใช้ `html.escape()` กับข้อมูลทุกฟิลด์ก่อนแสดงผล
4. **Log Injection Prevention:**
   - `AuditLogger` ทำความสะอาดอักขระควบคุม (`\r`, `\n`) ทุกฟิลด์ก่อนบันทึกลงไฟล์ JSONL
5. **Secret Masking & Honest Connector Status:**
   - `SentinelConfig` ปิดบังค่า Secret ใน `repr()` และ `to_safe_dict()`
   - External Connectors จะแสดงสถานะ `NOT_CONFIGURED` อย่างตรงไปตรงมาหากยังไม่ได้ตั้งค่า Credentials จริง
6. **Real vs Sample Telemetry Separation:**
   - ข้อมูลตัวอย่างทุกชิ้นถูกติดป้ายกำกับ `is_sample=True` และสามารถกรองออกด้วย `--exclude-samples` หรือ `?include_samples=0` เพื่อไม่ให้ปะปนกับข้อมูลจริง

---

## 2. ระบบ Anti-REA (`sentinel_x/security/release_protection/`)

### 2.1 ความสามารถหลัก
- **Tamper Detection & Release Integrity Verification:** คำนวณ SHA-256 ของทุกไฟล์ใน Release และตรวจสอบการแก้ไข ลบ หรือเพิ่มไฟล์โดยไม่ได้รับอนุญาต
- **Publisher Authentication (Signed Release Manifest):** ใช้ลายเซ็นดิจิทัลแบบอสมมาตร **Ed25519** (ผ่าน OpenSSL 3.0) ห้ามใช้เฉพาะค่า Hash เพียงอย่างเดียวเป็นหลักฐานยืนยันตัวตนของผู้เผยแพร่
- **Sensitive Artifact Exposure Reduction:** สแกนหา Secrets, ไฟล์ `.env`/`*.key`/`*.pem`, Debug Artifacts (`*.pdb`, `breakpoint()`), Source Maps (`*.map`) และการตั้งค่า Build ที่ไม่ปลอดภัย

### 2.2 การจัดการกุญแจ (Key Management Policy)
- **ห้าม** ฝัง Private Signing Key ไว้ใน Source Code หรือ Commit ขึ้น GitHub โดยเด็ดขาด
- สร้างและจัดเก็บ Private Key ไว้นอกโฟลเดอร์ Repository เสมอ เช่น:
  ```bash
  python3 -m sentinel_x.security.release_protection.cli keygen \
    --private-key ~/external_keys/sentinel_release.key \
    --public-key ~/external_keys/sentinel_release_public.pem
  ```

### 2.3 ข้อจำกัดด้านความปลอดภัยตามความเป็นจริง (Honest Security Limitations)
- **Anti-REA:** ไม่มีซอฟต์แวร์ใดสามารถรับประกันการป้องกัน Reverse Engineering ได้ 100% ระบบ Anti-REA ใน Sentinel-X ออกแบบมาเพื่อช่วย **Tamper Detection**, **Release Integrity Verification**, **Build Hardening**, และ **Sensitive Artifact Exposure Reduction**
- **Threat Detection Rules:** กฎการตรวจจับแต่ละข้อมีขอบเขตเฉพาะตามรูปแบบ Log และเงื่อนไขที่กำหนด ไม่สามารถอ้างว่ากฎข้อใดข้อหนึ่งตรวจจับการโจมตีได้ทุกประเภท
- **Status:** โปรเจกต์ผ่านการทดสอบ Unit & Integration Tests ครบถ้วนในสภาพแวดล้อมพัฒนา สำหรับการนำไปใช้ในระดับ Production ควรตั้งค่า Reverse Proxy (TLS) และจัดการสิทธิ์ของระบบปฏิบัติการเพิ่มเติม
