# Sentinel-X — รายการติดตามงาน (`TODO.md`)

สถานะที่ใช้:
- `[x]` COMPLETED (เสร็จสมบูรณ์และตรวจสอบแล้ว)
- `[>]` IN PROGRESS (กำลังดำเนินการ)
- `[ ]` PENDING (รอดำเนินการ)
- `[!]` BLOCKED (ติดปัญหา)
- `[?]` NEEDS APPROVAL (ต้องรออนุมัติ)

---

## 1. งานที่เสร็จแล้ว (Completed Tasks)

- [x] **PHASE 0 — DISCOVERY**: ตรวจสอบ Workspace, Git status, Remote, Technology Stack และจัดทำรายงานวิเคราะห์เบื้องต้น
  - *เงื่อนไขการเสร็จสิ้น:* รายงานครบ 12 หัวข้อโดยไม่แก้ไขไฟล์ และได้รับอนุมัติจากผู้ใช้แล้ว
- [x] **สร้าง `.gitignore` และ `.env.example`**: ป้องกันการรั่วไหลของ Secret, Private Keys, Local DB และไฟล์ชั่วคราว
  - *เงื่อนไขการเสร็จสิ้น:* มีไฟล์ `.gitignore` และ `.env.example` ที่ใช้เฉพาะ Placeholder ใน Workspace Root
- [x] **PHASE 1 — ARCHITECTURE**: ออกแบบสถาปัตยกรรม โมดูลหลัก Data Flow และ Security Boundaries
  - *เงื่อนไขการเสร็จสิ้น:* บันทึก `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md` ครบถ้วน
- [x] **PHASE 2 — FOUNDATION**: พัฒนาโครงสร้างพื้นฐาน `sentinel_x/core/`
  - `sentinel_x/core/exceptions.py`: ระบบจัดการข้อผิดพลาดของแพลตฟอร์ม
  - `sentinel_x/core/config.py`: ระบบโหลดและตรวจสอบการตั้งค่าจาก Environment Variables
  - `sentinel_x/core/audit.py`: ระบบบันทึก Security Audit Log (พร้อมป้องกัน Log Injection)
  - `sentinel_x/core/models.py`: โมเดลข้อมูลหลัก (`NormalizedSecurityEvent`, `DetectionRule`, `Alert`, `Incident`, `IncidentNote`, `TimelineEntry`)
  - `sentinel_x/core/database.py`: ชั้นฐานข้อมูล SQLite พร้อม Parameterized Queries
  - `tests/test_foundation.py`: Unit Tests ทดสอบทุกส่วนของ Foundation (รันผ่าน 4/4 tests)

- [x] **PHASE 3 — CORE SOC**:
  - [x] **3.1 ระบบจัดการ Security Logs (`sentinel_x/ingestion/`)**: Parsers (JSON, Syslog, Auth/SSH, Web Access), Normalizer, Timestamp UTC handling, Filtering, Searching, Event Correlation
  - [x] **3.2 Threat Detection Engine & MITRE ATT&CK (`sentinel_x/detection/`)**: Official MITRE ATT&CK catalog, Rule-based & Correlation detection, Severity classification, Detection explanation & evidence, Alert generation, Rule management
  - [x] **3.3 Incident Management & Reporting (`sentinel_x/incidents/`, `sentinel_x/reporting/`)**: สร้าง/อัปเดต Incident, Severity, Investigation Notes, Event linking, Timeline, Resolution tracking, Export reports (JSON/Markdown/HTML)
  - [x] **3.4 External Integrations Interface (`sentinel_x/integrations/`)**: Interfaces สำหรับ SIEM, EDR, Threat Intel, Notification ที่ตรวจสอบการตั้งค่า Credentials จริง
  - [x] **3.5 Security Dashboard & API (`sentinel_x/dashboard/`)**: แสดงข้อมูลจริงจากฐานข้อมูล (Events, Alerts, Severity Distribution, Stats, Incidents, Recent Activity) และแยก Sample Data ชัดเจน
  - [x] **3.6 SOC End-to-End Tests (`tests/test_soc_core.py`)**: ทดสอบการทำงานตั้งแต่ Ingest -> Detect -> Alert -> Incident -> Report -> Dashboard API (ผ่านครบทุกกรณี)

- [x] **PHASE 4 — ANTI-REA (`sentinel_x/security/release_protection/`)**:
  - [x] **4.1 File Inventory & Signed Manifest**: SHA-256 File Inventory, Ed25519 Manifest Signing & Verification (ใช้ External Key เท่านั้น)
  - [x] **4.2 Security & Artifact Scanner**: Secret Scanning, Sensitive File Detection, Debug Artifact & Source Map Exposure Checks, Build Configuration Checks
  - [x] **4.3 Security Audit Report & Release Verification CLI**: รายงานผลการตรวจสอบและ CLI สำหรับสร้าง/ตรวจสอบ Release
  - [x] **4.4 Anti-REA Tests (`tests/test_release_protection.py`)**: ทดสอบแยกอิสระจาก SOC Core (ผ่านครบทุกกรณี)
- [x] **PHASE 5 — INTEGRATION**:
  - [x] เชื่อมต่อ CLI หลัก (`sentinel_x/cli.py`) และ `sentinel_x/platform.py`, ทดสอบการทำงานร่วมกันของทุกโมดูล (`tests/test_integration.py`), ทดสอบ Security Boundaries และรัน Anti-REA Audit ตรวจสอบโปรเจกต์จริง (ผ่าน 12/12 tests)
- [x] **PHASE 6 — RELEASE PREPARATION**:
  - [x] จัดทำ `README.md`, เอกสารการติดตั้ง/ตั้งค่า/ความปลอดภัย (`docs/INSTALLATION.md`, `docs/CONFIGURATION.md`, `docs/SECURITY.md`), `requirements.txt`, `pyproject.toml`, ตรวจสอบ Dependency License และทำ Secret Scan ทั้งโปรเจกต์ (`PASSED` 0 findings)
- [x] **Git Commit & Push ขึ้น GitHub**: ตรวจสอบ `git status`, รัน Test ทั้งหมด (`12/12 OK`), ทำ Secret Scan (`PASSED`) และได้รับอนุมัติจากผู้ใช้ให้ Commit & Push ขึ้น `origin/main`
- [x] **PHASE 7 — EXTENDED SOC CAPABILITIES**:
  - [x] รองรับการรับ Log แบบ Real-time Syslog UDP Listener (`sentinel_x/ingestion/syslog_receiver.py`)
  - [x] รองรับกฎการตรวจจับในรูปแบบ Sigma YAML Rule Importer (`sentinel_x/detection/sigma.py`, `config/rules/sample_sigma_rule.yml`)
  - [x] ชุดทดสอบ `tests/test_phase7_extensions.py` (รันผ่านครบ 14/14 tests ทั้งโปรเจกต์)
- [x] **PHASE 8 — STANDALONE EXECUTABLE BUILD PIPELINE (.EXE)**:
  - [x] พัฒนา Standalone Entrypoint (`sentinel_x/__main__.py`) รองรับทั้งการรันผ่าน CLI และการดับเบิลคลิกเปิด Local Dashboard บน Windows
  - [x] พัฒนา `scripts/build_exe.py` (บังคับตรวจ Anti-REA Audit ก่อน Build, รัน PyInstaller แบบ `shell=False`, และสร้าง `sentinel-x.exe.sha256` + `build_manifest.json`)
  - [x] พัฒนา `scripts/build_windows.bat` สำหรับสร้าง `.exe` แบบคลิกเดียวบนเครื่อง Windows
  - [x] พัฒนาชุดทดสอบ `tests/test_build_exe.py`
- [x] **PHASE 9 — EXTERNAL API SETTINGS UI & GITHUB RELEASE / PACKAGES PIPELINE**:
  - [x] พัฒนาหน้าเว็บตั้งค่า API บริการภายนอก (`/settings`) สำหรับลูกค้า (SIEM, EDR, Threat Intelligence, Webhook Notification, External Security Tool / SOAR)
  - [x] พัฒนา REST API สำหรับบันทึกและทดสอบการเชื่อมต่อจริง (`/api/v1/settings/connectors`, `/api/v1/settings/connectors/test`) พร้อมจัดเก็บลง SQLite (`connector_settings`) และซ่อนค่า API Key (`••••••••xxxx`)
  - [x] พัฒนา `scripts/build_release_package.py` สร้างไฟล์ `.whl`, `.tar.gz`, `-release-bundle.zip`, `release_manifest.json`, และ `SHA256SUMS.txt`
  - [x] พัฒนา `Dockerfile` และ `.github/workflows/release-and-package.yml` สำหรับเผยแพร่ GitHub Release และ GitHub Packages (`ghcr.io`)
  - [x] พัฒนาชุดทดสอบ `tests/test_api_settings_and_release_pkg.py`
- [x] **PHASE 10 — AUTOMATED PATCH GENERATOR, PRE-COMPILED .EXE & VERSION RELEASE PIPELINE**:
  - [x] พัฒนา `build_windows_pe_zipapp_exe()` ใน `scripts/build_exe.py` เพื่อคอมไพล์ `dist/sentinel-x.exe` (Windows 64-bit PE32+ Console Executable + Embedded ZipApp) ให้เสร็จพร้อมใช้งานทันทีโดยไม่ต้องรอคอมไพล์เอง
  - [x] พัฒนา `scripts/release_patch.py` สำหรับปรับเลขเวอร์ชันอัตโนมัติ (`sentinel_x/__init__.py`, `pyproject.toml`), สร้างไฟล์ `.patch` (`patches/v<version>.patch`, `patches/latest.patch`, `patches/PATCH_MANIFEST.json`), คอมไพล์ `dist/sentinel-x.exe` ใหม่ และอัปเดต Git Tag บน GitHub
  - [x] พัฒนา `scripts/apply_patch_windows.bat` สำหรับดึง Patch และไฟล์ `.exe` ล่าสุดบน Windows แบบคลิกเดียว พร้อมแสดงป้ายเลขเวอร์ชัน (`v0.1.1`) บนหน้า `/` และ `/settings`
  - [x] ทดสอบครบ 23/23 Automated Tests ทั้งโปรเจกต์
- [x] **PHASE 11 — OFFICIAL SENTINEL-X WEBSITE FOR VERCEL DEPLOYMENT**:
  - [x] พัฒนาหน้าเว็บ Official Website (`public/index.html`, `public/styles.css`, `public/app.js`, `public/version.json`) พร้อมระบบจำลองการตรวจจับภัยคุกคามและแปลง Log เป็น MITRE ATT&CK แบบเรียลไทม์ (Live Simulator)
  - [x] สร้างไฟล์ `vercel.json` ตั้งค่า Zero-Config Deployment (`outputDirectory: "public"`), Security Headers และลิงก์ดาวน์โหลดตรง `/downloads/sentinel-x.exe` และ `/downloads/latest.patch`
  - [x] เชื่อมต่อ `scripts/release_patch.py` ให้ซิงค์เลขเวอร์ชันและค่า SHA-256 ลง `public/version.json` และ `public/index.html` อัตโนมัติทุกครั้งที่ออก Patch (ผ่านครบ 24/24 tests)

---

## 2. งานที่กำลังทำ (In Progress Tasks)
- ไม่มี (พัฒนา ทดสอบ และซิงค์ครบทุก Phase แล้ว)

---

## 3. งานที่รอดำเนินการ (Pending Tasks)
- ไม่มีงานค้างใน Phase 0–9

---

## 4. งานที่ต้องรออนุมัติ (Needs Approval)
- ไม่มี (`None`)

---

## 5. งานที่ติดปัญหา (Blocked Tasks)
- ไม่มี (`None`)

---

## 6. งานด้านความปลอดภัยและงานทดสอบ (Security & Testing Checklist)
- [x] ทดสอบป้องกัน Path Traversal ใน Log Ingestion (`test_soc_core.py`)
- [x] ทดสอบป้องกัน SQL Injection ใน Search/Filter Queries (`test_foundation.py`)
- [x] ทดสอบ Output Encoding (XSS Prevention) ใน Dashboard/Report HTML (`test_soc_core.py`)
- [x] ทดสอบ Tamper Detection เมื่อไฟล์ถูกแก้ไขหลังสร้าง Signed Manifest (`test_release_protection.py`)
- [x] ทดสอบ Secret Scanner ตรวจจับ Token/Private Key จำลอง (`test_release_protection.py` & `test_integration.py`)
- [x] ทดสอบ Real-time UDP Syslog Ingestion และ Sigma YAML MITRE Tag Validation (`test_phase7_extensions.py`)
- [x] ทดสอบ Pre-build Anti-REA Security Audit บล็อกการสร้าง `.exe` ทันทีหากพบไฟล์ความลับรั่วไหลในโปรเจกต์ (`test_build_exe.py`)
- [x] ทดสอบการซ่อนค่า API Key (Secret Masking), การป้องกัน URL อันตราย (`javascript:`) และการบันทึก Audit Log ในหน้าตั้งค่า API (`test_api_settings_and_release_pkg.py`)

---

## 7. งานในอนาคต (Future Enhancements)
- รองรับ Syslog over TLS (RFC 5425) สำหรับสภาพแวดล้อมข้ามเครือข่าย
