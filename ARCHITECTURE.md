# Sentinel-X — System Architecture (`ARCHITECTURE.md`)

## 1. ภาพรวมสถาปัตยกรรม (System Architecture Overview)

Sentinel-X ออกแบบในรูปแบบ **Modular Monolith แบบ Local-first** ด้วยภาษา **Python 3.11+** โดยเน้นความปลอดภัยตั้งแต่โครงสร้างพื้นฐาน (Secure by Design), ลดการพึ่งพาไลบรารีภายนอกที่ไม่จำเป็น (Minimal Dependencies), แยกส่วน Business Logic ออกจาก Presentation/UI อย่างชัดเจน และแยกโมดูล **Anti-REA (`release_protection`)** ให้ทำงานได้โดยอิสระไม่กระทบต่อการทำงานของระบบ SOC หลัก

```
+-------------------------------------------------------------------------+
|                        Presentation & Interfaces                        |
|   [Web Security Dashboard / REST API]       [Sentinel-X CLI & Tools]    |
+-------------------+-------------------------------------+---------------+
                    |                                     |
+-------------------v-------------------------------------v---------------+
|                         Core SOC Platform Layer                         |
|  +-----------------+  +------------------+  +------------------------+  |
|  |  Log Ingestion  |  | Threat Detection |  |  Incident Management   |  |
|  |  & Normalizer   |->|  & MITRE ATT&CK  |->|  & Reporting Engine    |  |
|  +-----------------+  +------------------+  +------------------------+  |
|  +-------------------------------------------------------------------+  |
|  |           External Integration Interfaces (SIEM/TI/Notify)        |  |
|  +-------------------------------------------------------------------+  |
+------------------------------------+------------------------------------+
                                     |
+------------------------------------v------------------------------------+
|                      Foundation & Storage Layer                         |
|   [Core Models]  [SQLite Parameterized Store]  [Config & Audit Logger]  |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
|         Independent Module: Anti-REA (`security/release_protection`)    |
|  [SHA-256 Inventory] [Ed25519 Signed Manifest] [Secret & Artifact Scan] |
+-------------------------------------------------------------------------+
```

---

## 2. โมดูลหลัก (Core Modules)

```text
sentinel-x/
├── sentinel_x/
│   ├── __init__.py
│   ├── cli.py                        # CLI หลักสำหรับสั่งงาน SOC และ Dashboard
│   ├── core/
│   │   ├── config.py                 # การอ่านและตรวจสอบค่าตั้งต้นจาก Environment Variables
│   │   ├── models.py                 # Dataclasses / Domain Models (Event, Alert, Rule, Incident)
│   │   ├── database.py               # SQLite Storage Layer (Parameterized SQL 100%)
│   │   ├── exceptions.py             # Custom Exception Hierarchy
│   │   └── audit.py                  # Structured Security Audit Logging
│   ├── ingestion/
│   │   ├── parsers.py                # Pluggable Parsers (JSON, Syslog, Linux Auth/SSH, Web Access)
│   │   ├── normalizer.py             # แปลง Raw Log เป็น NormalizedSecurityEvent (UTC ISO-8601)
│   │   └── service.py                # Ingestion Service (File Size Limit, Path Traversal Guard, Search/Correlation)
│   ├── detection/
│   │   ├── mitre.py                  # ฐานข้อมูลอ้างอิง MITRE ATT&CK ทางการ (Tactic, Technique ID/Name)
│   │   ├── rules.py                  # การโหลด ตรวจสอบ และจัดการ Detection Rules (Single & Correlation)
│   │   └── engine.py                 # Threat Detection Engine, Alert Generation & Explanation
│   ├── incidents/
│   │   └── service.py                # Incident Lifecycle, Investigation Notes, Event Linking, Timeline
│   ├── reporting/
│   │   └── exporter.py               # การสร้างรายงาน Incident & SOC Summary (JSON, Markdown, HTML)
│   ├── integrations/
│   │   └── connectors.py             # Interfaces สำหรับ SIEM, EDR, Threat Intel, Notification (ตรวจสอบ Credential จริง)
│   ├── dashboard/
│   │   └── server.py                 # Local-first Security Dashboard & REST API (แยกข้อมูลจริงและ Sample ชัดเจน)
│   └── security/
│       └── release_protection/       # โมดูล Anti-REA แยกอิสระ
│           ├── inventory.py          # คำนวณ SHA-256 File Inventory
│           ├── manifest.py           # สร้างและตรวจสอบ Signed Release Manifest (Ed25519 Digital Signature)
│           ├── scanner.py            # Secret Scanning, Sensitive Files, Debug/SourceMap & Build Config Audit
│           ├── report.py             # สร้าง Security Audit Report
│           └── cli.py                # Release Verification CLI
├── config/
│   └── rules/
│       └── default_rules.json        # กฎตรวจจับเริ่มต้นพร้อม MITRE ATT&CK Mapping
├── data/
│   └── samples/                      # ข้อมูล Log ตัวอย่างสำหรับทดสอบ (ระบุชัดเจนว่าเป็น Sample)
├── scripts/
│   ├── build_exe.py                  # สคริปต์คอมไพล์ Standalone Windows .exe (PyInstaller / Clang+LLD PE32+ / csc.exe)
│   ├── build_release_package.py      # สคริปต์สร้างแพ็กเกจ .whl, .tar.gz, .zip, release_manifest.json, SHA256SUMS.txt
│   ├── release_patch.py              # สคริปต์อัตโนมัติสำหรับปรับเวอร์ชัน, สร้างไฟล์ .patch, คอมไพล์ .exe และอัปเดต GitHub
│   ├── build_windows.bat             # สคริปต์ Build .exe แบบคลิกเดียวบน Windows
│   └── apply_patch_windows.bat       # สคริปต์อัปเดต Patch และตรวจรับไฟล์ dist\sentinel-x.exe ที่คอมไพล์เสร็จแล้ว
├── patches/                          # เก็บไฟล์ Git Unified Diff Patch (v*.patch, latest.patch, PATCH_MANIFEST.json)
├── dist/                             # เก็บไฟล์ sentinel-x.exe ที่คอมไพล์พร้อมใช้งานทันทีพร้อมไฟล์ .sha256 และ build_manifest.json
├── public/                           # หน้าเว็บ Official Website ของ Sentinel-X สำหรับ Deploy บน Vercel (index.html, styles.css, app.js, version.json)
├── vercel.json                       # ไฟล์ตั้งค่า Vercel Zero-Config Deployment, Security Headers และลิงก์ดาวน์โหลด .exe / .patch
├── tests/                            # Unit Tests & Integration Tests แยกตามโมดูล
└── docs/                             # เอกสารคู่มือการติดตั้ง การตั้งค่า และความปลอดภัย
```

---

## 3. Dependencies

เลือกใช้ Python Standard Library เป็นหลัก (`sqlite3`, `json`, `re`, `hashlib`, `hmac`, `http.server`, `urllib`, `pathlib`, `datetime`, `logging`, `unittest`/`pytest`) ร่วมกับแพ็กเกจมาตรฐานเท่าที่จำเป็น:
- `cryptography` — สำหรับ Digital Signature แบบ Asymmetric (`Ed25519`) ในการลงนามและตรวจสอบ Release Manifest ของโมดูล Anti-REA อย่างปลอดภัยตามมาตรฐานสากล
- `pytest` — สำหรับการรัน Unit Tests และ Integration Tests

*(หลีกเลี่ยง Framework หรือ ORM ขนาดใหญ่ที่เพิ่มความเสี่ยงด้าน Supply Chain)*

---

## 4. การไหลของข้อมูล (Data Flow)

1. **Log Ingestion Flow:**
   - รับข้อมูล Raw Log จากไฟล์หรือ API -> ตรวจสอบสิทธิ์และป้องกัน Path Traversal (`Path.resolve()` ต้องอยู่ภายใต้โฟลเดอร์ที่อนุญาต และขนาดไม่เกิน `SENTINEL_MAX_INGEST_FILE_BYTES`) -> ส่งต่อให้ `Parser` ที่เหมาะสม -> `Normalizer` แปลงเวลาเป็น UTC ISO-8601 และจัดหมวดหมู่ Event -> บันทึกลงตาราง `security_events`
2. **Threat Detection & MITRE Mapping Flow:**
   - เมื่อมี `NormalizedSecurityEvent` ใหม่ -> `DetectionEngine` ประเมินกับ `DetectionRule` ที่เปิดใช้งาน (ทั้งแบบเงื่อนไขเดี่ยว และแบบ Time-window Correlation เช่น SSH Brute Force) -> แนบข้อมูล MITRE ATT&CK (`Technique ID`, `Technique Name`, `Tactic`) และคำอธิบาย (`Detection Explanation` + `Event Evidence`) -> สร้าง `Alert` ลงตาราง `alerts`
3. **Incident Management & Reporting Flow:**
   - นักวิเคราะห์หรือระบบสร้าง `Incident` จาก `Alert`/`Event` -> บันทึกสถานะ (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`), `Severity`, และ `Investigation Notes` -> ทุกการเปลี่ยนแปลงถูกบันทึกใน `incident_timeline` และ `audit.log` -> ส่งออกรายงานผ่าน `ReportingExporter`
4. **Release Protection (Anti-REA) Flow:**
   - สแกนไฟล์ในโปรเจกต์เพื่อตรวจหา Secrets, ไฟล์อ่อนไหว, Debug Artifacts, Source Maps และการตั้งค่า Build -> คำนวณ SHA-256 ของทุกไฟล์ใน Release -> สร้าง Manifest และลงนามด้วย `Ed25519 Private Key` ที่โหลดจากภายนอก -> ตรวจสอบความถูกต้องของทั้ง Signature และ File Hashes เพื่อตรวจจับการแก้ไขโดยไม่ได้รับอนุญาต (Tamper Detection)

---

## 5. ขอบเขตความปลอดภัยและการวิเคราะห์ความเสี่ยง (Security Boundaries & Risk Analysis)

| ขอบเขต / ความเสี่ยง | มาตรการป้องกัน (Security Controls) |
| :--- | :--- |
| **File Ingestion Boundary** | ป้องกัน Path Traversal ด้วยการตรวจสอบ Canonical Path (`resolve()`) ห้ามอ่าน symlink ที่ชี้ไปนอกขอบเขต และจำกัดขนาดไฟล์สูงสุด |
| **Database Boundary (SQLite)** | ใช้ Parameterized Queries (`?`) ทุกคำสั่ง 100% ห้ามต่อ String ใน SQL เพื่อป้องกัน SQL Injection |
| **Web Dashboard & API Boundary** | ผูกกับ `127.0.0.1` เป็นค่าเริ่มต้น (Local-first), ทำ Output Encoding/HTML Escaping ป้องกัน XSS, ตรวจสอบ Content-Type และความยาว Input, และรองรับ API Token Authentication สำหรับ Endpoint ที่แก้ไขข้อมูล |
| **External Connector Boundary** | ห้ามจำลองว่าเชื่อมต่อสำเร็จหากไม่มีการตั้งค่า Credentials จริง แสดงสถานะ `NOT_CONFIGURED` อย่างตรงไปตรงมา และห้ามใช้ `shell=True` ป้องกัน Command Injection |
| **Cryptographic Signing Boundary (Anti-REA)** | ใช้ Ed25519 Digital Signature สำหรับยืนยันตัวตนผู้เผยแพร่คู่กับ SHA-256 File Hashes ห้ามฝัง Private Key ในโค้ดหรือ Commit ขึ้น Git |

---

## 6. จุดเชื่อมต่อภายนอก (Integration Points)

โมดูล `sentinel_x/integrations/connectors.py` กำหนด Base Interface (`SecurityConnector`) สำหรับ:
1. **SIEM Connector** (`SIEMForwarderConnector`)
2. **Endpoint Security Connector** (`EndpointResponseConnector`)
3. **Threat Intelligence Connector** (`ThreatIntelLookupConnector`)
4. **Notification Connector** (`WebhookNotificationConnector`)

ทุก Connector มีเมธอด `check_health()` และ `is_configured()` ที่ตรวจสอบจาก Environment Variables จริง

---

## 7. แผนการพัฒนา (Development Plan)

- **PHASE 0 — DISCOVERY:** ตรวจสอบสภาพแวดล้อมและโครงสร้าง `[COMPLETED]`
- **PHASE 1 — ARCHITECTURE:** ออกแบบสถาปัตยกรรมและสร้างไฟล์จัดการสถานะโปรเจกต์ `[COMPLETED]`
- **PHASE 2 — FOUNDATION:** พัฒนา `sentinel_x/core/` (Config, Models, SQLite Database, Exceptions, Audit Logging) พร้อม Unit Tests `[COMPLETED]`
- **PHASE 3 — CORE SOC:** พัฒนา Ingestion, Detection Engine + MITRE ATT&CK, Incidents, Reporting, Connectors, และ Dashboard พร้อม Tests `[COMPLETED]`
- **PHASE 4 — ANTI-REA:** พัฒนา `sentinel_x/security/release_protection/` พร้อม Release Verification CLI และ Tests `[COMPLETED]`
- **PHASE 5 — INTEGRATION:** เชื่อมต่อระบบทั้งหมดเข้าด้วยกัน รัน End-to-End Tests และรัน Anti-REA Audit กับตัวโปรเจกต์ `[COMPLETED]`
- **PHASE 6 — RELEASE PREPARATION:** จัดทำเอกสารครบถ้วน ทบทวนความปลอดภัย และซิงค์ขึ้น GitHub `[COMPLETED]`
- **PHASE 7 — EXTENDED SOC CAPABILITIES:** พัฒนา Real-time UDP Syslog Receiver (`sentinel_x/ingestion/syslog_receiver.py`) และ Sigma YAML Rule Importer (`sentinel_x/detection/sigma.py`) พร้อมชุดทดสอบ `[COMPLETED]`
- **PHASE 8 — STANDALONE EXECUTABLE BUILD PIPELINE (.EXE):** พัฒนา Standalone Entrypoint (`sentinel_x/__main__.py`), สคริปต์สร้างไฟล์ `.exe` พร้อมตรวจ Anti-REA ก่อน Build และสร้าง SHA-256 Build Manifest (`scripts/build_exe.py`), สคริปต์ One-Click สำหรับ Windows (`scripts/build_windows.bat`) และชุดทดสอบ `tests/test_build_exe.py` `[COMPLETED]`
- **PHASE 9 — EXTERNAL API SETTINGS UI & GITHUB RELEASE / PACKAGES PIPELINE:** พัฒนาหน้าเว็บตั้งค่าการเชื่อมต่อ API บริการภายนอก (`/settings`), REST API จัดการและทดสอบการเชื่อมต่อ (`/api/v1/settings/connectors`, `/api/v1/settings/connectors/test`) พร้อมบันทึกใน SQLite แบบซ่อนค่า Secret, สคริปต์สร้างแพ็กเกจ Release (`scripts/build_release_package.py`), `Dockerfile` สำหรับ GitHub Packages (`ghcr.io`), และ GitHub Actions Workflow (`.github/workflows/release-and-package.yml`) พร้อมชุดทดสอบ `tests/test_api_settings_and_release_pkg.py` `[COMPLETED]`
