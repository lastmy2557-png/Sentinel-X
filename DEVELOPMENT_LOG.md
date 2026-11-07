# Sentinel-X — บันทึกการพัฒนา (`DEVELOPMENT_LOG.md`)

---

## [2026-11-06] — PHASE 0 (DISCOVERY) & PHASE 1 (ARCHITECTURE)

- **งานที่ทำเสร็จ:**
  - ตรวจสอบ Workspace (`/home/antigravity/lastmy2557-png/Sentinel-X`), สถานะ Git (`main`), Remote (`origin`), และเครื่องมือในระบบ (`Python 3.11.2`, `uv 0.13.7`, `git 2.39.5`)
  - สร้างไฟล์ `.gitignore` และ `.env.example` เพื่อป้องกันการรั่วไหลของข้อมูลสำคัญ
  - ออกแบบสถาปัตยกรรม Modular Monolith สำหรับ Core SOC และโมดูลแยกอิสระ Anti-REA (`sentinel_x/security/release_protection/`)
  - จัดทำเอกสารควบคุมสถานะโปรเจกต์ครบทั้ง 5 ไฟล์ (`ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`)
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `.gitignore`, `.env.example`, `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ใช้ Python 3.11+ และ SQLite (Parameterized Queries) เป็นแกนหลักแบบ Local-first
  - แยกโมดูล `release_protection` ออกจากระบบ SOC หลักอย่างสมบูรณ์
- **Tests ที่รันและผลการทดสอบ:**
  - ตรวจสอบโครงสร้างไฟล์และสถานะ Git (Read-only checks) ผ่านเรียบร้อย (Automated unit tests จะเริ่มใน Phase 2)
- **ปัญหาที่พบ:**
  - ไม่มีปัญหาในโปรเจกต์ พร้อมเข้าสู่ Phase 2 (Foundation)

---

## [2026-11-06] — PHASE 2 (FOUNDATION)

- **งานที่ทำเสร็จ:**
  - พัฒนา `sentinel_x/core/` ครบทุกส่วน: `exceptions.py`, `config.py`, `audit.py`, `models.py`, `database.py`
  - พัฒนาชุดทดสอบ `tests/test_foundation.py` ครอบคลุมการตรวจสอบ Config, การซ่อน Secret, การป้องกัน Log Injection, การตรวจสอบ MITRE Technique ID และการป้องกัน SQL Injection ใน SQLite
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `sentinel_x/__init__.py`, `sentinel_x/core/__init__.py`, `sentinel_x/core/exceptions.py`, `sentinel_x/core/config.py`, `sentinel_x/core/audit.py`, `sentinel_x/core/models.py`, `sentinel_x/core/database.py`, `tests/__init__.py`, `tests/test_foundation.py`
  - อัปเดต: `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ใช้ `unittest` มาตรฐานของ Python 3.11 เพื่อให้รันทดสอบได้ทันทีในทุกสภาพแวดล้อมโดยไม่ต้องติดตั้งไลบรารีภายนอกเพิ่มเติม
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 4/4 tests (`OK`)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อมเข้าสู่ Phase 3 (Core SOC)

---

## [2026-11-06] — PHASE 3 (CORE SOC)

- **งานที่ทำเสร็จ:**
  - พัฒนาระบบจัดการ Security Logs (`sentinel_x/ingestion/`): รองรับ JSON, Syslog/SSH/Sudo, Web Access (พร้อม URL decoding), Custom Parser Registry, Search/Filter, Event Correlation และ Path Traversal / Size Limit Guard
  - พัฒนา Threat Detection Engine & Official MITRE ATT&CK (`sentinel_x/detection/`): รองรับ Single-event และ Time-window Correlation, Rule Management, Dry-run Rule Testing และสร้าง Alert พร้อมคำอธิบายและหลักฐาน
  - พัฒนา Incident Management & Reporting (`sentinel_x/incidents/`, `sentinel_x/reporting/`): สร้าง/อัปเดตสถานะและ Severity, บันทึก Investigation Notes, เชื่อมโยง Events/Alerts, Timeline อัตโนมัติ, ส่งออกรายงาน JSON/Markdown/XSS-safe HTML
  - พัฒนา External Security Connectors (`sentinel_x/integrations/`) และ Security Dashboard & HTTP Server (`sentinel_x/dashboard/`)
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `sentinel_x/ingestion/*`, `sentinel_x/detection/*`, `sentinel_x/incidents/*`, `sentinel_x/reporting/*`, `sentinel_x/integrations/*`, `sentinel_x/dashboard/*`, `config/rules/default_rules.json`, `data/samples/sample_security.log`, `tests/test_soc_core.py`
  - อัปเดต: `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ถอดรหัส URL-encoded URI ใน `WebAccessLogParser` เพื่อให้กฎตรวจจับ SQLi และ Directory Traversal ตรวจพบ Payload ที่เข้ารหัส `%20` หรือ `%2e` ได้อย่างแม่นยำ
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 7/7 tests (`OK`)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อมเข้าสู่ Phase 4 (Anti-REA Release Protection)

---

## [2026-11-06] — PHASE 4 (ANTI-REA / RELEASE PROTECTION)

- **งานที่ทำเสร็จ:**
  - พัฒนาโมดูลแยกอิสระ `sentinel_x/security/release_protection/` ครบทุกส่วน:
    - `inventory.py`: คำนวณ SHA-256 File Inventory แบบ Deterministic พร้อมป้องกัน Symlink Traversal
    - `manifest.py`: สร้างและตรวจสอบ Signed Release Manifest ด้วย OpenSSL 3.0 Ed25519 Digital Signature (External Key เท่านั้น) พร้อมตรวจจับการแก้ไข ลบ หรือเพิ่มไฟล์โดยไม่ได้รับอนุญาต (Tamper Detection)
    - `scanner.py`: สแกนหา Secrets (พร้อมปิดบังค่า Secret ในผลลัพธ์), Sensitive Files, Debug Artifacts, Source Maps และการตั้งค่า Build ที่ไม่ปลอดภัย
    - `report.py`: สร้างรายงาน Security Audit Report ทั้งรูปแบบ JSON และ Markdown พร้อมระบุขอบเขตความสามารถตามจริง
    - `cli.py`: Release Verification CLI (`keygen`, `inventory`, `sign`, `verify`, `audit`)
  - พัฒนาและรันชุดทดสอบแยกอิสระ `tests/test_release_protection.py`
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `sentinel_x/security/__init__.py`, `sentinel_x/security/release_protection/__init__.py`, `inventory.py`, `manifest.py`, `scanner.py`, `report.py`, `cli.py`, `tests/test_release_protection.py`
  - อัปเดต: `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ใช้ OpenSSL 3.0 Ed25519 Digital Signature ผ่าน `subprocess.run(..., shell=False)` เพื่อความปลอดภัยสูงสุดโดยไม่ต้องติดตั้งไลบรารีภายนอกเพิ่มเติม
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 10/10 tests (`OK`)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อมเข้าสู่ Phase 5 (Integration)

---

## [2026-11-06] — PHASE 5 (INTEGRATION)

- **งานที่ทำเสร็จ:**
  - พัฒนา `sentinel_x/platform.py` (`SentinelXPlatform`) เชื่อมต่อระบบ Ingestion, Detection, Incident Management, Reporting, Integrations และ Dashboard เข้าด้วยกัน
  - พัฒนา `sentinel_x/cli.py` สำหรับการสั่งงานแพลตฟอร์มผ่าน Command Line
  - พัฒนาและรัน `tests/test_integration.py` ทดสอบการทำงานร่วมกันตั้งแต่ต้นจนจบ และรัน Anti-REA Self-Audit กับโปรเจกต์ Sentinel-X จริง
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `sentinel_x/platform.py`, `sentinel_x/cli.py`, `tests/test_integration.py`
  - อัปเดต: `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ให้ `SentinelXPlatform` เชื่อม callback `on_event_ingested` เข้ากับ `ThreatDetectionEngine.evaluate_event` โดยตรงเพื่อให้ทุก Log ที่ถูก Ingest ผ่านการตรวจจับภัยคุกคามทันที
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 12/12 tests (`OK`)
  - Anti-REA Self-Audit บน `/home/antigravity/lastmy2557-png/Sentinel-X` -> `PASSED` (0 findings)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อมเข้าสู่ Phase 6 (Release Preparation)

---

## [2026-11-06] — PHASE 6 (RELEASE PREPARATION)

- **งานที่ทำเสร็จ:**
  - จัดทำเอกสารคู่มือการติดตั้ง (`docs/INSTALLATION.md`), การตั้งค่า (`docs/CONFIGURATION.md`), นโยบายความปลอดภัย (`docs/SECURITY.md`), และอัปเดต `README.md`
  - สร้าง `requirements.txt` และ `pyproject.toml`
  - ปรับปรุง `.gitignore` ให้อนุญาต `!data/samples/*.log` สำหรับไฟล์ทดสอบ
  - รันชุดทดสอบทั้งหมดและรัน Anti-REA Audit (Secret Scan, Sensitive File Check, Debug/SourceMap Check, Build Config Check) ตรวจสอบทั้งโปรเจกต์
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `requirements.txt`, `pyproject.toml`, `docs/INSTALLATION.md`, `docs/CONFIGURATION.md`, `docs/SECURITY.md`
  - แก้ไข: `README.md`, `.gitignore`, `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - รักษาโครงสร้าง Zero External Runtime Dependencies (ใช้ Python 3.11+ Standard Library และ OpenSSL 3.0) เพื่อลดความเสี่ยงด้าน Supply Chain และความซับซ้อนในการติดตั้ง
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 12/12 tests (`OK`)
  - `python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown` -> `PASSED` (`51 files inventoried`, `0 findings`)
- **ปัญหาที่พบ:**
  - ไม่มี ได้รับอนุมัติจากผู้ใช้ให้ดำเนินการ Commit และ Push ขึ้น GitHub (`origin/main`) เรียบร้อยแล้ว

---

## [2026-11-07] — PHASE 7 (EXTENDED SOC CAPABILITIES)

- **งานที่ทำเสร็จ:**
  - พัฒนา `sentinel_x/ingestion/syslog_receiver.py` (`SyslogUDPReceiver`) สำหรับรับข้อมูล Syslog แบบ Real-time ผ่าน UDP (`127.0.0.1` เป็นค่าเริ่มต้น) พร้อมจำกัดขนาดแพ็กเกจและส่งเข้า Detection Engine ทันที
  - พัฒนา `sentinel_x/detection/sigma.py` (`parse_sigma_yaml_to_rule`, `load_sigma_rule_file`) สำหรับนำเข้ากฎตรวจจับแบบ Sigma YAML โดยใช้ `yaml.safe_load` และตรวจสอบ Tag ของ MITRE ATT&CK กับฐานข้อมูลทางการ
  - เพิ่มไฟล์ตัวอย่าง `config/rules/sample_sigma_rule.yml` และเพิ่มคำสั่ง CLI `import-sigma` และ `syslog-listen`
  - พัฒนาและรันชุดทดสอบ `tests/test_phase7_extensions.py`
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `sentinel_x/ingestion/syslog_receiver.py`, `sentinel_x/detection/sigma.py`, `config/rules/sample_sigma_rule.yml`, `tests/test_phase7_extensions.py`
  - แก้ไข: `sentinel_x/ingestion/__init__.py`, `sentinel_x/detection/__init__.py`, `sentinel_x/detection/engine.py`, `sentinel_x/cli.py`, `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ใช้ `yaml.safe_load` เท่านั้นในการอ่านไฟล์กฎ YAML เพื่อป้องกันช่องโหว่ Arbitrary Object Deserialization
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 14/14 tests (`OK`)
  - `python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown` -> `PASSED` (`55 files inventoried`, `0 findings`)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อม Commit และ Push ขึ้น `origin/main` ตามคำสั่งอนุมัติของผู้ใช้

---

## [2026-11-07] — PHASE 8 (STANDALONE EXECUTABLE BUILD PIPELINE / WINDOWS .EXE)

- **งานที่ทำเสร็จ:**
  - พัฒนา `sentinel_x/__main__.py` เป็นจุดเข้าใช้งานสำหรับ Standalone Executable (`sentinel-x.exe`) โดยหากรันแบบไม่มีอาร์กิวเมนต์ (เช่น ดับเบิลคลิกบน Windows) จะเปิด Local-first Security Dashboard บน `http://127.0.0.1:8080` อัตโนมัติ และหากระบุอาร์กิวเมนต์จะส่งต่อไปยัง SOC CLI หรือ Release Protection CLI
  - พัฒนา `scripts/build_exe.py` สำหรับคอมไพล์โปรเจกต์ด้วย PyInstaller (`--onefile`, `shell=False`) โดยมีระบบบังคับรัน **Anti-REA Security Audit** ก่อนเริ่ม Build และสร้างไฟล์ `sentinel-x.exe.sha256` คู่กับ `build_manifest.json` หลังคอมไพล์เสร็จ
  - พัฒนา `scripts/build_windows.bat` สำหรับรันบนเครื่อง Windows แบบคลิกเดียว (สร้าง `.venv`, ติดตั้ง `pyinstaller` และ `pyyaml`, รัน Tests, และสร้าง `dist\sentinel-x.exe`)
  - อัปเดตคู่มือ `docs/INSTALLATION.md` และ `README.md` พร้อมพัฒนาชุดทดสอบ `tests/test_build_exe.py`
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `sentinel_x/__main__.py`, `scripts/build_exe.py`, `scripts/build_windows.bat`, `tests/test_build_exe.py`
  - แก้ไข: `.gitignore`, `README.md`, `docs/INSTALLATION.md`, `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ผสานการตรวจสอบ Anti-REA เข้าไปในขั้นตอน Pre-build ของ `scripts/build_exe.py` เพื่อป้องกันไม่ให้มีการแพ็กไฟล์ `.exe` หากตรวจพบ Secret หรือไฟล์ความลับหลงเหลืออยู่ในโฟลเดอร์โปรเจกต์
  - แก้ไขไวยากรณ์ `scripts/build_windows.bat` ไม่ให้ใช้วงเล็บหลายบรรทัดใน `cmd.exe`, พัฒนา **Native RFC 8032 Ed25519 + RFC 8410 PEM** ใน `manifest.py` (เข้ากันได้กับ OpenSSL 3.0 100% โดยไม่ต้องเรียก `openssl.exe`), ปรับปรุง `SyslogUDPReceiver` และ `DatabaseManager` สำหรับ Windows, เพิ่ม Pure-Python Sigma YAML Parser Fallback ใน `sigma.py`, และเพิ่มระบบคอมไพล์ `.exe` ด้วย `csc.exe` ของ Windows สำหรับสภาพแวดล้อม `Python 3.14.2`
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 20/20 tests (`OK`)
  - ทดสอบ Interoperability ระหว่าง RFC 8032 Ed25519 ใน `manifest.py` กับ `openssl pkeyutl -verify` -> `Signature Verified Successfully`
  - `python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown` -> `PASSED` (`59 files inventoried`, `0 findings`)
- **ปัญหาที่พบ:**
  - แก้ไขปัญหา `FAILED (failures=1, errors=2)` บน Windows เรียบร้อยแล้ว พร้อม Commit และ Push ขึ้น `origin/main`

---

## [2026-11-07] — PHASE 9 (EXTERNAL API SETTINGS UI & GITHUB RELEASE / PACKAGES PIPELINE)

- **งานที่ทำเสร็จ:**
  - พัฒนาหน้าเว็บตั้งค่าการเชื่อมต่อ API บริการภายนอก (`/settings`) ใน `sentinel_x/dashboard/server.py` พร้อมแถบเมนูนำทางเชื่อมระหว่างหน้า `SOC Dashboard (/)` และหน้า `ตั้งค่า API บริการภายนอก (/settings)`
  - พัฒนา REST API `GET/POST /api/v1/settings/connectors` และ `POST /api/v1/settings/connectors/test` รองรับการตั้งค่าบริการภายนอกทั้ง 5 หมวดหมู่ที่ลูกค้าใช้งานจริง (SIEM, EDR, Threat Intelligence, Webhook Notification, External Security Tool / SOAR)
  - เพิ่มตาราง `connector_settings` ใน `sentinel_x/core/database.py` พร้อมการซ่อนค่า API Key (`••••••••xxxx`), การตรวจสอบความถูกต้องของ URL และการบันทึก Security Audit Log ทุกครั้งที่มีการแก้ไขหรือทดสอบการเชื่อมต่อ
  - พัฒนา `scripts/build_release_package.py` สำหรับสร้างไฟล์แพ็กเกจมาตรฐาน PEP 427 Wheel (`.whl`), Source Tarball (`.tar.gz`), Release Bundle (`.zip`), `release_manifest.json`, และ `SHA256SUMS.txt`
  - สร้าง `Dockerfile` (Non-root container สำหรับ GitHub Container Registry `ghcr.io`) และ `.github/workflows/release-and-package.yml` สำหรับทำ CI/CD สร้าง Windows `.exe`, เผยแพร่ GitHub Packages และสร้าง GitHub Release อัตโนมัติ
  - พัฒนาและรันชุดทดสอบ `tests/test_api_settings_and_release_pkg.py`
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `scripts/build_release_package.py`, `Dockerfile`, `.github/workflows/release-and-package.yml`, `tests/test_api_settings_and_release_pkg.py`
  - แก้ไข: `sentinel_x/core/database.py`, `sentinel_x/integrations/connectors.py`, `sentinel_x/dashboard/server.py`, `sentinel_x/platform.py`, `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ห้ามส่งค่า API Key ดิบกลับไปยังหน้าเว็บหรือ API Response เด็ดขาด (ส่งกลับเฉพาะค่าที่ผ่าน `mask_secret_value` แล้วเท่านั้น) และหากผู้ใช้เว้นช่อง API Key ว่างขณะกดบันทึก ระบบจะคงค่า API Key เดิมที่บันทึกไว้ในฐานข้อมูลโดยไม่ต้องกรอกซ้ำ
  - ปรับปรุง CSS Layout ของ `.topbar`, `.nav`, `.nav a`, `.conn-header`, และ `.checkbox-row` ใน `sentinel_x/dashboard/server.py` ให้ใช้ `display: flex; flex-wrap: wrap; gap: ...` และ `display: inline-flex; white-space: nowrap;` บนปุ่มนำทาง เพื่อป้องกันไม่ให้ปุ่ม `ตั้งค่า API บริการภายนอก (API Settings)` ตัดบรรทัดทับกับปุ่ม `SOC Dashboard`
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 22/22 tests (`OK`)
  - `python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown` -> `PASSED` (`63 files inventoried`, `0 findings`)
- **ปัญหาที่พบ:**
  - แก้ไขปัญหาปุ่มเมนูนำทางบนหัวหน้า `/settings` ซ้อนทับกันเมื่อข้อความยาวเสร็จเรียบร้อย พร้อม Commit, Push, และอัปเดต Git Tag `v0.1.0`

---

## [2026-11-07] — PHASE 10 (AUTOMATED PATCH GENERATOR, PRE-COMPILED .EXE & VERSION RELEASE PIPELINE)

- **งานที่ทำเสร็จ:**
  - พัฒนา `build_windows_pe_zipapp_exe()` ใน `scripts/build_exe.py` โดยใช้ `clang --target=x86_64-pc-windows-msvc` + `llvm-dlltool` + `lld-link` เพื่อคอมไพล์ `dist/sentinel-x.exe` เป็นไฟล์ **Native 64-bit Windows PE32+ Console Executable** พร้อมฝัง ZipApp ในตัวเดียว และอนุญาตให้ Track ไฟล์ `dist/sentinel-x.exe`, `dist/sentinel-x.exe.sha256`, และ `dist/build_manifest.json` ลงใน Git เพื่อให้ผู้ใช้ดึงไฟล์ `.exe` ที่คอมไพล์เสร็จแล้วไปรันได้ทันที
  - พัฒนา `scripts/release_patch.py` สำหรับทำงานอัตโนมัติทุกครั้งที่มีการอัปเดตไฟล์:
    1. ปรับเลขเวอร์ชันอัตโนมัติ (`patch`, `minor`, `major` หรือระบุ `--version`) ใน `sentinel_x/__init__.py` และ `pyproject.toml`
    2. รัน Anti-REA Security Audit
    3. สร้างไฟล์ `.patch` มาตรฐาน (`patches/v<version>.patch`, `patches/latest.patch`) และ `patches/PATCH_MANIFEST.json`
    4. คอมไพล์ `dist/sentinel-x.exe` ใหม่พร้อมคำนวณ SHA-256 และสร้างชุดแพ็กเกจ Release
    5. Commit, ติด Git Tag เวอร์ชันใหม่ (`v0.1.1`) และ Push ขึ้น GitHub (`origin/main`) อัตโนมัติ
  - พัฒนา `scripts/apply_patch_windows.bat` สำหรับอัปเดต Patch และตรวจรับ `dist\sentinel-x.exe` บน Windows แบบคลิกเดียว พร้อมแสดงป้ายเวอร์ชัน (`v0.1.1`) บนหน้า `/` และ `/settings`
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `scripts/release_patch.py`, `scripts/apply_patch_windows.bat`, `patches/v0.1.1.patch`, `patches/latest.patch`, `patches/PATCH_MANIFEST.json`, `dist/sentinel-x.exe`, `dist/sentinel-x.exe.sha256`, `dist/build_manifest.json`
  - แก้ไข: `scripts/build_exe.py`, `sentinel_x/cli.py`, `sentinel_x/dashboard/server.py`, `sentinel_x/security/release_protection/scanner.py`, `sentinel_x/security/release_protection/inventory.py`, `.gitignore`, `tests/test_api_settings_and_release_pkg.py`, `README.md`, `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ใช้ `clang` + `lld-link` คอมไพล์ Native Win32 PE32+ Stub ที่เรียกใช้เฉพาะ `kernel32.dll` (ไม่ต้องพึ่งพา CRT ภายนอก) ต่อท้ายด้วย Python ZipApp เพื่อให้ `dist/sentinel-x.exe` ถูกคอมไพล์เสร็จสมบูรณ์ตั้งแต่ต้นทางทุกครั้งที่มีการออก Patch
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 23/23 tests (`OK`)
  - `python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown` -> `PASSED` (`0 findings`)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อมรัน `scripts/release_patch.py` เพื่อออก Patch `v0.1.1`, คอมไพล์ `dist/sentinel-x.exe`, และ Push ขึ้น GitHub

---

## [2026-11-07] — PHASE 11 (OFFICIAL SENTINEL-X WEBSITE FOR VERCEL DEPLOYMENT)

- **งานที่ทำเสร็จ:**
  - พัฒนาหน้าเว็บ **Official Sentinel-X Website** ในโฟลเดอร์ `public/` (`public/index.html`, `public/styles.css`, `public/app.js`, `public/version.json`) พร้อมไฟล์ตั้งค่า `vercel.json` ที่ระดับ Root เพื่อให้สามารถเชื่อมต่อ GitHub Repository `lastmy2557-png/Sentinel-X` เข้ากับ **Vercel** และ Deploy ได้ทันทีโดยไม่ต้องตั้งค่าเพิ่ม (Zero-Config)
  - ออกแบบหน้าเว็บด้วย Vanilla HTML/CSS/JS โทนสี Obsidian Slate แบบมืออาชีพสำหรับระบบ Cybersecurity & SOC พร้อมฟีเจอร์:
    1. **Quick-Start Interactive Terminal:** สลับดูคำสั่งรัน `Windows (.exe)`, `Python CLI`, `Docker (GHCR)`, และ `Anti-REA Sign` พร้อมปุ่มคัดลอกคำสั่ง
    2. **Interactive Threat Detection & MITRE ATT&CK Simulator:** จำลองการประมวลผล Raw Log (SSH Brute Force `T1110.001`, Sudo Escalation `T1548.003`, Web Shell Upload `T1505.003`, Reverse Shell `T1059.004` หรือพิมพ์ Log เอง) ให้เห็นผลลัพธ์ `NormalizedSecurityEvent` และ `Alert` แบบเรียลไทม์
    3. **Direct Download & Integrity Center:** ปุ่มดาวน์โหลด `/downloads/sentinel-x.exe` และ `/downloads/latest.patch` ที่เชื่อมตรงกับไฟล์ล่าสุดบน GitHub พร้อมแสดงค่า SHA-256 Checksum
  - อัปเดต `scripts/release_patch.py` ให้ซิงค์เลขเวอร์ชันและค่า SHA-256 ลงใน `public/version.json` และ `public/index.html` โดยอัตโนมัติทุกครั้งที่รัน
- **ไฟล์ที่เปลี่ยนแปลง:**
  - สร้างใหม่: `public/index.html`, `public/styles.css`, `public/app.js`, `public/version.json`, `vercel.json`, `patches/v0.1.2.patch`
  - แก้ไข: `scripts/release_patch.py`, `tests/test_api_settings_and_release_pkg.py`, `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - กำหนด `"framework": null`, `"buildCommand": ""`, และ `"outputDirectory": "public"` ใน `vercel.json` เพื่อไม่ให้ Vercel สับสนกับ `pyproject.toml` ของฝั่ง Python CLI และให้เสิร์ฟหน้าเว็บ Official จากโฟลเดอร์ `public/` ได้อย่างรวดเร็วผ่าน Vercel Edge Network
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 24/24 tests (`OK`)
  - `python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown` -> `PASSED` (`0 findings`)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อมรัน `scripts/release_patch.py` เพื่อออก Patch `v0.1.2`, คอมไพล์ `dist/sentinel-x.exe` ใหม่ และ Push ขึ้น GitHub

---

## [2026-11-07] — PHASE 12 (FULL INTERACTIVE MULTI-TAB WEB CONSOLE ON VERCEL `v0.1.3`)

- **งานที่ทำเสร็จ:**
  - อัปเกรดหน้าเว็บ Official บน Vercel (`https://sentinel-x-weld-tau.vercel.app/`) ให้สามารถสลับและใช้งานได้จริงครบทุกแท็บ:
    1. **แท็บ `แสดงทุกแท็บ (All)` & `ภาพรวม (Overview)`:** หน้าหลักพร้อม Quick-Start Terminal 4 โหมด และปุ่มคัดลอกคำสั่ง/SHA-256
    2. **แท็บ `SOC Dashboard & เคส`:** คอนโซลนำเข้า Raw Logs หลายบรรทัด, แปลงเป็น `NormalizedSecurityEvent`, ประมวลผลกฎตรวจจับ MITRE ATT&CK, กรอง/ค้นหารายการแจ้งเตือน, เปลี่ยนสถานะเคส Incident, เพิ่มบันทึกการสอบสวน และดาวน์โหลดรายงานจริง (`.json`, `.md`, `.html`)
    3. **แท็บ `ทดลองตรวจจับ (Live Simulator)`:** จำลองการโจมตี 6 รูปแบบพร้อมส่งเข้า SOC Dashboard, สตูดิโอแก้ไขและลงทะเบียนกฎ **Sigma YAML** และตารางสำรวจฐานข้อมูลทางการ **MITRE ATT&CK**
    4. **แท็บ `สถาปัตยกรรม SOC`:** แสดงรายละเอียด 6 โมดูลหลักพร้อมปุ่มกดเชื่อมไปยังหน้าคอนโซลของแต่ละโมดูลโดยตรง
    5. **แท็บ `การเชื่อมต่อ API ภายนอก (/settings)`:** ฟอร์มตั้งค่าจริงครบทั้ง 5 บริการ (`siem_forwarder`, `edr_controller`, `threat_intel_feed`, `webhook_notifier`, `external_security_tool`) พร้อมระบบซ่อน API Key (`••••••••xxxx`), ปุ่มบันทึก, ปุ่มทดสอบการเชื่อมต่อ, ปุ่มดูตัวอย่าง Payload และปุ่มเติมค่าตัวอย่าง
    6. **แท็บ `Anti-REA Release Protection`:** เครื่องมือสแกนโค้ดหาความลับรั่วไหล/ช่องโหว่ก่อนปล่อยซอฟต์แวร์ (ดาวน์โหลดรายงาน `.md` ได้) และสตูดิโอจำลองการลงนามดิจิทัล `Ed25519` พร้อมปุ่มจำลองการแอบแก้ไขไฟล์ (`TAMPER_DETECTED`)
    7. **แท็บ `ดาวน์โหลด & Patch`:** ปุ่มดาวน์โหลดตรง `/downloads/sentinel-x.exe`, `/downloads/latest.patch`, `/downloads/SHA256SUMS.txt`, เครื่องมือคำนวณและตรวจสอบค่า `SHA-256` ของไฟล์ในเบราว์เซอร์ (`WebCrypto SHA-256`) และหน้าต่างดูเนื้อหาไฟล์ `latest.patch` คู่กับประวัติใน `PATCH_MANIFEST.json`
- **ไฟล์ที่เปลี่ยนแปลง:**
  - แก้ไข/สร้างใหม่: `public/index.html`, `public/styles.css`, `public/app.js`, `public/version.json`, `public/downloads/*`, `public/patches/*`, `vercel.json`, `scripts/release_patch.py`, `sentinel_x/security/release_protection/scanner.py`, `tests/test_api_settings_and_release_pkg.py`, `patches/v0.1.3.patch`
  - อัปเดต: `ARCHITECTURE.md`, `PROJECT_STATE.md`, `TODO.md`, `PROCESS.md`, `DEVELOPMENT_LOG.md`
- **การตัดสินใจทางเทคนิค:**
  - ให้ `scripts/release_patch.py` คัดลอก `sentinel-x.exe`, `SHA256SUMS.txt`, `latest.patch`, และ `PATCH_MANIFEST.json` ลงใน `public/downloads/` และ `public/patches/` โดยอัตโนมัติ เพื่อให้ Vercel เสิร์ฟไฟล์ดาวน์โหลดและแสดงผลเนื้อหา Patch จาก CDN เดียวกันโดยไม่ติด CORS
- **Tests ที่รันและผลการทดสอบ:**
  - `python3 -m unittest discover -s tests -p "test_*.py" -v` -> ผ่าน 24/24 tests (`OK`)
  - `python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown` -> `PASSED` (`0 findings`)
- **ปัญหาที่พบ:**
  - ไม่มี พร้อมรัน `scripts/release_patch.py` เพื่อออก Patch `v0.1.3`, คอมไพล์ `dist/sentinel-x.exe` ใหม่ และ Push ขึ้น GitHub เพื่อให้ Vercel อัปเดต `https://sentinel-x-weld-tau.vercel.app/` อัตโนมัติ
