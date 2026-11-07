# Sentinel-X — Cybersecurity & SOC Platform

**Sentinel-X** คือแพลตฟอร์ม Cybersecurity และ Security Operations Center (SOC) แบบ **Local-first, Modular Architecture** ที่พัฒนาด้วย Python 3.11+ สำหรับรวบรวม วิเคราะห์ ตรวจจับภัยคุกคาม (พร้อมเชื่อมโยงฐานข้อมูลทางการของ **MITRE ATT&CK**) จัดการเหตุการณ์ด้านความปลอดภัย (Incident Response) และตรวจสอบความสมบูรณ์ของซอฟต์แวร์ด้วยโมดูลแยกอิสระ **Anti-REA (`release_protection`)**

---

## ความสามารถหลัก (Key Capabilities)

1. **Security Log Management (`sentinel_x/ingestion/`):**
   - รองรับการ Ingest, Parse, และ Normalize ข้อมูล Log หลายรูปแบบ (JSON, Syslog RFC3164/ISO, Linux Auth/SSH/Sudo, Apache/Nginx Web Access)
   - ออกแบบด้วย `LogParserRegistry` ให้เพิ่มรูปแบบ Log ใหม่ได้โดยไม่กระทบส่วนอื่น
   - รองรับการค้นหา กรองข้อมูล และทำ **Event Correlation** ตาม `source_ip`, `user`, หรือ `source_host`
   - ป้องกัน Path Traversal และจำกัดขนาดไฟล์สูงสุด
2. **Threat Detection Engine & MITRE ATT&CK (`sentinel_x/detection/`):**
   - รองรับทั้งกฎแบบ **Single-event Matching** และ **Time-window Correlation** (เช่น การตรวจจับ SSH Brute Force)
   - เชื่อมโยงกับ **Official MITRE ATT&CK** (`Technique ID`, `Technique Name`, `Tactic`) พร้อมคำอธิบาย (`Explanation`) และหลักฐาน (`Event Evidence`)
   - รองรับการเปิด/ปิด โหลดกฎจาก JSON และทดสอบกฎแบบ Dry-run (`test_rule`)
3. **Incident Management & Reporting (`sentinel_x/incidents/`, `sentinel_x/reporting/`):**
   - จัดการสถานะ Incident (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`), ระดับความรุนแรง (`Severity`), บันทึก `Investigation Notes`, ผูก Events/Alerts และสร้าง `Incident Timeline` อัตโนมัติ
   - ส่งออกรายงานในรูปแบบ **JSON**, **Markdown**, และ **HTML** (พร้อมการทำ HTML Escaping ป้องกัน XSS)
4. **Security Dashboard & External API Settings UI (`sentinel_x/dashboard/`, `sentinel_x/integrations/`):**
   - แสดงข้อมูลจริงจากฐานข้อมูล SQLite ท้องถิ่น และแยกข้อมูลตัวอย่าง (`is_sample`) ออกจากข้อมูลจริงอย่างชัดเจน
   - มาพร้อมหน้า **ตั้งค่าการเชื่อมต่อ API ภายนอก (`http://127.0.0.1:8080/settings`)** และ REST API (`/api/v1/settings/connectors`, `/api/v1/settings/connectors/test`) สำหรับตั้งค่าและทดสอบการเชื่อมต่อกับบริการที่ลูกค้าใช้งานจริง ได้แก่:
     1. **SIEM Platform Forwarder** (Splunk HEC, Elastic SIEM, Microsoft Sentinel, IBM QRadar)
     2. **EDR Endpoint Controller** (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne)
     3. **Threat Intelligence Feed** (VirusTotal, AbuseIPDB, MISP, AlienVault OTX)
     4. **Webhook / ChatOps Alert Notifier** (Slack, Microsoft Teams, Discord, PagerDuty)
     5. **External Security Tool / SOAR** (TheHive, Cortex XSOAR, Jira Service Management)
   - บันทึกการตั้งค่าลง SQLite (`connector_settings`) อย่างปลอดภัย พร้อม **Secret Masking** (ไม่เปิดเผย API Key ตัวเต็มกลับไปที่หน้าเว็บหรือ API Response)
5. **Anti-REA / Release Protection (`sentinel_x/security/release_protection/`):**
   - โมดูลแยกอิสระสำหรับ **Tamper Detection**, **Release Integrity Verification**, **Build Hardening**, และ **Sensitive Artifact Exposure Reduction**
   - สร้าง **SHA-256 File Inventory** และลงนาม/ตรวจสอบ **Signed Release Manifest** ด้วยลายเซ็นดิจิทัลมาตรฐาน **RFC 8032 Ed25519 / RFC 8410 PEM** (รองรับทั้ง Pure-Python ในตัวและ OpenSSL 3.0 โดยใช้ External Key เท่านั้น)
   - สแกนหา Secrets, Sensitive Files, Debug Artifacts, Source Maps และการตั้งค่า Build ที่ไม่ปลอดภัย

> **ข้อจำกัดด้านความปลอดภัยตามความเป็นจริง:**
> ไม่มีซอฟต์แวร์ใดสามารถรับประกันการป้องกัน Reverse Engineering ได้ 100% โมดูล Anti-REA มุ่งเน้นการตรวจจับการแก้ไขไฟล์โดยไม่ได้รับอนุญาต (Tamper Detection), การยืนยันความถูกต้องของ Release Manifest ด้วยลายเซ็นดิจิทัล และการลดการเปิดเผยข้อมูลอ่อนไหว

---

## การเริ่มต้นใช้งานอย่างรวดเร็ว (Quick Start)

### 1. รันชุดทดสอบทั้งหมด (Unit & Integration Tests)
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### 2. ทดสอบ Ingest ข้อมูลตัวอย่าง, เปิด SOC Dashboard และหน้าตั้งค่า API (`/settings`)
```bash
# Ingest ไฟล์ Log ตัวอย่าง (ระบุ --sample อย่างชัดเจน)
python3 -m sentinel_x.cli ingest --file data/samples/sample_security.log --sample

# แสดงข้อมูลสรุป SOC Dashboard
python3 -m sentinel_x.cli summary

# แสดงรายการ Alerts ที่ตรวจพบพร้อม MITRE ATT&CK
python3 -m sentinel_x.cli alerts

# เปิดใช้งาน Local-first Security Dashboard และหน้าตั้งค่า API ภายนอก
# - SOC Dashboard:       http://127.0.0.1:8080/
# - ตั้งค่า API ภายนอก:   http://127.0.0.1:8080/settings
python3 -m sentinel_x.cli serve --host 127.0.0.1 --port 8080
```

### 3. การใช้งาน Release Protection CLI (Anti-REA)
```bash
# รันการตรวจสอบความปลอดภัยของโปรเจกต์ (Secret Scan, Sensitive Files, Build Config)
python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown

# สร้างกุญแจ Ed25519 ไว้นอกโฟลเดอร์ Repository
python3 -m sentinel_x.security.release_protection.cli keygen \
  --private-key /tmp/sentinel_release.key \
  --public-key /tmp/sentinel_release_public.pem

# สร้างและลงนาม Release Manifest
python3 -m sentinel_x.security.release_protection.cli sign \
  --root . \
  --private-key /tmp/sentinel_release.key \
  --output /tmp/release_manifest.json

# ตรวจสอบลายเซ็นดิจิทัลและความสมบูรณ์ของไฟล์ (Tamper Detection)
python3 -m sentinel_x.security.release_protection.cli verify \
  --root . \
  --manifest /tmp/release_manifest.json \
  --public-key /tmp/sentinel_release_public.pem
```

### 4. การอัปเดต Patch และใช้งานไฟล์ `dist\sentinel-x.exe` ที่คอมไพล์เสร็จแล้วบน Windows
ทุกครั้งที่มีการอัปเดตโค้ด ระบบจะสร้างไฟล์ `.patch` ในโฟลเดอร์ `patches/` และคอมไพล์ไฟล์ `dist\sentinel-x.exe` ให้เสร็จสมบูรณ์พร้อมใช้งานทันที:
```bat
REM วิธีที่ 1: รันสคริปต์อัปเดต Patch และตรวจรับไฟล์ dist\sentinel-x.exe ล่าสุดแบบคลิกเดียว
scripts\apply_patch_windows.bat

REM วิธีที่ 2: หรือใช้ git pull แล้วรันไฟล์ dist\sentinel-x.exe ที่คอมไพล์เสร็จแล้วได้ทันที (ไม่ต้องคอมไพล์ใหม่เอง)
git pull origin main
dist\sentinel-x.exe --version
dist\sentinel-x.exe serve --host 127.0.0.1 --port 8080
```

### 5. การสร้าง Patch, คอมไพล์ `.exe` และอัปเดตเวอร์ชันขึ้น GitHub อัตโนมัติ (`scripts/release_patch.py`)
```bash
# ปรับเลขเวอร์ชัน (เช่น 0.1.0 -> 0.1.1), สร้างไฟล์ patches/v0.1.1.patch, คอมไพล์ dist/sentinel-x.exe และ Push ขึ้น GitHub
python3 scripts/release_patch.py --bump patch --summary "คำอธิบายการอัปเดต" --commit-and-push
```

---

## เอกสารประกอบ (Documentation)
- [สถาปัตยกรรมระบบ (`ARCHITECTURE.md`)](ARCHITECTURE.md)
- [คู่มือการติดตั้ง (`docs/INSTALLATION.md`)](docs/INSTALLATION.md)
- [คู่มือการตั้งค่า (`docs/CONFIGURATION.md`)](docs/CONFIGURATION.md)
- [นโยบายและสถาปัตยกรรมความปลอดภัย (`docs/SECURITY.md`)](docs/SECURITY.md)
- [สถานะโปรเจกต์ (`PROJECT_STATE.md`)](PROJECT_STATE.md)
- [รายการติดตามงาน (`TODO.md`)](TODO.md)
- [บันทึกสถานะต่อเนื่อง (`PROCESS.md`)](PROCESS.md)
- [บันทึกการพัฒนา (`DEVELOPMENT_LOG.md`)](DEVELOPMENT_LOG.md)
