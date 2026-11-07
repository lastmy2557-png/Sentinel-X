# คู่มือการตั้งค่า Sentinel-X (`docs/CONFIGURATION.md`)

## 1. การตั้งค่าผ่าน Environment Variables (`.env`)

Sentinel-X อ่านค่าการตั้งค่าผ่าน `sentinel_x/core/config.py` โดยตรวจสอบความถูกต้องทุกค่าก่อนเริ่มทำงาน และจะไม่ถือว่าค่าที่เป็น Placeholder (`CHANGE_ME`, `PLACEHOLDER`) เป็นข้อมูลรับรองจริง

| ตัวแปร (Environment Variable) | ค่าเริ่มต้น (Default) | คำอธิบาย |
| :--- | :--- | :--- |
| `SENTINEL_ENV` | `development` | โหมดการทำงาน (`development`, `testing`, `production`) |
| `SENTINEL_DB_PATH` | `data/runtime/sentinel_x.db` | ตำแหน่งไฟล์ฐานข้อมูล SQLite ท้องถิ่น |
| `SENTINEL_LOG_LEVEL` | `INFO` | ระดับการบันทึก Log (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `SENTINEL_AUDIT_LOG_PATH` | `logs/audit.log` | ตำแหน่งไฟล์ Security Audit Log (JSON Lines) |
| `SENTINEL_MAX_INGEST_FILE_BYTES` | `10485760` (10 MB) | ขนาดไฟล์ Log สูงสุดที่อนุญาตให้ Ingest ต่อไฟล์ |
| `SENTINEL_ALLOWED_INGEST_DIR` | `data/samples` | โฟลเดอร์ที่อนุญาตเมื่อเปิดใช้การจำกัดขอบเขตไฟล์ |
| `SENTINEL_HOST` | `127.0.0.1` | IP ที่ผูกกับ Security Dashboard (Local-first เป็นค่าเริ่มต้น) |
| `SENTINEL_PORT` | `8080` | พอร์ตของ Security Dashboard (`1`–`65535`) |
| `SENTINEL_API_TOKEN` | *(ว่าง)* | API Token สำหรับการตรวจสอบสิทธิ์ |
| `SENTINEL_SIEM_ENDPOINT` | *(ว่าง)* | URL ของระบบ SIEM ภายนอก |
| `SENTINEL_SIEM_API_KEY` | *(ว่าง)* | API Key สำหรับเชื่อมต่อระบบ SIEM |
| `SENTINEL_WEBHOOK_URL` | *(ว่าง)* | URL สำหรับส่งการแจ้งเตือน Webhook |
| `SENTINEL_THREAT_INTEL_API_KEY` | *(ว่าง)* | API Key สำหรับ Threat Intelligence |
| `SENTINEL_RELEASE_PRIVATE_KEY_PATH` | *(ว่าง)* | Path ไปยังไฟล์ Private Key (`Ed25519`) ภายนอกสำหรับลงนาม Release Manifest |
| `SENTINEL_RELEASE_PUBLIC_KEY_PATH` | *(ว่าง)* | Path ไปยังไฟล์ Public Key (`Ed25519`) สำหรับตรวจสอบ Release Manifest |

---

## 2. การจัดการกฎการตรวจจับ (Detection Rules Configuration)

กฎเริ่มต้นของระบบถูกนิยามไว้ใน `sentinel_x/detection/engine.py` และตัวอย่างไฟล์ JSON ใน `config/rules/default_rules.json`

โครงสร้างของกฎแต่ละข้อประกอบด้วย:
- `rule_id`: รหัสอ้างอิงกฎ (เช่น `SX-DET-001`)
- `name` & `description`: ชื่อและคำอธิบายพร้อมขอบเขตข้อจำกัดของกฎ
- `severity`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `mitre`: ข้อมูลอ้างอิงจากฐานข้อมูลทางการของ MITRE ATT&CK (`technique_id`, `technique_name`, `tactic`)
- `conditions`: เงื่อนไขการตรวจจับ (`category`, `action`, `outcome`, `message_regex`, และ `correlation` สำหรับการตรวจจับแบบ Time-window)
