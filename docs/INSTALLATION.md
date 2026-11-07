# คู่มือการติดตั้ง Sentinel-X (`docs/INSTALLATION.md`)

## 1. ความต้องการของระบบ (System Requirements)
- **Operating System:** Linux (Debian/Ubuntu หรือเทียบเท่า), macOS, หรือ Windows (WSL2)
- **Python:** เวอร์ชัน `3.11` ขึ้นไป (ใช้ Standard Library ของ Python 3.11+ เป็นหลักเพื่อลดความเสี่ยงด้าน Supply Chain)
- **OpenSSL:** เวอร์ชัน `3.0` ขึ้นไป (สำหรับการสร้างและตรวจสอบลายเซ็นดิจิทัล `Ed25519` ในโมดูล Anti-REA)
- **Git:** เวอร์ชัน `2.30` ขึ้นไป

---

## 2. ขั้นตอนการติดตั้ง (Installation Steps)

### 2.1 ตรวจสอบเครื่องมือในระบบ
```bash
python3 --version
openssl version
git --version
```

### 2.2 ตั้งค่าไฟล์ Environment เบื้องต้น
คัดลอกไฟล์ `.env.example` ไปเป็น `.env` (ไฟล์ `.env` ถูกกำหนดไว้ใน `.gitignore` แล้วและจะไม่ถูก Commit ขึ้น Git):
```bash
cp .env.example .env
```

### 2.3 ติดตั้งแพ็กเกจแบบ Editable (ทางเลือก)
คุณสามารถรันผ่าน `python3 -m sentinel_x.cli` ได้ทันทีโดยไม่ต้องติดตั้งแพ็กเกจเพิ่มเติม หรือติดตั้งใน Virtual Environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## 3. การตรวจสอบหลังติดตั้ง (Post-Installation Verification)

### 3.1 รันชุดทดสอบทั้งหมด (Unit & Integration Tests)
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### 3.2 รันการตรวจสอบความปลอดภัยของโปรเจกต์ด้วย Anti-REA
```bash
python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown
```
