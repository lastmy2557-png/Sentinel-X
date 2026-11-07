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

---

## 4. การคอมไพล์เป็นไฟล์ `.exe` สำหรับ Windows (Standalone Executable Build)

คุณสามารถคอมไพล์ **Sentinel-X** ให้เป็นไฟล์ `.exe` แบบไฟล์เดียว (`dist\sentinel-x.exe`) บนเครื่อง Windows ได้โดยไม่ต้องติดตั้ง Python ในเครื่องปลายทางที่นำไปรัน:

### 4.1 วิธีที่ 1: รันสคริปต์อัตโนมัติ (One-Click Build บน Windows)
ดับเบิลคลิกหรือรันไฟล์ `scripts\build_windows.bat` ใน Command Prompt หรือ PowerShell:
```bat
scripts\build_windows.bat
```
สคริปต์จะดำเนินการอัตโนมัติครบทุกขั้นตอน:
1. สร้าง Virtual Environment (`.venv`) และติดตั้ง `pyinstaller` + `pyyaml`
2. รันชุดทดสอบ Unit & Integration Tests ทั้งหมด
3. รันการตรวจสอบความปลอดภัยด้วย **Anti-REA Security Audit** ก่อนเริ่ม Build
4. คอมไพล์เป็นไฟล์ `dist\sentinel-x.exe` พร้อมสร้างไฟล์ตรวจสอบความสมบูรณ์ `dist\sentinel-x.exe.sha256` และ `dist\build_manifest.json`

### 4.2 วิธีที่ 2: รันผ่าน Python Build Script โดยตรง
```bash
# ทดสอบคำสั่งและตรวจความปลอดภัยก่อน Build จริง (Dry-run)
python scripts/build_exe.py --dry-run

# คอมไพล์เป็นไฟล์ Executable จริง
pip install pyinstaller pyyaml
python scripts/build_exe.py
```

### 4.3 การใช้งานไฟล์ `dist\sentinel-x.exe`
- **ดับเบิลคลิก `sentinel-x.exe` โดยตรง:** เปิดใช้งาน Local Security Dashboard บน `http://127.0.0.1:8080` ทันที
- **รันผ่าน Command Prompt / PowerShell:**
  ```bat
  dist\sentinel-x.exe summary
  dist\sentinel-x.exe ingest --file data\samples\sample_security.log --sample
  dist\sentinel-x.exe release-protection audit --root . --format markdown
  ```
