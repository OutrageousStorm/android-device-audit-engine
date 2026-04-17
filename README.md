# 🔎 Android Device Audit Engine

Run a complete security audit on your Android device and generate a detailed HTML/JSON report.

## Usage
```bash
python3 audit.py
# Creates: audit_report.html + audit_report.json
```

## What it checks
- ✅ Bootloader verification status
- ✅ Root detection (su binary)
- ✅ Full-disk encryption
- ✅ Developer options
- ✅ USB debugging
- ✅ SELinux enforcement
- ✅ Location services
- ✅ Ad tracking settings
- ✅ Suspicious app detection (Facebook, Instagram, TikTok, etc.)
- ✅ Dangerous permissions granted

## Requirements
```bash
adb devices  # device connected
```
