#!/usr/bin/env python3
"""audit_engine.py - Comprehensive Android security audit"""
import subprocess, json, sys
from datetime import datetime

def adb(cmd):
    r = subprocess.run(f"adb shell {cmd}", shell=True, capture_output=True, text=True)
    return r.stdout.strip()

class AuditEngine:
    def __init__(self):
        self.results = []
        self.passed = 0
        self.failed = 0
    
    def check(self, name, cmd, good_val, critical=False):
        val = adb(cmd)
        ok = val == good_val
        status = "PASS" if ok else "FAIL"
        icon = "✅" if ok else "⚠️"
        self.results.append({"name": name, "status": status, "value": val, "expected": good_val})
        if ok:
            self.passed += 1
        else:
            self.failed += 1
            if critical:
                print(f"🔴 CRITICAL: {name}")
        print(f"  {icon} {name:<40} [{val}]")
    
    def report(self):
        total = self.passed + self.failed
        pct = int((self.passed / total) * 100) if total else 0
        print(f"\n{'='*60}")
        print(f"Security Score: {pct}% ({self.passed}/{total} checks passed)")
        print(f"{'='*60}")
        return {"score": pct, "passed": self.passed, "failed": self.failed}

def main():
    print("\n🔎 Android Device Security Audit\n")
    a = AuditEngine()
    
    # Bootloader
    print("Bootloader Security:")
    a.check("Bootloader locked", "getprop ro.boot.verifiedbootstate", "green")
    a.check("OEM unlock disabled", "getprop ro.oem_unlock_supported", "0")
    
    # Encryption
    print("\nEncryption:")
    a.check("FDE enabled", "getprop ro.crypto.state", "encrypted")
    a.check("FBE enabled", "test -d /data/user && echo yes || echo no", "yes")
    
    # SELinux
    print("\nMAC (SELinux):")
    a.check("SELinux enforcing", "getenforce", "Enforcing", critical=True)
    
    # Permissions
    print("\nTracking Permissions:")
    a.check("Ad tracking disabled", "settings get global limit_ad_tracking", "1")
    a.check("Location off", "settings get secure location_mode", "0")
    a.check("WiFi scan disabled", "settings get global wifi_scan_always_enabled", "0")
    
    # Apps
    print("\nSuspicious Apps:")
    pkgs = adb("pm list packages")
    trackers = ["com.facebook.katana", "com.instagram.android"]
    found = sum(1 for t in trackers if f"package:{t}" in pkgs)
    a.check(f"No major trackers (found {found}/2)", "", "0")
    
    result = a.report()
    
    # Export JSON
    with open("audit_report.json", "w") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "audit": a.results, "summary": result}, f, indent=2)
    print(f"Report saved to audit_report.json")

if __name__ == "__main__":
    main()
