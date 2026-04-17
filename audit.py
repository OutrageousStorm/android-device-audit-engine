#!/usr/bin/env python3
"""
audit.py -- Comprehensive Android device and app security audit
Generates JSON and HTML reports with security findings.
Usage: python3 audit.py [--output report.html] [--apps-only]
"""
import subprocess, json, sys, re, html
from datetime import datetime
from pathlib import Path

def adb(cmd):
    r = subprocess.run(f"adb shell {cmd}", shell=True, capture_output=True, text=True)
    return r.stdout.strip()

class AndroidAuditor:
    def __init__(self):
        self.findings = []
        self.device_info = {}
        self.apps = []

    def audit_device(self):
        """Core device security checks"""
        print("[*] Auditing device...")
        
        # Bootloader status
        bl = adb("getprop ro.boot.verifiedbootstate")
        if bl != "green":
            self.findings.append({
                "severity": "HIGH",
                "category": "Boot Security",
                "title": f"Bootloader not verified",
                "description": f"Verified boot state: {bl}. Device may be modified.",
                "remediation": "Keep bootloader locked or verify integrity."
            })
        
        # Root detection
        has_su = bool(adb("which su 2>/dev/null"))
        if has_su:
            self.findings.append({
                "severity": "CRITICAL",
                "category": "Root Access",
                "title": "Device is rooted",
                "description": "su binary detected. Full system compromise possible.",
                "remediation": "Remove root or accept the security implications."
            })
        
        # Encryption
        enc = adb("getprop ro.crypto.state")
        if enc != "encrypted":
            self.findings.append({
                "severity": "CRITICAL",
                "category": "Encryption",
                "title": "Device not encrypted",
                "description": "Full-disk encryption not enabled. Data at risk.",
                "remediation": "Enable encryption in Settings > Security."
            })
        
        # Developer options
        dev = adb("settings get global development_settings_enabled")
        if dev == "1":
            self.findings.append({
                "severity": "HIGH",
                "category": "Developer Settings",
                "title": "Developer options enabled",
                "description": "USB debugging and advanced options are on.",
                "remediation": "Disable in Settings > Developer options."
            })
        
        # ADB enabled
        adb_en = adb("settings get global adb_enabled")
        if adb_en == "1":
            self.findings.append({
                "severity": "MEDIUM",
                "category": "ADB",
                "title": "USB debugging enabled",
                "description": "ADB is accessible. Only enable when needed.",
                "remediation": "Disable USB debugging when not in use."
            })
        
        # SELinux
        se = adb("getenforce 2>/dev/null")
        if se != "Enforcing":
            self.findings.append({
                "severity": "HIGH",
                "category": "SELinux",
                "title": f"SELinux not enforcing: {se}",
                "description": "Mandatory access control is disabled.",
                "remediation": "Enable SELinux enforcement via Settings or system config."
            })
        
        # Location
        loc = adb("settings get secure location_mode")
        if loc != "0":
            self.findings.append({
                "severity": "MEDIUM",
                "category": "Location",
                "title": "Location services enabled",
                "description": f"Location mode: {loc}. Apps can track you.",
                "remediation": "Turn off location or use GPS-only mode."
            })
        
        # Ad tracking
        ad_track = adb("settings get global limit_ad_tracking")
        if ad_track != "1":
            self.findings.append({
                "severity": "LOW",
                "category": "Privacy",
                "title": "Ad tracking not limited",
                "description": "Advertising ID tracking is enabled.",
                "remediation": "Enable 'Limit ad tracking' in Settings > Privacy."
            })
        
        self.device_info = {
            "model": adb("getprop ro.product.model"),
            "android": adb("getprop ro.build.version.release"),
            "api": adb("getprop ro.build.version.sdk"),
            "security_patch": adb("getprop ro.build.version.security_patch"),
            "bootloader": bl,
            "encryption": enc,
            "selinux": se,
        }

    def audit_apps(self):
        """Check installed apps for suspicious permissions"""
        print("[*] Auditing installed apps...")
        pkgs = adb("pm list packages -3")
        apps = [p.split(":")[1] for p in pkgs.splitlines() if p.startswith("package:")]
        
        dangerous_perms = [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
        ]
        
        suspicious_packages = [
            ("com.facebook.katana", "Facebook — known for extensive tracking"),
            ("com.instagram.android", "Instagram — data collection"),
            ("com.twitter.android", "Twitter — location tracking"),
            ("com.zhiliaoapp.musically", "TikTok — Chinese data exfiltration"),
        ]
        
        for pkg, reason in suspicious_packages:
            if pkg in apps:
                perms = adb(f"dumpsys package {pkg} | grep 'granted=true'")
                severity = "CRITICAL" if "FINE_LOCATION" in perms else "HIGH"
                self.findings.append({
                    "severity": severity,
                    "category": "Suspicious App",
                    "title": f"{pkg.split('.')[-1]} detected",
                    "description": reason,
                    "remediation": "Uninstall or use an alternative."
                })

    def generate_report(self):
        """Generate JSON + HTML report"""
        timestamp = datetime.now().isoformat()
        
        # Count by severity
        by_sev = {}
        for f in self.findings:
            sev = f["severity"]
            by_sev[sev] = by_sev.get(sev, 0) + 1
        
        report = {
            "timestamp": timestamp,
            "device": self.device_info,
            "findings": self.findings,
            "summary": {
                "total": len(self.findings),
                "critical": by_sev.get("CRITICAL", 0),
                "high": by_sev.get("HIGH", 0),
                "medium": by_sev.get("MEDIUM", 0),
                "low": by_sev.get("LOW", 0),
            }
        }
        
        return report

    def to_html(self, report):
        """Convert report to HTML"""
        sev_colors = {
            "CRITICAL": "#ff4444", "HIGH": "#ff9800",
            "MEDIUM": "#ffc107", "LOW": "#4caf50"
        }
        
        findings_html = ""
        for f in report["findings"]:
            color = sev_colors.get(f["severity"], "#999")
            findings_html += f'''
            <div class="finding" style="border-left: 4px solid {color}; padding: 15px; margin: 10px 0; background: #f5f5f5;">
                <h4 style="margin: 0 0 5px 0; color: {color};">{f["severity"]} — {f["category"]}</h4>
                <b>{html.escape(f["title"])}</b><br>
                <p style="margin: 5px 0 0 0; color: #666;">{html.escape(f["description"])}</p>
                <p style="margin: 5px 0 0 0; color: #4caf50; font-size: 0.9em;"><b>Remediation:</b> {html.escape(f["remediation"])}</p>
            </div>
            '''
        
        html_template = f'''<!DOCTYPE html>
<html>
<head>
    <title>Android Security Audit Report</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; background: #f0f0f0; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }}
        .stat {{ padding: 15px; border-radius: 4px; text-align: center; color: white; font-weight: bold; }}
        .stat.critical {{ background: #ff4444; }}
        .stat.high {{ background: #ff9800; }}
        .stat.medium {{ background: #ffc107; color: black; }}
        .stat.low {{ background: #4caf50; }}
        .device-info {{ background: #f9f9f9; padding: 15px; border-radius: 4px; margin: 20px 0; }}
        .device-info p {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Android Security Audit Report</h1>
        <p><small>Generated: {report["timestamp"]}</small></p>
        
        <div class="summary">
            <div class="stat critical">CRITICAL<br>{report["summary"]["critical"]}</div>
            <div class="stat high">HIGH<br>{report["summary"]["high"]}</div>
            <div class="stat medium">MEDIUM<br>{report["summary"]["medium"]}</div>
            <div class="stat low">LOW<br>{report["summary"]["low"]}</div>
        </div>
        
        <div class="device-info">
            <h3>Device Information</h3>
            <p><b>Model:</b> {report["device"]["model"]}</p>
            <p><b>Android:</b> {report["device"]["android"]} (API {report["device"]["api"]})</p>
            <p><b>Security Patch:</b> {report["device"]["security_patch"]}</p>
            <p><b>Encryption:</b> {report["device"]["encryption"]}</p>
            <p><b>SELinux:</b> {report["device"]["selinux"]}</p>
        </div>
        
        <h3>Findings ({report["summary"]["total"]} total)</h3>
        {findings_html}
        
        <p style="font-size: 0.85em; color: #999; margin-top: 40px;">
            Report generated by Android Device Audit Engine
        </p>
    </div>
</body>
</html>
'''
        return html_template

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="audit_report.html")
    parser.add_argument("--apps-only", action="store_true")
    args = parser.parse_args()
    
    auditor = AndroidAuditor()
    if not args.apps_only:
        auditor.audit_device()
    auditor.audit_apps()
    
    report = auditor.generate_report()
    
    # Save JSON
    json_path = args.output.replace(".html", ".json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"✓ JSON report: {json_path}")
    
    # Save HTML
    html_content = auditor.to_html(report)
    with open(args.output, "w") as f:
        f.write(html_content)
    print(f"✓ HTML report: {args.output}")
    
    # Print summary
    print(f"\nFindings: {report['summary']['total']}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = report['summary'][sev.lower()]
        if count > 0:
            print(f"  {sev}: {count}")

if __name__ == "__main__":
    main()
