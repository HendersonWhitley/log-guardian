from collections import defaultdict
import json
import argparse
from pathlib import Path
from datetime import datetime

# ========= Banner =========
def banner():
    print("""
╔════════════════════════════╗
║        LOG GUARDIAN        ║
║   Suspicious Log Analyzer  ║
╚════════════════════════════╝
""")

# ========= Colors =========
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

# ========= Keywords =========
SUSPICIOUS_KEYWORDS = [
    "Failed password",
    "login failed",
    "/etc/passwd",
    "curl",
    "| sh"
]

# ========= Core Logic =========
def analyze_log(log_path, output_dir):
    failed_ip_counts = defaultdict(int)
    alerts = []

    with open(log_path, "r") as file:
        for line in file:

            # 1️⃣ Keyword alerts
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in line:

                    if keyword in ["Failed password", "login failed"]:
                        level = "WARNING"
                        color = YELLOW
                    elif keyword in ["/etc/passwd", "curl", "| sh"]:
                        level = "CRITICAL"
                        color = RED
                    else:
                        level = "INFO"
                        color = GREEN

                    print(
                        f"{color}[{datetime.now().strftime('%H:%M:%S')}] ⚠ {level}:{RESET} {line.strip()}"
                    )

                    alert_obj = {
                        "type": keyword,
                        "raw": line.strip()
                    }
                    alerts.append(alert_obj)

            # 2️⃣ Brute force tracking
            if "Failed password" in line or "login failed" in line:
                ip = None

                if "ip=" in line:
                    ip = line.split("ip=")[-1].strip()
                elif "from " in line:
                    ip = line.split("from ")[-1].strip()

                if ip:
                    failed_ip_counts[ip] += 1

    # 3️⃣ Brute force summary
    print("\n🔥 Brute force summary:")
    for ip, count in failed_ip_counts.items():
        if count >= 3:
            summary = f"Possible brute force from {ip} ({count} failures)"
            print(f"{RED}🔥 {summary}{RESET}")
            alerts.append(summary)

    # 4️⃣ Save reports
    output_dir.mkdir(exist_ok=True)

    with open(output_dir / "report.txt", "w") as report:
        for alert in alerts:
            report.write(str(alert) + "\n")

    with open(output_dir / "report.json", "w") as json_report:
        json.dump(alerts, json_report, indent=4)

    print("\n✅ Reports saved to output/")

# ========= CLI =========
def main():
    banner()

    parser = argparse.ArgumentParser(description="Log Guardian — Suspicious log analyzer")
    parser.add_argument("-f", "--file", default="data/sample.log", help="Log file to analyze")
    parser.add_argument("-o", "--output", default="output", help="Output directory")

    args = parser.parse_args()

    log_path = Path(args.file)
    output_dir = Path(args.output)

    analyze_log(log_path, output_dir)

if __name__ == "__main__":
    main()
