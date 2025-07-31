import re
from collections import Counter
import csv
import sys

# Load the log file
def parse_log(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()

    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # IPv4 format
    path_pattern = r'GET\s+(/[^\s]*)'     # Extract path after GET

    ip_hits = []
    flagged_entries = []

    SUSPICIOUS_PATHS = ["/admin", "/login", "/etc/passwd", "/wp-login", "/config"]

    for line in lines:
        ip_match = re.search(ip_pattern, line)
        path_match = re.search(path_pattern, line)
        if ip_match and path_match:
            ip = ip_match.group(1)
            path = path_match.group(1)
            ip_hits.append(ip)

            if path in SUSPICIOUS_PATHS:
                flagged_entries.append((ip, path))

    return ip_hits, flagged_entries

# Export to CSV
def save_report(ip_count, suspicious_list):
    with open("report.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Suspicious IP", "Hit Count"])
        for ip, count in ip_count.items():
            if count > 2:  # threshold
                writer.writerow([ip, count])
        if suspicious_list:
            writer.writerow([])
            writer.writerow(["Suspicious Path Accesses"])
            writer.writerow(["IP", "Path"])
            for ip, path in suspicious_list:
                writer.writerow([ip, path])

if __name__ == "__main__":
    log_file = sys.argv[1]
    ip_hits, flagged = parse_log(log_file)
    ip_counter = Counter(ip_hits)
    print("\n📌 Suspicious IPs with more than 2 hits:")
    for ip, count in ip_counter.items():
        if count > 2:
            print(f"{ip} => {count} requests")

    print("\n🚨 Flagged Requests to Sensitive Paths:")
    for ip, path in flagged:
        print(f"{ip} accessed {path}")

    save_report(ip_counter, flagged)
    print("\n✅ Report saved to report.csv")
