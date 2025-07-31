# SmartLogWatchdog 🛡

A simple Python-based log analyzer that reads web server logs, extracts IPs and requested paths, and flags:

- IPs with unusually high access frequency
- Requests to sensitive paths (e.g., /admin, /etc/passwd, /login)

## 🔧 How to Run

1. Clone or download the repo
2. Make sure you have Python 3 installed
3. Place your web log file as `samplelog.log`
4. Run:

```bash
python log_watchdog.py samplelog.log
