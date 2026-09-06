**SSH Log Analyzer**  
A small Python security tool for analyzing Linux SSH authentication logs and highlighting suspicious authentication activity.  
**Features**  
- Counts failed SSH password authentication attempts.  
- Counts successful SSH logins.  
- Detects attempts to use non-existent accounts.  
- Groups failed authentication attempts by source IP.  
- Groups successful logins by username.  
- Flags IP addresses that reach a configurable number of failed attempts.  
- Works with logs exported from Fedora journalctl.  
**Requirements**  
- Python 3.10+  
- No external packages  
**Usage**  
python3 analyzer.py <log_file> [threshold]  
   
Example:  
python3 analyzer.py sample.log  
   
Use a custom threshold:  
python3 analyzer.py sample.log 10  
   
The default threshold is **5 failed authentication attempts**.  
**Example output**  
=== SSH Log Analyzer ===  
   
 Failed password attempts: 8  
 Successful logins: 1  
 Invalid user attempts: 1  
   
 Failed attempts by IP:  
   198.51.100.20: 5  
   192.0.2.10: 3  
   
 Successful logins by user:  
   student: 1  
   
 Suspicious IPs (5+ failed attempts):  
   ALERT: 198.51.100.20 -> 5 failed attempts  
   
**Analyze real Fedora SSH logs**  
Export recent SSH events:  
sudo journalctl -u sshd --since "1 hour ago" > sshd.log  
   
Then run the analyzer:  
python3 analyzer.py sshd.log  
   
The generated sshd.log is intentionally not part of the repository. Local .log files are ignored by .gitignore.  
**Detection logic**  
The current detector uses a simple threshold-based heuristic:  
5+ failed authentication attempts from the same source IP  
                     ↓  
                  ALERT  
   
This is an educational detection method rather than a production brute-force detector. A production SOC would also consider time windows, account context, IP reputation, successful logins after failures, and other signals.  
**Project structure**  
ssh-log-analyzer/  
 ├── analyzer.py  
 ├── sample.log  
 ├── README.md  
 └── .gitignore  
   
**What this project demonstrates**  
- Python functions and control flow.  
- File processing and string parsing.  
- Dictionaries for event aggregation.  
- Command-line arguments.  
- Basic SSH security-event analysis.  
- Turning raw authentication logs into a readable security report.  
**Author**  
Nikita Chu​​prov — Information Security student.  
-    
