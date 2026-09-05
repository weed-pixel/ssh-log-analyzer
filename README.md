# SSH Log Analyzer

A small Python security project for analyzing Linux SSH authentication logs.

The program reads an SSH log line by line and reports:

- failed password authentication attempts;
- successful SSH logins;
- attempts to use non-existent users;
- failed authentication attempts grouped by source IP;
- successful logins grouped by username;
- suspicious IP addresses that exceed a configurable failure threshold.

The project is intentionally built with simple Python concepts such as functions, loops, strings, lists, dictionaries and conditions.

## Requirements

- Python 3.10+
- No external Python packages

## Usage

```bash
python3 analyzer.py sample.log
```

Use a custom threshold:

```bash
python3 analyzer.py sample.log 3
```

## Example

```text
=== SSH Log Analyzer ===

Failed password attempts: 8
Successful logins: 1
Invalid user attempts: 0

Failed attempts by IP:
  192.0.2.10: 3
  198.51.100.20: 5

Successful logins by user:
  student: 1

Suspicious IPs (5+ failed attempts):
  ALERT: 198.51.100.20 -> 5 failed attempts
```

## Using real Fedora SSH logs

On Fedora, export recent SSH events:

```bash
sudo journalctl -u sshd --since "1 hour ago" > sshd.log
```

Then analyze them:

```bash
python3 analyzer.py sshd.log
```

You can also export a larger time range:

```bash
sudo journalctl -u sshd --since "today" > sshd.log
```

## How detection works

The program treats repeated failed authentication events from the same source IP as suspicious.

For example, with the default threshold:

```text
192.0.2.10 -> 1 failed attempt
192.0.2.10 -> 2 failed attempts
192.0.2.10 -> 3 failed attempts
192.0.2.10 -> 4 failed attempts
192.0.2.10 -> 5 failed attempts
```

The fifth attempt causes an `ALERT`.

This is a simple educational heuristic, not a production brute-force detection system. A real SOC would also consider time windows, account context, IP reputation, successful logins after failures, network location, and other signals.

## Example log

`sample.log` contains examples of:

- successful SSH authentication;
- failed password authentication;
- invalid users.

## Project structure

```text
ssh-log-analyzer/
├── analyzer.py
├── sample.log
└── README.md
```

## What I learned

This project helped practice:

- reading files in Python;
- working with strings and `split()`;
- functions and return values;
- dictionaries for counting events;
- command-line arguments;
- basic security-event analysis;
- turning raw logs into a simple security report.
