#!/usr/bin/env python3

import sys


def extract_value(line, marker):
    """Return the word immediately after marker."""
    parts = line.split()

    if marker in parts:
        index = parts.index(marker)

        if index + 1 < len(parts):
            return parts[index + 1]

    return None


def extract_ip(line):
    """Return the IP address after the word 'from'."""
    return extract_value(line, "from")


def extract_user(line):
    """Extract username from common SSH authentication messages."""
    parts = line.split()

    # Example:
    # Failed password for student from 192.0.2.10 ...
    if "for" in parts:
        index = parts.index("for")

        if index + 1 < len(parts):
            username = parts[index + 1]

            # "invalid user" / "illegal user" have an extra word.
            if username in ("invalid", "illegal") and index + 2 < len(parts):
                return parts[index + 2]

            return username

    return None


def analyze_log(filename, threshold=5):
    failed_logins = 0
    successful_logins = 0
    invalid_users = 0

    failed_by_ip = {}
    successful_by_user = {}

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                # Failed SSH password authentication.
                if "Failed password" in line:
                    failed_logins += 1

                    ip = extract_ip(line)

                    if ip:
                        if ip in failed_by_ip:
                            failed_by_ip[ip] += 1
                        else:
                            failed_by_ip[ip] = 1

                # SSH login using a non-existent account.
                elif "Invalid user" in line or "invalid user" in line:
                    invalid_users += 1

                    ip = extract_ip(line)

                    if ip:
                        if ip in failed_by_ip:
                            failed_by_ip[ip] += 1
                        else:
                            failed_by_ip[ip] = 1

                # Successful password or public-key authentication.
                elif "Accepted password" in line or "Accepted publickey" in line:
                    successful_logins += 1

                    user = extract_user(line)

                    if user:
                        if user in successful_by_user:
                            successful_by_user[user] += 1
                        else:
                            successful_by_user[user] = 1

    except FileNotFoundError:
        print(f"Error: file not found: {filename}")
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied: {filename}")
        sys.exit(1)

    return (
        failed_logins,
        successful_logins,
        invalid_users,
        failed_by_ip,
        successful_by_user,
        threshold,
    )


def print_report(
    failed_logins,
    successful_logins,
    invalid_users,
    failed_by_ip,
    successful_by_user,
    threshold,
):
    print("=== SSH Log Analyzer ===")
    print()

    print(f"Failed password attempts: {failed_logins}")
    print(f"Successful logins: {successful_logins}")
    print(f"Invalid user attempts: {invalid_users}")

    print()
    print("Failed attempts by IP:")

    if failed_by_ip:
        for ip, count in sorted(
            failed_by_ip.items(), key=lambda item: item[1], reverse=True
        ):
            print(f"  {ip}: {count}")
    else:
        print("  No failed authentication attempts found.")

    print()
    print("Successful logins by user:")

    if successful_by_user:
        for user, count in sorted(
            successful_by_user.items(), key=lambda item: item[1], reverse=True
        ):
            print(f"  {user}: {count}")
    else:
        print("  No successful logins found.")

    print()
    print(f"Suspicious IPs ({threshold}+ failed attempts):")

    suspicious_found = False

    for ip, count in sorted(
        failed_by_ip.items(), key=lambda item: item[1], reverse=True
    ):
        if count >= threshold:
            print(f"  ALERT: {ip} -> {count} failed attempts")
            suspicious_found = True

    if not suspicious_found:
        print("  No IPs exceeded the threshold.")


def main():
    if len(sys.argv) not in (2, 3):
        print("Usage: python3 analyzer.py <log_file> [threshold]")
        sys.exit(1)

    filename = sys.argv[1]

    threshold = 5

    if len(sys.argv) == 3:
        try:
            threshold = int(sys.argv[2])

            if threshold < 1:
                raise ValueError

        except ValueError:
            print("Error: threshold must be a positive integer.")
            sys.exit(1)

    results = analyze_log(filename, threshold)

    print_report(*results)


if __name__ == "__main__":
    main()
