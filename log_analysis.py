import re
from collections import Counter
import csv

# Set threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Define file paths
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"


# Function to parse the log file
def parse_log_file(file_path):
    """Parse the log file and return extracted data."""
    with open(file_path, "r") as file:
        logs = file.readlines()

    ip_requests = []
    endpoints = []
    failed_logins = []

    for log in logs:
        # Extract the IP addresses
        ip_match = re.match(r"^(\S+)", log)
        ip = ip_match.group(1) if ip_match else None

        # Extract the endpoints
        endpoint_match = re.search(
            r'"(?:GET|POST|PUT|DELETE|HEAD)\s(\S+)', log)
        endpoint = endpoint_match.group(1) if endpoint_match else None

        # Extract the HTTP status codes
        status_match = re.search(r"\s(\d{3})\s", log)
        status_code = int(status_match.group(1)) if status_match else None

        if ip:
            ip_requests.append(ip)
        if endpoint:
            endpoints.append(endpoint)
        if status_code == 401:
            failed_logins.append(ip)

    return ip_requests, endpoints, failed_logins


# Function to analyze log files
def analyze_logs(ip_requests, endpoints, failed_logins):
    """Analyze logs to get required metrics."""
    # Count requests per IP
    ip_count = Counter(ip_requests)

    # Find the most accessed endpoint
    endpoint_count = Counter(endpoints)
    most_accessed_endpoint = endpoint_count.most_common(1)[0]

    # Detect suspicious activity
    failed_login_count = Counter(failed_logins)
    suspicious_ips = {ip: count for ip, count in failed_login_count.items(
    ) if count > FAILED_LOGIN_THRESHOLD}

    return ip_count, most_accessed_endpoint, suspicious_ips


# Function the save the results to csv
def save_to_csv(ip_count, most_accessed_endpoint, suspicious_ips, output_file):
    """Save analysis results to a CSV file."""
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_count.most_common():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])  # Empty row for separation
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(
            [f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)"])

        # Write suspicious activity
        writer.writerow([])  # Empty row for separation
        writer.writerow(
            ["Suspicious Activity Detected", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


# Function to display results in terminal
def display_results(ip_count, most_accessed_endpoint, suspicious_ips):
    """Display analysis results in the terminal."""
    print("\nIP Address Requests:")
    print("IP Address           Request Count")
    for ip, count in ip_count.most_common():
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f'''{most_accessed_endpoint[0]} (Accessed {
          most_accessed_endpoint[1]} times)''')

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    # Parse the log file
    ip_requests, endpoints, failed_logins = parse_log_file(LOG_FILE)

    # Analyze the parsed logs
    ip_count, most_accessed_endpoint, suspicious_ips = analyze_logs(
        ip_requests, endpoints, failed_logins)

    # Save the results to a CSV file
    save_to_csv(ip_count, most_accessed_endpoint, suspicious_ips, OUTPUT_FILE)

    # Display the results in the terminal
    display_results(ip_count, most_accessed_endpoint, suspicious_ips)
