import re
import csv
from collections import defaultdict

# File path for the log file
LOG_FILE = "sample.log"

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Parses the log file and extracts required data.
    """
    ip_request_counts = defaultdict(int)
    endpoint_access_counts = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    try:
        with open(file_path, "r") as log_file:
            for line in log_file:
                # Extract IP address
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    ip_request_counts[ip] += 1

                # Extract endpoint
                endpoint_match = re.search(r'\"[A-Z]+\s(\/[^\s]*)', line)
                if endpoint_match:
                    endpoint = endpoint_match.group(1)
                    endpoint_access_counts[endpoint] += 1

                # Check for failed login attempts
                if "401" in line or "Invalid credentials" in line:
                    if ip_match:
                        failed_login_attempts[ip] += 1

        return ip_request_counts, endpoint_access_counts, failed_login_attempts
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist in the current directory.")
        return None, None, None

def save_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_activities, output_file="log_analysis_results.csv"):
    """
    Saves the analysis results to a CSV file.
    """
    with open(output_file, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_request_counts.items():
            writer.writerow([ip, count])
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_request_counts, endpoint_access_counts, failed_login_attempts = parse_log_file(LOG_FILE)
    if ip_request_counts is None:
        return

    # Calculate the most accessed endpoint
    most_accessed_endpoint = max(endpoint_access_counts.items(), key=lambda x: x[1])

    # Detect suspicious activity
    suspicious_activities = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display the results
    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activities:
        print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
        for ip, count in suspicious_activities.items():
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity detected.")

    # Save the results to a CSV file
    save_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_activities)
    print("\nResults saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    main()
