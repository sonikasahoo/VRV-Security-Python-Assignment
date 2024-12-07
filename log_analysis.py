
import re       # For Regular Expressions to parse the log file
import csv      # To handle csv files
from collections import Counter  # To count the frequency of elements



# Parse the log file to extract specific details
def parse_log_file(file_path):
    log_data =[]
    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Use Regex to extract values like IP address, status, etc.
                match = re.match(r'^(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.+?)\] "(?P<method>GET|POST|PUT|PATCH|DELETE) (?P<endpoint>/\S*) HTTP/[\d.]+" (?P<status>\d{3}) (?P<size>\d+)( "(?P<message>.+)")?$', line)

                if match:
                    # Add data as a dictionary
                    log_data.append(match.groupdict())
    # Handle Errors
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return log_data


# Count Requests for each IP address using Counter
def count_requests_per_IP(log_data):
    ip_counts = Counter(entry['ip'] for entry in log_data)
    # returns a sorted list in descending order
    return sorted(ip_counts.items(), key = lambda i: i[1], reverse = True)


# Identify Most Frequently Accessed Endpoint
def most_accessed_endpts(log_data):
    # Count occurrences of each Endpoint
    count_endpts = Counter(entry['endpoint'] for entry in log_data)
    # returns maximum one
    return max(count_endpts.items(), key = lambda i: i[1])


# Suspicious Activity Detection
# Adjust the threshold for suspicious activity detection 
# by modifying the threshold argument
def detect_suspicious_activity(log_data, threshold = 10):
    # Count failed login attempts (status code 401) for eac IP address
    failed_logins = Counter(entry['ip'] for entry in log_data if entry['status'] == '401')
    # Return IPs with failed login attempts above the threshold value
    return [(ip,count) for ip, count in failed_logins.items() if count > threshold]


# Save Outputs to a CSV file
def save_results_to_csv(ip_counts, most_accessed, suspicious_acts, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # write total no. of requests for each IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)

        # Write Most Accessed Endpoint
        writer.writerow([])                  # Add an empty row for separation between different set of values
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed)

        # Write Suspicious Activity
        writer.writerow([])                  # Add an empty row for separation between different set of values
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_acts)


# Main Script to excute the analysis
def main():
    log_file = 'sample.log'                 # Path to the log file
    output_csv = 'log_analysis_output.csv'  # Path to save the result csv file

    # Parse the log file
    log_data = parse_log_file(log_file)

    # Process the data
    ip_counts = count_requests_per_IP(log_data)
    most_accessed = most_accessed_endpts(log_data)
    suspicious_acts = detect_suspicious_activity(log_data)

    # Terminal Output
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in ip_counts:
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<15}")
    for ip, count in suspicious_acts:
        print(f"{ip:<20} {count:<15}")
    

    # Save the output to a CSV file
    save_results_to_csv(ip_counts, most_accessed, suspicious_acts, output_csv)
    print(f"\nResults saved to {output_csv}")

# Ensures the script runs its main logic only when executed directly (e.g., python log_analysis.py).
# Prevents uninteded execution of main() if the script is imported into another script for reusing its functions.
if __name__ == "__main__":
    main()
