import requests
import csv
import logging
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# Setup logging
logging.basicConfig(filename='script.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define API URLs and keys
abuse_ip_url = 'https://api.abuseipdb.com/api/v2/check'
virustotal_api_url = "https://www.virustotal.com/api/v3/ip_addresses/"
abuse_ip_key = 'ab49db191557d16697c8ecafcf70e37392e9bab3cfb0826700bfc540670cceb43302d17eb987cca3'
virustotal_keys = [
    "d9ee6a81e195f0f7e4c964fece7695cf4f4916588838909b351bd93c9daa433f",
    "d80c33bca93502de7839e8ae3b8a3208ffafacfc1deb19551a98df9b78deaf29"
]

def is_valid_ip(ip):
    """Validate IP address format."""
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return pattern.match(ip) is not None

def check_abuse_ip(ip_address):
    """Checks the reputation of the given IP address using the AbuseIPDB API."""
    headers = {
        'Key': abuse_ip_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address
    }
    
    try:
        response = requests.get(abuse_ip_url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        return data['data']['abuseConfidenceScore']
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking AbuseIPDB for {ip_address}: {e}")
        return 0

def fetch_virustotal_info(ip_address, api_key):
    """Fetches information about an IP address from VirusTotal API, including country details."""
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(f"{virustotal_api_url}{ip_address}", headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # Extract necessary data
        analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        country = data.get('data', {}).get('attributes', {}).get('country', 'Unknown')
        
        return analysis_stats, country  # Return both analysis stats and country

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for IP {ip_address} with API key {api_key}: {e}")
        return {'error': str(e)}, 'Unknown'  # Return 'Unknown' if the request fails

def get_comment(virustotal_result):
    """Generates a comment based on VirusTotal results."""
    malicious_count = virustotal_result.get('malicious', 0)
    
    if malicious_count <= 5:
        return "Under Observation"
    elif 6 <= malicious_count <= 9:
        return "Check for previous incident"
    elif malicious_count >= 10:
        return "Take action"
    return "No data"

def process_csv(input_path):
    """Processes the input CSV and writes results to an output CSV."""
    base_name = os.path.splitext(input_path)[0]
    output_path = f"{base_name}_resultoutput.csv"
    
    ip_addresses = set()  # Use a set for unique IPs
    existing_data = []

    try:
        with open(input_path, 'r') as infile:
            reader = csv.reader(infile)
            header = next(reader)
            # Collect unique and valid IP addresses
            for row in reader:
                ip = row[0]  # Assuming the IP is in the first column
                if is_valid_ip(ip):
                    ip_addresses.add(ip)
                existing_data.append(row)  # Store the entire row
            
    except Exception as e:
        logging.error(f"Failed to read input CSV file: {e}")
        return
    
    results = []
    
    # Check IP reputation with AbuseIPDB
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_ip = {executor.submit(check_abuse_ip, ip): ip for ip in ip_addresses}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            abuse_score = future.result()
            if abuse_score > 0:  # Only proceed if reported
                result, country = fetch_virustotal_info(ip, virustotal_keys[0])  # Use the first key
                comment = get_comment(result)  # Get the comment based on the VirusTotal result
                results.append((ip, abuse_score, result, comment, country))
            else:
                results.append((ip, abuse_score, {}, "Clean", "Unknown"))  # No need to check VirusTotal if not reported

    # Write results to output CSV
    try:
        with open(output_path, 'w', newline='') as outfile:
            writer = csv.writer(outfile)
            # Write the original header plus new columns for AbuseIPDB score, VirusTotal analysis, and country
            writer.writerow(header + ['AbuseIPDB Score', 'Malicious', 'Suspicious', 'Undetected', 'Harmless', 'Comment', 'Country'])
            
            # Create a mapping of IP results for easy lookup
            ip_results = {ip: (abuse_score, result, comment, country) for ip, abuse_score, result, comment, country in results}
            
            for row in existing_data:
                ip = row[0]  # Assuming the IP is in the first column
                if ip in ip_results:
                    abuse_score, result, comment, country = ip_results[ip]
                    writer.writerow(row + [
                        abuse_score,
                        result.get('malicious', 'N/A'),
                        result.get('suspicious', 'N/A'),
                        result.get('undetected', 'N/A'),
                        result.get('harmless', 'N/A'),
                        comment,
                        country
                    ])
                else:
                    writer.writerow(row + ['Not Reported', 'N/A', 'N/A', 'N/A', 'N/A', 'Clean', 'Unknown'])

    except Exception as e:
        logging.error(f"Failed to write to output CSV file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process IP addresses from a CSV file using AbuseIPDB and VirusTotal APIs.")
    parser.add_argument('input_csv', type=str, help='Input CSV file path')

    args = parser.parse_args()

    logging.info("Starting CSV processing...")
    process_csv(args.input_csv)
    logging.info("CSV processing completed.")
