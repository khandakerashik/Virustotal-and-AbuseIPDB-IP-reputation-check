import requests
import csv
import logging
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup logging
logging.basicConfig(filename='script.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define API URL and keys
api_url = "https://www.virustotal.com/api/v3/ip_addresses/"
api_keys = [
    "d9ee6a81e195f0f7e4c964fece7695cf4f4916588838909b351bd93c9daa433f",  # First API key
    "d80c33bca93502de7839e8ae3b8a3208ffafacfc1deb19551a98df9b78deaf29"  # Updated second API key
]

def fetch_ip_info(ip_address, api_key):
    """Fetches information about an IP address from VirusTotal API using the specified API key and extracts specific attributes."""
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        start = time.time()
        response = requests.get(f"{api_url}{ip_address}", headers=headers)
        response.raise_for_status()  # Check for HTTP errors
        data = response.json()  # Parse the response as JSON
        elapsed = time.time() - start

        # Log request timing
        logging.info(f"Request for IP {ip_address} took {elapsed:.2f} seconds")

        # Extract specific attributes if available
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return ip_address, {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0),
            'api_key': api_key
        }

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for IP {ip_address} with API key {api_key}: {e}")
        return ip_address, {'error': str(e), 'api_key': api_key}

def process_ips(ip_addresses):
    """Processes the input IP addresses and writes the filtered responses to an output CSV with parallel processing."""
    # Static output file path
    output_path = 'inlineipoutput.csv'
    
    # Start time for total execution
    total_start_time = time.time()
    
    # Create a list of (ip, api_key) tuples
    requests_list = [(ip, api_keys[i // 4 % len(api_keys)]) for i, ip in enumerate(ip_addresses)]

    # Process requests in parallel
    request_count = 0
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(fetch_ip_info, ip, api_key): (ip, api_key) for ip, api_key in requests_list}
        
        results = []
        for future in as_completed(futures):
            ip_address, result = future.result()
            results.append((ip_address, result))
            
            # Update request count
            request_count += 1
            
            # Implement delay after 8 requests (4 per key)
            if request_count % 8 == 0:
                elapsed_time = time.time() - total_start_time
                if elapsed_time < 60:
                    sleep_time = 60 - elapsed_time
                    logging.info(f"8 requests completed. Sleeping for {sleep_time:.2f} seconds.")
                    time.sleep(sleep_time)
                total_start_time = time.time()  # Reset total_start_time for the next interval

    # Write results to output CSV
    try:
        write_start_time = time.time()  # Start time for writing the CSV
        
        with open(output_path, 'w', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(['IP Address', 'Malicious', 'Suspicious', 'Undetected', 'Harmless', 'API Key Used'])  # Header
            
            for ip_address, result in results:
                if 'error' in result:
                    writer.writerow([ip_address] + ['Error'] * 4 + [result['api_key']])
                else:
                    writer.writerow([ip_address] + [
                        result.get('malicious', 'N/A'),
                        result.get('suspicious', 'N/A'),
                        result.get('undetected', 'N/A'),
                        result.get('harmless', 'N/A'),
                        result.get('api_key', 'N/A')
                    ])
        
        # Calculate time taken for CSV writing
        write_time = time.time() - write_start_time
        logging.info(f"CSV writing took {write_time:.2f} seconds")
    
    except Exception as e:
        logging.error(f"Failed to write to output CSV file: {e}")

    # Calculate total time taken for the entire process
    total_time = time.time() - total_start_time
    logging.info(f"Total time taken for the entire process: {total_time:.2f} seconds")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process IP addresses using VirusTotal API.")
    parser.add_argument('ips', type=str, nargs='+', help='IP addresses to be processed')

    args = parser.parse_args()

    logging.info("Starting IP processing...")
    process_ips(args.ips)
    logging.info("IP processing completed.")
