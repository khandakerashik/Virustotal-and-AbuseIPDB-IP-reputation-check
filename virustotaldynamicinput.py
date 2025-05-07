import requests
import csv
import json
import logging
import time
import os
import argparse

# Setup logging
logging.basicConfig(filename='script.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define API URL and headers
api_url = "https://www.virustotal.com/api/v3/ip_addresses/"
api_key = "d9ee6a81e195f0f7e4c964fece7695cf4f4916588838909b351bd93c9daa433f"  # API key
headers = {
    "accept": "application/json",
    "x-apikey": api_key
}

def fetch_ip_info(ip_address):
    """Fetches information about an IP address from VirusTotal API and extracts specific attributes."""
    try:
        response = requests.get(f"{api_url}{ip_address}", headers=headers)
        response.raise_for_status()  # Check for HTTP errors
        data = response.json()  # Parse the response as JSON

        # Extract specific attributes if available
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'harmless': stats.get('harmless', 0)
        }

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for IP {ip_address}: {e}")
        return None  # Return None if there's an error

def process_csv(input_path):
    """Processes the input CSV and writes the filtered responses to an output CSV with rate limiting."""
    # Generate output file path based on input file name
    base_name = os.path.splitext(input_path)[0]
    output_path = f"{base_name}_output.csv"
    
    request_count = 0
    start_time = time.time()

    try:
        with open(input_path, 'r') as infile:
            reader = csv.reader(infile)
            header = next(reader)
            logging.info(f"Read header: {header}")

            with open(output_path, 'w', newline='') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(header + ['Malicious', 'Suspicious', 'Undetected', 'Harmless'])  # Add new columns for filtered data
                
                for row in reader:
                    ip_address = row[0]  # Assuming the IP address is in the first column
                    response_data = fetch_ip_info(ip_address)
                    if response_data is None:
                        writer.writerow(row + ['Error', 'Error', 'Error', 'Error'])  # Append 'Error' if there's an exception
                        continue
                    
                    try:
                        writer.writerow(row + [
                            response_data.get('malicious', 'N/A'),
                            response_data.get('suspicious', 'N/A'),
                            response_data.get('undetected', 'N/A'),
                            response_data.get('harmless', 'N/A')
                        ])  # Append the filtered data to the row
                    except Exception as e:
                        logging.error(f"Failed to process response for IP {ip_address}: {e}")
                        writer.writerow(row + ['Processing Error', 'Processing Error', 'Processing Error', 'Processing Error'])  # Append 'Processing Error' if something goes wrong

                    # Rate limiting: 4 requests per minute
                    request_count += 1
                    if request_count >= 4:
                        elapsed_time = time.time() - start_time
                        if elapsed_time < 60:
                            sleep_time = 60 - elapsed_time
                            logging.info(f"Rate limit reached. Sleeping for {sleep_time} seconds.")
                            time.sleep(sleep_time)
                        request_count = 0
                        start_time = time.time()

    except Exception as e:
        logging.error(f"Failed to process CSV files: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process IP addresses from a CSV file using VirusTotal API.")
    parser.add_argument('input_csv', type=str, help='Input CSV file path')

    args = parser.parse_args()

    logging.info("Starting CSV processing...")
    process_csv(args.input_csv)
    logging.info("CSV processing completed.")
