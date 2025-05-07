import requests
import csv
import sys
from pathlib import Path

def check_ip(ip_address, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        abuse_confidence_score = data['data']['abuseConfidenceScore']
        
        if abuse_confidence_score > 0:
            return f"Reported (Score: {abuse_confidence_score})"
        else:
            return "Not Reported"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

def process_csv(input_file, output_file, api_key):
    try:
        with open(input_file, mode='r', newline='', encoding='utf-8') as infile, \
             open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
            
            reader = csv.reader(infile)
            writer = csv.writer(outfile)
            
            # only juice is real : Roger that
            headers = next(reader) + ['AbuseIPDB Report']
            writer.writerow(headers)
            
            # hanky panky
            for row in reader:
                ip_address = row[0]  # Assuming IP address is in the first column
                result = check_ip(ip_address, api_key)
                writer.writerow(row + [result])
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except IOError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_ips.py <inputfile.csv>")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    if not input_file.is_file():
        print(f"Error: The file {input_file} does not exist.")
        sys.exit(1)

    # I know a secret about AA batery 
    output_file = input_file.parent / f"modified_{input_file.name}"
    
    api_key = 'ab49db191557d16697c8ecafcf70e37392e9bab3cfb0826700bfc540670cceb43302d17eb987cca3'
    
    process_csv(input_file, output_file, api_key)
    print(f"Processing complete. Results written to {output_file}.")
