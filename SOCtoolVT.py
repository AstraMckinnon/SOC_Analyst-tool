import requests
import sys
import json
import ipaddress
import urllib
import urllib.request
import pprint
import hashlib

VT_API_KEY = '<Give your VT API Key>'
VT_BASE_URL = 'https://www.virustotal.com/api/v3'

HEADERS = {
    'x-apikey': VT_API_KEY
}

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_url_reputation(url):
    response = requests.get(f"{VT_BASE_URL}/urls/{hashlib.sha256(url.encode()).hexdigest()}", headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        print("URL not found in VirusTotal. Submitting for analysis...")
        res = requests.post(f"{VT_BASE_URL}/urls", headers=HEADERS, data={"url": url})
        return res.json()

def check_ip_reputation(ip):
    response = requests.get(f"{VT_BASE_URL}/ip_addresses/{ip}", headers=HEADERS)
    return response.json()

def check_file_reputation(file_path):
    file_hash = get_file_hash(file_path)
    response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        print("File not found in VirusTotal. Uploading for analysis...")
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            res = requests.post(f"{VT_BASE_URL}/files", headers=HEADERS, files=files)
        return res.json()

def display_analysis(data):
    if 'data' in data and 'attributes' in data['data']:
        stats = data['data']['attributes'].get('last_analysis_stats', {})
        print("Reputation Summary:")
        for key, value in stats.items():
            print(f"  {key.capitalize()}: {value}")
    else:
        print("Could not retrieve reputation information.")

def main():
    choice = input("Check (1) URL Reputation, (2) IP Reputation, or (3) File: Reputation ")
    if choice == '1':
        input_url = input("Enter URL: ")
        result = check_url_reputation(input_url)
        display_analysis(result)
    elif choice == '2':
        ip = input("Enter IP Address: ")
        result = check_ip_reputation(ip)
        display_analysis(result)
    elif choice == '3':
        file_path = input("Enter path to file: ")
        if os.path.isfile(file_path):
            result = check_file_reputation(file_path)
            display_analysis(result)
        else:
            print("Invalid file path.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
