
import argparse
import os
import sys
import re
import json
import requests
from datetime import datetime
from decouple import config, UndefinedValueError
import xlsxwriter
from requests.exceptions import RequestException


def load_api_key():
    try:
        return config('ABUSEIPDB_APIKEY')
    except UndefinedValueError:
        print("[ERROR] Missing API key. Please add it to your .env file as 'ABUSEIPDB_APIKEY'.")
        sys.exit(1)


def extract_ips(file_path):
    ips = []
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    try:
        with open(file_path, 'r') as file:
            for line in file:
                found = pattern.findall(line)
                ips.extend(found)
        return ips
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)


def query_abuseipdb(ip, api_key, max_age):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': str(max_age)
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json()['data']
    except RequestException as e:
        print(f"[ERROR] Request failed for {ip}: {e}")
        return None
    except KeyError:
        print(f"[ERROR] Unexpected response for {ip}: {response.text}")
        return None


def save_results_to_excel(results, output_path):
    workbook = xlsxwriter.Workbook(output_path)
    worksheet = workbook.add_worksheet("Results")
    bold = workbook.add_format({'bold': True})
    headers = ['IP', 'Domain', 'Hostnames', 'Abuse Confidence %', 'Total Reports', 'Country', 'ISP', 'Usage Type', 'Last Reported']
    for col_num, header in enumerate(headers):
        worksheet.write(0, col_num, header, bold)
    
    for row_num, data in enumerate(results, start=1):
        for col_num, value in enumerate(data):
            worksheet.write(row_num, col_num, value)
    
    workbook.close()
    print(f"[+] Results saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="AbuseIPDB Bulk IP Checker")
    parser.add_argument("file", help="Path to input file containing IP addresses")
    parser.add_argument("--max-age", type=int, default=90, help="Max age in days (default: 90)")
    args = parser.parse_args()

    api_key = load_api_key()
    ips = extract_ips(args.file)
    if not ips:
        print("[!] No IPs found in input file.")
        sys.exit(1)
    
    print(f"[+] Found {len(ips)} IPs to check.")
    results = []
    
    for ip in ips:
        print(f"[*] Checking {ip}...")
        data = query_abuseipdb(ip, api_key, args.max_age)
        if data:
            results.append([
                data.get("ipAddress", ""),
                data.get("domain", ""),
                ", ".join(data.get("hostnames", [])),
                data.get("abuseConfidenceScore", ""),
                data.get("totalReports", ""),
                data.get("countryCode", ""),
                data.get("isp", ""),
                data.get("usageType", ""),
                data.get("lastReportedAt", "")
            ])

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = os.path.join(os.path.dirname(os.path.abspath(args.file)), f"abuseipdb_results_{timestamp}.xlsx")
    save_results_to_excel(results, output_file)


if __name__ == "__main__":
    main()
