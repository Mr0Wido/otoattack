#!/usr/bin/env python3

import requests
import urllib.parse
import argparse


payloads = [
    {"payload": "{{7*7}}", "expected_output": "49"},
    {"payload": "{{7*'7'}}", "expected_output": "7777777"},
    {"payload": "{{9*9}}", "expected_output": "81"},
    {"payload": "{{3*'3'}}", "expected_output": "333"},
    {"payload": "${6*6}", "expected_output": "36"},
]


def parser_arguments():
    parser = argparse.ArgumentParser(description="SSTI Scanner")
    parser.add_argument("-ul", "--url-list", help="Specify a URL list for SSTI", required=True)
    return parser.parse_args()


def inject_ssti(url):
    headers_list = [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"},
        {"User-Agent": "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36"},
        {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/537.36"},
    ]

    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if not query_params:
        print(f"[-] No query parameters found in {url}. Skipping...")
        return

    for payload in payloads:
        for headers in headers_list:
            for param in query_params.keys():
                modified_params = query_params.copy()
                modified_params[param] = payload["payload"]

                new_query = urllib.parse.urlencode(modified_params, doseq=True)
                payload_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                print(f"{payload_url}")
                try:
                    response = requests.get(payload_url, headers=headers, timeout=10)
                    if payload["expected_output"] in response.text:
                        print(f"[+] Potential SSTI detected: {payload['payload']} : {payload_url}")
                        with open("ssti_found.txt", "a") as f:
                            f.write(f"{payload_url} | Expected Output: {payload['expected_output']}\n")
                    else:
                        print(f"[-] No SSTI: {payload_url}")

                except requests.exceptions.RequestException as e:
                    print(f"[!] Error on {url}: {e}")

def main():
    args = parser_arguments()
    try:
        with open(args.url_list, "r") as f:
            urls = [line.strip() for line in f if "=" in line]
    except FileNotFoundError:
        print("[!] URL list file not found.")
        return

    for url in urls:
        inject_ssti(url)

if __name__ == "__main__":
    main()
