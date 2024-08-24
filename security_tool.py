#!/usr/bin/env python3

import argparse
import requests
import sys
from termcolor import colored

def print_heart_bear():
    bear_heart = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⢀⣴⣶⣶⣶⣶⣄⠀⣀⣴⣶⣶⣶⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⣿⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣸⣿⣿⣀⣀⡀⠀⠀⠀⠀⠀⠀⠈⠻⢿⢿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠿⠿⠿⠿⠿⠿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢾⣿⣿⣿⣿⣿⣿⠆⠠⣿⡿⣿⣿⣿⢿⣿⣦⣴⣿⡿⠿⢿⣿⣷⣄⠀⢾⣿⣿⣿⣿⡿⣿⠆⠀⢸⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣧⠀⠀⠀⠀⣠⣿⡿⠁⠀⠀⣰⣿⡿⠁⠀⠀⠀⠈⠻⣿⣧⡀⠀⠘⣿⡟⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣧⡀⠀⢰⣿⡿⠁⠀⠀⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣇⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠸⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣷⣴⣿⡟⠀⠀⠀⢰⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⡏⠀⠀⠀⠀⠘⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡀⠀⠀⠀⠀⠀⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠇⠀⠀⣿⣧⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣿⣿⣇⣀⡀⠀⠀⠀⠘⢿⣿⣦⣀⠀⠀⢀⣠⣾⣿⠏⠀⠀⠀⠀⢿⣿⣦⡀⠀⠀⣀⣼⣿⠏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠻⠿⠿⠿⠿⠿⠿⠿⠀⠀⠀⠀⠀⠙⠿⢿⣿⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠙⠿⢿⣿⣿⡿⠟⠉⠀⠀
    """
    print(colored(bear_heart, "red"))

def print_header():
    print(colored("=" * 50, "cyan"))
    print(colored("❤❤❤ WEB APPLICATION SECURITY TESTING TOOL ❤❤❤", "cyan"))
    print(colored("             𝕯𝖊𝖛𝖊𝖑𝖔𝖕𝖊𝖉 𝖇𝖞 𝕶𝖆𝖆𝖓", "yellow"))
    print(colored("=" * 50, "cyan"))

def print_menu():
    print(colored("\nChoose an option:", "cyan"))
    print(colored(" 1. Scan for XSS vulnerabilities", "green"))
    print(colored(" 2. Scan for SQL Injection vulnerabilities", "green"))
    print(colored(" 3. Inspect HTTP Headers", "green"))
    print(colored("=" * 50, "cyan"))

def check_xss(url):
    payloads = ["<script>alert('XSS')</script>", "'\"<img src=x onerror=alert(1)>"]
    print(colored("Scanning for XSS vulnerabilities...", "blue"))
    for payload in payloads:
        test_url = f"{url}?search={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                print(colored(f"Potential XSS vulnerability found at: {test_url}", "red"))
        except requests.RequestException as e:
            print(colored(f"Error: {e}", "red"))

def check_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR 'x'='x", "' OR 1=1--"]
    print(colored("Scanning for SQL Injection vulnerabilities...", "blue"))
    for payload in payloads:
        test_url = f"{url}'{payload}"
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                print(colored(f"Potential SQL Injection vulnerability found at: {test_url}", "red"))
        except requests.RequestException as e:
            print(colored(f"Error: {e}", "red"))

def check_http_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        print(colored("Inspecting HTTP headers...", "blue"))
        print(colored("HTTP Headers:", "green"))
        for header, value in headers.items():
            print(colored(f"{header}: {value}", "green"))
    except requests.RequestException as e:
        print(colored(f"Error: {e}", "red"))

def main():
    print_heart_bear()
    print_header()
    print_menu()

    try:
        choice = int(input(colored("Enter your choice (1/2/3): ", "cyan")))
        if choice not in [1, 2, 3]:
            raise ValueError("Invalid choice")
    except ValueError as e:
        print(colored(f"Error: {e}", "red"))
        sys.exit(1)

    url = input(colored("Enter the URL to test (e.g., http://example.com): ", "cyan"))

    try:
        if choice == 1:
            check_xss(url)
        elif choice == 2:
            check_sql_injection(url)
        elif choice == 3:
            check_http_headers(url)
    except KeyboardInterrupt:
        print(colored("\nOperation cancelled by user.", "yellow"))
        sys.exit(0)

if __name__ == "__main__":
    main()
