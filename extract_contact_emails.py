#!/usr/bin/env python3

# Get all contact emails from a given IP by whois and rdap query
#
# dependencies:
# pip install python-whois requests ipwhois

import re
import whois
import requests
import sys
import ipaddress
from ipwhois import IPWhois
import json

def extract_emails_from_text(text):
    """Extract email addresses from a given text."""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)

def get_whois_emails(ip):
    """Get contact emails from WHOIS data."""
    try:
        whois_data = whois.whois(ip)
        if whois_data.text:
            return extract_emails_from_text(whois_data.text)
    except Exception as e:
        print(f"Error fetching WHOIS data: {e}")
    return []

def get_ipwhois_emails(ip):
    """Get contact emails from WHOIS data."""
    try:
        ipwhois_data = IPWhois(ip)
        if ipwhois_data.lookup_whois():
            return extract_emails_from_text(json.dumps(ipwhois_data.lookup_whois()))
    except Exception as e:
        print(f"Error fetching IPWHOIS data: {e}")
    return []
    
def get_rdap_emails(ip):
    """Get contact emails from RDAP data."""
    rdap_url = f"https://rdap.arin.net/registry/ip/{ip}"
    try:
        response = requests.get(rdap_url, timeout=10)
        if response.status_code == 200:
            rdap_data = response.json()
            emails = []
            if "entities" in rdap_data:
                for entity in rdap_data["entities"]:
                    if "vcardArray" in entity:
                        for vcard in entity["vcardArray"][1]:
                            if vcard[0] == "email":
                                emails.append(vcard[3])
            return emails
    except Exception as e:
        print(f"Error fetching RDAP data: {e}")
    return []

def main():
    if len(sys.argv) != 2:
        print("Usage: python extract_contact_emails.py <IP_ADDRESS>")
        sys.exit(1)

    try:
        ip = ipaddress.ip_address(sys.argv[1])
        ip = sys.argv[1]
    except ValueError:
        print('IP address invalid: %s' % sys.argv[1])
        sys.exit(2)
    except:
        print("Usage: python extract_contact_emails.py <IP_ADDRESS>")
        sys.exit(2)
    
    print(f"Fetching contact emails for IP: {ip}\n")

    #whois_emails = get_whois_emails(ip)
    ipwhois_emails = get_ipwhois_emails(ip)
    rdap_emails = get_rdap_emails(ip)

    #all_emails = set(whois_emails + rdap_emails)
    all_emails = set(ipwhois_emails + rdap_emails)

    if all_emails:
        print("Contact Emails Found:")
        for email in all_emails:
            print(email)
    else:
        print("No contact emails found.")

if __name__ == "__main__":
    main()
