#!/bin/sh

python3 sanitizer-tcp-resolver.py Pirate-Copyright-Domains.txt && python3 sanitizer-tcp-resolver.py Malware-Malicious-Domains.txt && python3 sanitizer-tcp-resolver.py Fake-Phishing-Domains.txt && python3 analyzer.py Ready-For-Analyzer-Pirate-Copyright-Domains.txt australian-ipv4-cidr.txt && python3 analyzer.py Ready-For-Analyzer-Malware-Malicious-Domains.txt australian-ipv4-cidr.txt && python3 analyzer.py Ready-For-Analyzer-Fake-Phishing-Domains.txt australian-ipv4-cidr.txt
