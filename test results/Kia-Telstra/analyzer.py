import os
import sys
import ipaddress
import multiprocessing
from functools import partial
import http.client
import json
import ssl
import dns.resolver
import dns.query


""" 

PLEASE ONLY INPUT THIS SCRIPT THE RESULT TXT FILE FROM sanitizer-tcp-Resolver.py 
which has the the word: Ready-For-Analyzer... at its first and make sure dnspython is installed, 
if not insatlled, you can install it by: 

pip install dnspython 

"""

# Define a list of known CDN IP ranges to check against
CDN_RANGES = [

    
#Amazon's CDN IP ranges (supernet)

"120.52.22.96/27", "205.251.249.0/24", "180.163.57.128/26", "204.246.168.0/22", "111.13.171.128/26", "18.160.0.0/15", "205.251.252.0/23", "54.192.0.0/16", "204.246.173.0/24", "54.230.200.0/21", "120.253.240.192/26", "116.129.226.128/26", "130.176.0.0/17", "108.156.0.0/14", "99.86.0.0/16", "13.32.0.0/15", "120.253.245.128/26", "13.224.0.0/14", "70.132.0.0/18", "15.158.0.0/16", "111.13.171.192/26", "13.249.0.0/16", "18.238.0.0/15", "18.244.0.0/15", "205.251.208.0/20", "3.165.0.0/16", "3.168.0.0/14", "65.9.128.0/18", "130.176.128.0/18", "58.254.138.0/25", "205.251.201.0/24", "205.251.206.0/23", "54.230.208.0/20", "3.160.0.0/14", "116.129.226.0/25", "52.222.128.0/17", "18.164.0.0/15", "111.13.185.32/27", "64.252.128.0/18", "205.251.254.0/24", "3.166.0.0/15", "54.230.224.0/19", "71.152.0.0/17", "216.137.32.0/19", "204.246.172.0/24", "205.251.202.0/23", "18.172.0.0/15", "120.52.39.128/27", "118.193.97.64/26", "3.164.64.0/18", "18.154.0.0/15", "54.240.128.0/18", "205.251.250.0/23", "180.163.57.0/25", "52.46.0.0/18", "52.82.128.0/19", "54.230.0.0/17", "54.230.128.0/18", "54.239.128.0/18", "130.176.224.0/20", "36.103.232.128/26", "52.84.0.0/15", "143.204.0.0/16", "144.220.0.0/16", "120.52.153.192/26", "119.147.182.0/25", "120.232.236.0/25", "111.13.185.64/27", "103.224.212.0/23", "103.180.114.0/24", "3.164.0.0/18", "54.182.0.0/16", "58.254.138.128/26", "120.253.245.192/27", "54.239.192.0/19", "18.68.0.0/16", "18.64.0.0/14", "120.52.12.64/26", "99.84.0.0/16", "205.251.204.0/23", "130.176.192.0/19", "52.124.128.0/17", "205.251.200.0/24", "204.246.164.0/22", "13.35.0.0/16", "204.246.174.0/23", "3.164.128.0/17", "3.172.0.0/18", "36.103.232.0/25", "119.147.182.128/26", "118.193.97.128/25", "120.232.236.128/26", "204.246.176.0/20", "65.8.0.0/16", "65.9.0.0/17", "108.138.0.0/15", "120.253.241.160/27", "64.252.64.0/18", "13.113.196.64/26", "13.113.203.0/24", "52.199.127.192/26", "13.124.199.0/24", "3.35.130.128/25", "52.78.247.128/26", "13.233.177.192/26", "15.207.13.128/25", "15.207.213.128/25", "52.66.194.128/26", "13.228.69.0/24", "52.220.191.0/26", "13.210.67.128/26", "13.54.63.128/26", "3.107.43.128/25", "3.107.44.0/25", "3.107.44.128/25", "43.218.56.128/26", "43.218.56.192/26", "43.218.56.64/26", "43.218.71.0/26", "99.79.169.0/24", "18.192.142.0/23", "18.199.68.0/22", "18.199.72.0/22", "18.199.76.0/22", "35.158.136.0/24", "52.57.254.0/24", "18.200.212.0/23", "52.212.248.0/26", "18.175.65.0/24", "18.175.66.0/24", "18.175.67.0/24", "3.10.17.128/25", "3.11.53.0/24", "52.56.127.0/25", "15.188.184.0/24", "52.47.139.0/24", "3.29.40.128/26", "3.29.40.192/26", "3.29.40.64/26", "3.29.57.0/26", "18.229.220.192/26", "18.230.229.0/24", "18.230.230.0/25", "54.233.255.128/26", "3.231.2.0/25", "3.234.232.224/27", "3.236.169.192/26", "3.236.48.0/23", "34.195.252.0/24", "34.226.14.0/24", "44.220.194.0/23", "44.220.196.0/23", "44.220.198.0/23", "44.220.200.0/23", "44.220.202.0/23", "44.222.66.0/24", "13.59.250.0/26", "18.216.170.128/25", "3.128.93.0/24", "3.134.215.0/24", "3.146.232.0/22", "3.147.164.0/22", "3.147.244.0/22", "52.15.127.128/26", "3.101.158.0/23", "52.52.191.128/26", "34.216.51.0/25", "34.223.12.224/27", "34.223.80.192/26", "35.162.63.192/26", "35.167.191.128/26", "35.93.168.0/23", "35.93.170.0/23", "35.93.172.0/23", "44.227.178.0/24", "44.234.108.128/25", "44.234.90.252/30",

#Akamai's CDN IP ranges(supernet)

"23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "104.64.0.0/10", "184.24.0.0/13", "23.0.0.0/12", "95.100.0.0/15", "92.122.0.0/15", "184.50.0.0/15", "88.221.0.0/16", "23.64.0.0/14", "72.246.0.0/15", "96.16.0.0/15", "96.6.0.0/15", "69.192.0.0/16", "23.72.0.0/13", "173.222.0.0/15", "118.214.0.0/16", "184.84.0.0/14",

#Cloudflare's CDN IP ranges(supernet)

"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",

#Fastly's CDN IP ranges(supernet)

"23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23","103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17","146.75.0.0/17","151.101.0.0/16","157.52.64.0/18",
"167.82.0.0/17","167.82.128.0/20","167.82.160.0/20","167.82.224.0/20","172.111.64.0/18","185.31.16.0/22","199.27.72.0/21","199.232.0.0/16",


#Goolge's CDN IP ranges(supernet)

"8.8.4.0/24", "8.8.8.0/24", "8.34.208.0/20", "8.35.192.0/20", "23.236.48.0/20", "23.251.128.0/19", "34.0.0.0/15", "34.2.0.0/16", "34.3.0.0/23", "34.3.3.0/24", "34.3.4.0/24", "34.3.8.0/21", "34.3.16.0/20", "34.3.32.0/19", "34.3.64.0/18", "34.4.0.0/14", "34.8.0.0/13", "34.16.0.0/12", "34.32.0.0/11", "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17", "35.199.128.0/18", "35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13", "64.15.112.0/20", "64.233.160.0/19", "66.22.228.0/23", "66.102.0.0/20", "66.249.64.0/19", "70.32.128.0/19", "72.14.192.0/18", "74.125.0.0/16", "104.154.0.0/15", "104.196.0.0/14", "104.237.160.0/19", "107.167.160.0/19", "107.178.192.0/18", "108.59.80.0/20", "108.170.192.0/18", "108.177.0.0/17", "130.211.0.0/16", "142.250.0.0/15", "146.148.0.0/17", "162.216.148.0/22", "162.222.176.0/21", "172.110.32.0/21", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "173.255.112.0/20", "192.158.28.0/22", "192.178.0.0/15", "193.186.4.0/24", "199.36.154.0/23", "199.36.156.0/24", "199.192.112.0/22", "199.223.232.0/21", "207.223.160.0/20", "208.65.152.0/22", "208.68.108.0/22", "208.81.188.0/22", "208.117.224.0/19", "209.85.128.0/17", "216.58.192.0/19", "216.73.80.0/20", "216.239.32.0/19", 


]


def is_cdn_ip(ip):
    """Check if the IP belongs to any known CDN ranges."""
    for cidr in CDN_RANGES:
        if ip in ipaddress.ip_network(cidr):
            return True
    return False

def load_aus_ips(aus_ip_file):
    """Load Australian IP networks from a file."""
    networks = []
    with open(aus_ip_file) as f:
        for line in f:
            try:
                network = ipaddress.ip_network(line.strip())
                networks.append(network)
            except ValueError:
                continue
    return networks

def is_australian_ip(ip, networks):
    """Check if the IP is within the specified Australian IP networks."""
    for network in networks:
        if ip in network:
            return True
    return False

def resolve_with_standard_dns(domain):
    """Resolve the domain using DNS over TCP to 1.1.1.1 in plaintext mode to catch firewalls."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']
        resolver.use_tcp = True
        answers = resolver.resolve(domain, 'A')
        return answers[0].address
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None

def resolve_with_doh(domain):
    """Resolve the domain using DNS over HTTPS to Cloudflare's DNS."""
    headers = {"Accept": "application/dns-json"}
    conn = http.client.HTTPSConnection("cloudflare-dns.com", context=ssl.create_default_context())
    try:
        conn.request("GET", f"/dns-query?name={domain}&type=A", headers=headers)
        response = conn.getresponse()
        if response.status == 200:
            data = response.read()
            results = json.loads(data)
            if "Answer" in results and results["Answer"]:
                return results["Answer"][0]["data"]
        return None
    finally:
        conn.close()

def process_line(line, aus_networks, output_dir):
    parts = line.split('\t')
    if len(parts) != 2:
        return  # Skip malformed lines

    domain, ip_str = parts
    ip_str = ip_str.strip()

    if ip_str == 'nothing':
        resolved_ip = resolve_with_standard_dns(domain)
        if resolved_ip is None:
            with open(os.path.join(output_dir, 'DNS-Dropped(Firewall).txt'), 'a') as dns_dropped_firewall:
                dns_dropped_firewall.write(f"{domain}\t{ip_str}\n")
        else:
            with open(os.path.join(output_dir, 'DNS-Dropped(Null-Entry).txt'), 'a') as dns_dropped_null:
                dns_dropped_null.write(f"{domain}\t{resolved_ip}\n")
        return

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return  # Skip invalid IP addresses

    resolved_ip = resolve_with_doh(domain)
    line_to_write = f"{domain}\t{ip_str}\n"

    if ip.is_private or ip.is_loopback:
        with open(os.path.join(output_dir, 'DNS-Blackholing.txt'), 'a') as dns_blackholing:
            dns_blackholing.write(line_to_write)
    elif is_cdn_ip(ip):
        with open(os.path.join(output_dir, 'NotBlocked.txt'), 'a') as not_blocked:
            not_blocked.write(line_to_write)
    elif resolved_ip == ip_str and is_australian_ip(ip, aus_networks):
        with open(os.path.join(output_dir, 'NotBlocked.txt'), 'a') as not_blocked:
            not_blocked.write(line_to_write)
    elif is_australian_ip(ip, aus_networks):
        if resolved_ip != ip_str:
            with open(os.path.join(output_dir, 'High-Potential-DNS-Redirected.txt'), 'a') as dns_redirected:
                dns_redirected.write(line_to_write)
    else:
        with open(os.path.join(output_dir, 'NotBlocked.txt'), 'a') as not_blocked:
            not_blocked.write(line_to_write)


def append_statistics_to_file(output_dir, domain_count):
    """Append statistics to each result file."""
    files = [
        'High-Potential-DNS-Redirected.txt',
        'DNS-Blackholing.txt',
        'DNS-Dropped(Firewall).txt',
        'DNS-Dropped(Null-Entry).txt',
        'NotBlocked.txt'
    ]
    for file_name in files:
        path = os.path.join(output_dir, file_name)
        if os.path.exists(path):
            with open(path, 'r+') as file:
                lines = file.readlines()
                block_count = len(lines)
                rate = (block_count / domain_count) * 100 if domain_count else 0
                # Move file pointer to the end of the file to append data
                file.seek(0, os.SEEK_END)
                file.write('\n' * 5)
                file.write(f"Rate-For-{file_name} found to be: {rate:.2f}%\n")


def run_analyzer(domain_file, aus_ip_file):
    aus_networks = load_aus_ips(aus_ip_file)
    output_dir = domain_file.rsplit('.', 1)[0] + '-analyzed'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(domain_file) as f:
        lines = f.readlines()
        domain_count = len(lines)
        pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
        process_line_partial = partial(process_line, aus_networks=aus_networks, output_dir=output_dir)
        pool.map(process_line_partial, lines)
        pool.close()
        pool.join()
    
    append_statistics_to_file(output_dir, domain_count)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 analyzer.py domain-list.txt australian-ipv4-cidr.txt")
        sys.exit(1)
    
    domain_file, aus_ip_file = sys.argv[1], sys.argv[2]
    run_analyzer(domain_file, aus_ip_file)

