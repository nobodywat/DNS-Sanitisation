import socket
import time
import ipaddress

def resolveDomain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

# Initialize lists for each label
dnsDropping = []
blackholing = []
redirection = []
unblocked = []

# Define private and Australian IP networks
privateIPs = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")] # Private IP networks
ausIPs = []
try:
    with open('../dns_sanitisation/results/resolved_domains.txt', "r") as file:
        domains = file.read().splitlines()

    with open("firewall.txt", "r") as ip_file:
        ausIPs = [ipaddress.ip_network(line.strip()) for line in ip_file] # Read Australian IP networks from file

    for domain in domains:
        ip = resolveDomain(domain)
        if ip:
            print(f'{domain}: {ip} was resolved successfully')
            ipObj = ipaddress.ip_address(ip)
            if any(ipObj in net for net in privateIPs): # Check if IP is in private network
                blackholing.append(domain + ": " + ip + '\n')
                print(f'{domain} with IP:{ip} is a private IP address')
                
            elif any(ipObj in net for net in ausIPs): # Check if IP is in Australian network
                unblocked.append(domain + ": " + ip + '\n')
                print(f'{domain} with IP:{ip} is an Australian IP and is not blocked')
                
            else:
                redirection.append(domain + ": " + ip + '\n') # IP is not in Australian network
                print(f'{domain} with IP:{ip} redirects to a non-Australian IP address')
                
        else:
            dnsDropping.append(domain + '\n')
            print(f'Could not resolve {domain}')

        time.sleep(0.5)

    # Save results to files
    with open("results/dnsDropping.txt", "w") as file:
        file.writelines(dnsDropping)

    with open("results/blackholing.txt", "w") as file:
        file.writelines(blackholing)

    with open("results/redirection.txt", "w") as file:
        file.writelines(redirection)
        
    with open("results/unblocked.txt", "w") as file:
        file.writelines(unblocked)

except FileNotFoundError as e:
    print(f"Error: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
