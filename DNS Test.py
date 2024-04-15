import socket
import time
import ipaddress

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

# Reading the domain names from a file, resolving them, and writing the resolvable ones to a new file
dns_dropping = []  # List to store resolved domains
blackholing = []  # List to store private IPs
redirection = []  # List to store IPs that are not from Australia
unblocked = []  # List to store domains that are not blocked

private_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

try:
    with open("resolved_domains.txt", "r") as file:
        domains = file.readlines()

    with open("firewall.txt", "r") as ip_file:
        aus_ips = ip_file.readlines()

    for domain in domains:
        domain = domain.strip()  # Clean any trailing newline characters
        ip = resolve_domain(domain)
        if ip:
            print(f'{domain} with IP:{ip} passed the DNS resolution test moving onto next test')
            
            for private_ip in private_ips:
                if ipaddress.ip_address(ip) not in ipaddress.ip_network(private_ip):
                    print(f'{domain} with IP:{ip} is not a private IP address within {private_ip}')
                    
                    for aus_ip in aus_ips:
                        if ipaddress.ip_address(ip) not in ipaddress.ip_address(aus_ip):
                            redirection.append(domain + ":" + ip + '\n')
                            print(f'{domain} with IP:{ip} redirects to a non-Australian IP address')
                            
                        else:
                            unblocked.append(domain + ":" + ip + '\n')
                            print(f'{domain} with IP:{ip} is not blocked')
                            
                else:
                    blackholing.append(domain + ":" + ip + '\n')  
                    print(f'{domain} with IP:{ip} is a private IP address')
                    
        else:
            dns_dropping.append(domain + ":" + ip + '\n')
            print(f'Could not resolve {domain}')
            
        time.sleep(0.5)  # Sleep to prevent too many requests in a short time

    # Writing resolved domains to a new file
    with open("resolved_domains.txt", "w") as output_file:
        output_file.writelines(resolved_domains)
        
    # Writing resolved IPs to a new file
    with open("resolved_ips.txt", "w") as output_file:
        output_file.writelines(resolved_ips)

except FileNotFoundError:
    print("The file 'domain_list.txt' does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")