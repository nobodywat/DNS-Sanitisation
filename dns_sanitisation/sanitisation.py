import socket
import time

def resolveDomain(domain): # Function to resolve a domain name to an IP address
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

# Reading the domain names from a file, resolving them, and writing the resolvable ones to a new file
resolvedIPs = []  # List to store resolved domains
resolvedDomains = []  # List to store resolved domains

try:
    with open("domain_list.txt", "r") as file:
        domains = file.readlines()

    for domain in domains:
        domain = domain.strip()  # Clean any trailing newline characters
        ip = resolveDomain(domain)
        if ip:
            print(f'{domain}: {ip}')
            resolvedIPs.append(ip + '\n')  # Append resolved domain with IP
            resolvedDomains.append(domain + '\n')  # Append resolved domain
        else:
            print(f'Could not resolve {domain}')

        time.sleep(0.5)  # Sleep to prevent too many requests in a short time

    # Writing resolved domains to a new file
    with open("results/resolved_domains.txt", "w") as output:
        output.writelines(resolvedDomains)
        
    # Writing resolved IPs to a new file
    # with open("results/resolved_ips.txt", "w") as output:
    #     output.writelines(resolvedIPs)

except FileNotFoundError:
    print("The file 'domain_list.txt' does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")