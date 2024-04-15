import socket
import time

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

# Reading the domain names from a file, resolving them, and writing the resolvable ones to a new file
resolved_ips = []  # List to store resolved domains
resolved_domains = []  # List to store resolved domains

try:
    with open("domain_list.txt", "r") as file:
        domains = file.readlines()

    for domain in domains:
        domain = domain.strip()  # Clean any trailing newline characters
        ip = resolve_domain(domain)
        if ip:
            print(f'{domain}: {ip}')
            resolved_ips.append(ip + '\n')  # Append resolved domain with IP
            resolved_domains.append(domain + '\n')  # Append resolved domain
        else:
            print(f'Could not resolve {domain}')

        time.sleep(0.5)  # Sleep to prevent too many requests in a short time

    # Writing resolved domains to a new file
    with open("results/resolved_domains.txt", "w") as output_file:
        output_file.writelines(resolved_domains)
        
    # Writing resolved IPs to a new file
    with open("results/resolved_ips.txt", "w") as output_file:
        output_file.writelines(resolved_ips)

except FileNotFoundError:
    print("The file 'domain_list.txt' does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")