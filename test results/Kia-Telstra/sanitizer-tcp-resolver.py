import sys
import multiprocessing
import http.client
import ssl
import json
import urllib.parse
import dns.resolver
import dns.query
import time

# Try to import dnspython modules with error handling
try:
    import dns.resolver
    import dns.query
except ImportError:
    print("Error: dnspython module is not installed.")
    sys.exit(1)

def resolve_with_doh(domain):
    """Resolve the domain using DNS over HTTPS to Cloudflare's DNS."""
    headers = {"Accept": "application/dns-json"}
    conn = http.client.HTTPSConnection("cloudflare-dns.com", context=ssl.create_default_context())
    try:
        safe_domain = urllib.parse.quote(domain)
        conn.request("GET", f"/dns-query?name={safe_domain}&type=A", headers=headers)
        response = conn.getresponse()
        if response.status == 200:
            data = response.read()
            results = json.loads(data)
            if "Answer" in results and results["Answer"]:
                return results["Answer"][0]["data"]
        return None
    finally:
        conn.close()

def resolve_ip(domain, attempts=3, delay=2):
    """Resolve the IP address of a domain using DNS over TCP with retry logic."""
    resolver = dns.resolver.Resolver()
    resolver.use_tcp = True
    for attempt in range(attempts):
        try:
            answers = resolver.resolve(domain, 'A')
            return answers[0].address
        except Exception:
            if attempt < attempts - 1:
                time.sleep(delay)
    return "nothing"

def filter_domain(domain):
    """Filter domains based on DNS resolution."""
    trimmed_domain = domain.strip()
    if resolve_with_doh(trimmed_domain):
        return trimmed_domain
    return None

def remove_duplicates(domains):
    """Remove duplicates from the list of domains, ignoring case sensitivity."""
    seen = set()
    unique_domains = []
    for domain in domains:
        normalized_domain = domain.strip().lower()
        if normalized_domain not in seen:
            seen.add(normalized_domain)
            unique_domains.append(domain.strip())
    return unique_domains

def filter_domains(domains):
    """Filter domains using multiprocessing to only include those with active DNS records."""
    pool = multiprocessing.Pool(processes=min(8, multiprocessing.cpu_count()))
    filtered_domains = pool.map(filter_domain, domains)
    pool.close()
    pool.join()
    return [domain for domain in filtered_domains if domain is not None]

def process_domains(domains, queue):
    """Process each domain to resolve their IP using DNS over TCP and send results to the queue."""
    for domain in domains:
        ip = resolve_ip(domain)
        queue.put(f"{domain}\t{ip}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py domain.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    output_filename = f"Ready-For-Analyzer-{input_file.replace('.txt', '')}.txt"

    with open(input_file, "r") as f:
        domains = f.read().splitlines()

    domains = remove_duplicates(domains)
    live_domains = filter_domains(domains)

    queue = multiprocessing.Queue()
    processes = []
    num_processes = min(8, multiprocessing.cpu_count())
    chunks = [live_domains[i::num_processes] for i in range(num_processes)]

    for i in range(num_processes):
        process = multiprocessing.Process(target=process_domains, args=(chunks[i], queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    with open(output_filename, "w") as output_file:
        while not queue.empty():
            output_file.write(queue.get() + "\n")

    print(f"Results have been saved to {output_filename}")

