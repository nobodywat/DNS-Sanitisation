
# DNS Blocking Method Analysis Project

This project analyzes different DNS blocking methods used by ISPs. It captures four methods:
1. DNS redirected/poisoning
2. DNS blackholed
3. DNS dropped with null entry
4. DNS dropped by firewall

## Dependencies

The project requires the `dnspython` module. Install it using pip:

```sh
pip3 install dnspython
```

## Cloudflare Dependency

This project is highly dependent on Cloudflare and their 1.1.1.1 DNS service, both in normal mode and in DoH (DNS over HTTPS) mode. It is highly recommended to ensure no filtering is in place by a network admin to 1.1.1.1 & one.one.one.one.

## Pre-Test Recommendations

1. Turn off the firewall on your device to avoid interference with the tests.
2. Perform a speed test before running the tests. The jitter should be less than 10 for accurate results. You can use [Cloudflare Speed Test](https://speed.cloudflare.com/) or any other jitter test site.

## Usage

### Step 1: Run the Sanitizer-TCP-Resolver

For Linux distributions:

This script processes DNS queries and generates an output file.

```sh
python3 sanitizer-tcp-resolver.py
```

For Windows:

This script processes DNS queries and generates an output file.

```sh
python3 sanitizer-tcp-resolver(windows).py
```

### Step 2: Run the Analyzer

This script analyzes the output from the first script. It also requires a list of Australian supernets in CIDR format, which should be updated monthly.

Download the latest list from [IP2Location Free Visitor Blocker](https://www.ip2location.com/free/visitor-blocker).

```sh
python3 analyzer.py australian-ipv4-cidr.txt
```

### Output

The `analyzer.py` script will create a folder with results, appending `-analyzed` to the name of the input file as the final output.

## Updating the Supernets List

To maintain higher accuracy, the list of Australian supernets in CIDR format should be updated monthly. Obtain the latest list from [IP2Location Free Visitor Blocker](https://www.ip2location.com/free/visitor-blocker).

## Testing with Fresh Domains

For testing against more fresh domains and on a larger scale, refer to the [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists?tab=readme-ov-file#tlds) GitHub project. The samples used in this project are sourced from there.

## Project Structure

- `sanitizer-tcp-resolver.py`: Script to process DNS queries for Linux.
- `sanitizer-tcp-resolver(windows).py`: Script to process DNS queries for Windows.
- `analyzer.py`: Script to analyze DNS blocking methods.
- `australian-ipv4-cidr.txt`: List of Australian supernets in CIDR format.
- `Fake-Phishing-Domains.txt`: Sample domains for testing.
- `Malware-Malicious-Domains.txt`: Sample domains for testing.
- `Pirate-Copyright-Domains.txt`: Sample domains for testing.
- `test results`: Directory containing test results.

## Future Work and Improvements

### Addressing Round Robin Load Balancing

The current framework needs to address the existence of round-robin load balancing, as it can produce false positives for the first method, which is redirected/poisoned DNS.

### Avoiding CDN False Positives

In our project, we tried to avoid falling into CDN false positives for redirected/poisoned DNS filtering by hardcoding the top 5 CDN IP ranges and then removing the list if it falls under that range. For a more comprehensive and reliable approach, it is best to use the [cloud-ip-ranges GitHub repository](https://github.com/femueller/cloud-ip-ranges) that has a larger and updated list. This can be very useful if the initial input domain to the script is pretty large and more diverse than our samples.

### Contributions Welcome

Any contributions to our project are welcome. We intend to expand this framework and repository to catch other blocking methods such as IP filtering and BGP filtering. Future improvements include:
- Capturing more DPI filtering methods beyond DNS queries, such as SNI DPI filtering. We also want to delve deeper into DPI by analyzing its detection behavior not only for headers but also for the body. For example, we plan to analyze and test DPI reactions to various cipher suite algorithms offered in both TLS 1.2 and TLS 1.3. We will focus particularly on stream ciphers in use, such as AES with different key sizes (128, 192, and 256), and bit-by-bit stream ciphers like ChaCha20. Additionally, we aim to examine integrity check methods such as CCMP, GCM, and Poly1305.

Your contributions and suggestions are highly appreciated to make this project more robust and comprehensive.
