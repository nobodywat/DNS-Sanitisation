# author: tim

# check-host icmp
# check-host tcp

import requests
import json
import time
    
def check_host_icmp(target_ip):
    # send request to check_host API for target_ip
    # returns json object of results

    # create request
    url="https://check-host.net/check-ping"
    headers={
        "Accept": "application/json"
    }
    params={
        "host": target_ip, 
        "max_nodes": "3"
    }

    # send request and receive response 
    response=requests.post(url, headers=headers, params=params)
    
    # save response as dict
    res_dict=json.loads(response.json())
    # read request id
    req_id=res_dict['request_id']

    url="https://check-host.net/check-result/".join(req_id)
    headers={"Accept": "application/json"}

    # send request
    response=requests.post(url, headers=headers)

    # return results as json object
    return response.json()

def check_ok ()

ip_list="test_ip_list.txt"
clean_ip_list="clean_ips.txt"
resolved_ips = []  # List to store resolved ips

try:
    with open(ip_list, "r") as file:
        dirty_ips = file.readlines()

    for ip in dirty_ips:
        ip = ip.strip()  # Clean any trailing newline characters

        # check if ip is online using check_host API, protocol:ICMP
        results=check_host_icmp(ip)

        time.sleep(0.5)  # Sleep to prevent too many requests in a short time

    # Writing resolved domains to a new file
    with open(clean_ip_list, "w") as output_file:
        output_file.writelines(resolved_ips)

except FileNotFoundError:
    print("The file", ip_list, "does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")