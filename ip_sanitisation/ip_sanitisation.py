# author: tim

# check-host icmp
# check-host tcp

import requests
import json
import time

start_time=time.time()
print("Program running..................................................................................................................")
    
def check_host(target_ip, protocol):
    url="https://check-host.net/"
    res_url="https://check-host.net/check-result/"

    # create request
    headers={
        "Accept": "application/json"
    }
    params={
        "host": target_ip, 
        # "max_nodes": "3"
    }


    if protocol=="icmp":
        url=url+"check-ping"

    elif protocol=="tcp":
        url=url+"check-tcp"
        params={
        "host": target_ip+":443", 
        # "max_nodes": "3"
        }
    else:
        print("Invalid protocol specified")
        return 0

    # send request to check_host API for target_ip
    # returns json object of results

    # send request and receive response 
    res=requests.get(url, headers=headers, params=params).json()
    
    # read request id
    req_id=res["request_id"]

    res_url=res_url+req_id

    time.sleep(2) # sleep for 1 sec to allow the results to load

    # send request
    response=requests.get(res_url, headers=headers)

    # return results as json object
    return response.json()


def check_least_ok(json_result, phrase):
    # check json for at least one occurence of phrase
    # returns index if found and -1 if not found.
    return json.dumps(json_result).find(phrase)


ip_list="ip_sanitisation/test_ip_list.txt"
online_ips = []
offline_ips = []

try:
    with open(ip_list, "r") as file:
        dirty_ips = file.readlines()

    for ip in dirty_ips:
        ip = ip.strip()  # Clean any trailing newline characters

        check_host_res=check_host(ip, "icmp")
        check_ok=check_least_ok(check_host_res, "OK")
        if check_ok==-1: # if check using icmp fail, 

            check_host_res=check_host(ip, "tcp")
            check_ok=check_least_ok(check_host_res, "time")
            if check_ok==-1: # if check using tcp fail,
                offline_ips.append(ip+"\n") # IP is offline
            else:
                online_ips.append(ip+"\n") # IP is online but blocks icmp

        else: # if check using icmp pass,
            online_ips.append(ip+"\n") # IP is online

    # write online_ips to file
    with open("ip_sanitisation/online_ips.txt", "w") as output_file:
        output_file.writelines(online_ips)

    # write offline_ips to file
    with open("ip_sanitisation/offline_ips.txt", "w") as output_file:
        output_file.writelines(offline_ips)

except FileNotFoundError:
    print("The file", ip_list, "does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")

print("Program ended successfully----------------------------------------------------------------------------------------------------")
end_time=time.time()
print("Elapsed time: ", end_time-start_time)