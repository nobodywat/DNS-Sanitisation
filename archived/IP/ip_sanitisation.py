# author: tim

# check-host icmp
# check-host tcp

import requests
import json
import time
import ipaddress

startTime=time.time()
print("Program running..................................................................................................................")
    
def checkHost(targetIp, protocol):
    url="https://check-host.net/"
    resUrl="https://check-host.net/check-result/"

    # create request
    headers={
        "Accept": "application/json"
    }
    params={
        "host": targetIp, 
        # "max_nodes": "3"
    }


    if protocol=="icmp":
        url=url+"check-ping"

    elif protocol=="tcp":
        url=url+"check-tcp"
        params={
        "host": targetIp+":443", 
        # "max_nodes": "3"
        }
    else:
        print("Invalid protocol specified")
        return 0

    # send request to check_host API for targetIp
    # returns json object of results

    # send request and receive response 
    res=requests.get(url, headers=headers, params=params).json()
    
    # read request id
    reqId=res["request_id"]

    resUrl=resUrl+reqId

    time.sleep(2) # sleep for 1 sec to allow the results to load

    # send request
    response=requests.get(resUrl, headers=headers)

    # return results as json object
    return response.json()


def checkLeastOk(jsonResult, phrase):
    # check json for at least one occurence of phrase
    # returns index if found and -1 if not found.
    return json.dumps(jsonResult).find(phrase)


# returns 1 if ip IS private,
# returns 0 if ip IS NOT private
def inSubnet(ip, subnetList):
    ipAddr=ipaddress.ip_address(ip)

    for range in subnetList:
        subnet=ipaddress.ip_network(range)

        if ipAddr in subnet:
            return 1 

    return 0 


ipList="IP/test_ip_list.txt"
listA = []
listB = []
offlineIps = []

try:
    with open(ipList, "r") as file:
        dirtyIps = file.readlines()

    for ip in dirtyIps:
        ip = ip.strip()  # Clean any trailing newline characters

        # check ip not private
        privRanges=['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        if inSubnet(ip, privRanges)==0:

            checkHostRes=checkHost(ip, "icmp")
            checkOk=checkLeastOk(checkHostRes, "OK")
            if checkOk==-1: # if check using icmp fail, 
                checkHostRes=checkHost(ip, "tcp")
                checkOk=checkLeastOk(checkHostRes, "time")
                if checkOk==-1: # if check using tcp fail,
                    offlineIps.append(ip+"\n") # IP is offline
                else:
                    listB.append(ip+"\n") # IP is online but blocks icmp: add to list B
            else: # if check using icmp pass,
                listA.append(ip+"\n") # IP is online: add to list A
                

    # write online_ips to file
    with open("IP/list_a.txt", "w") as outputFile:
        outputFile.writelines(listA)

    with open("IP/list_b.txt", "w") as outputFile:
        outputFile.writelines(listB)

    # write offline_ips to file
    with open("IP/offline_ips.txt", "w") as outputFile:
        outputFile.writelines(offlineIps)

except FileNotFoundError:
    print("The file", ipList, "does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")

print("Program ended successfully----------------------------------------------------------------------------------------------------")
endTime=time.time()
print("Elapsed time: ", endTime-startTime)