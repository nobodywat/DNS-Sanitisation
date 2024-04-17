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

    time.sleep(2) # sleep for 2 sec to allow the results to load

    # send request
    response=requests.get(resUrl, headers=headers)

    # return results as json object
    return response.json()


def checkLeastOk(jsonResult, phrase):
    # check json for at least one occurence of phrase
    # returns index if found and -1 if not found.
    return json.dumps(jsonResult).find(phrase)


listA='IP/list_a.txt' # online, allow icmp
listB='IP/list_b.txt' # online, block icmp
unblockedIps=[]
blockedIps=[]

# icmp test chunk
try: 
    with open(listA, "r") as file:
        listAIps = file.readlines()

    for ip in listAIps:
        ip=ip.strip()

        checkHostRes=checkHost(ip, "icmp")
        checkOk=checkLeastOk(checkHostRes, "OK")

        if checkOk==-1: # if check fails
            blockedIps.append(ip+"\n")
        else:
            unblockedIps.append(ip+"\n")

except FileNotFoundError:
    print("The file", listA, "does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")

# tcp test chunk
try: 
    with open(listB, "r") as file:
        listBIps = file.readlines()

    for ip in listBIps:
        ip=ip.strip()

        checkHostRes=checkHost(ip, "tcp")
        checkOk=checkLeastOk(checkHostRes, "time")

        if checkOk==-1: # if check fails
            blockedIps.append(ip+"\n")
        else:
            unblockedIps.append(ip+"\n")

except FileNotFoundError:
    print("The file", listB, "does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")

with open("IP/blockedIps.txt", "w") as outputFile:
        outputFile.writelines(blockedIps)

with open("IP/unblockedIps.txt", "w") as outputFile:
        outputFile.writelines(unblockedIps)



print("Program ended successfully----------------------------------------------------------------------------------------------------")
endTime=time.time()
print("Elapsed time: ", endTime-startTime)