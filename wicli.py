#!/usr/bin/env python
"""
This script automatically creates users on the Symantec Web isolation demo portal
Copyright - Symantec Inc.

"""

__author__ = "Fabio Rosa"
__version__ = "0.2"
__license__ = "MIT"

import sys, argparse, requests, json, time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument('username', help="enter the username to be added to the web isolation platform (usually e-mail address). Uppercases will be automatically converted to lowercase.")
parser.add_argument("--password", "-p", required=True, help="(Mandatory) Enter here the desired password for the new user")
parser.add_argument("--commit", "-c", help="(Optional) Use this option if you want to commit changes after processing this request", action="store_true")
args = parser.parse_args()

def main():
    # ENTER YOUR ADMIN CREDENTIALS BELOW, KEEPING THE DOUBLE QUOTES
    # #####################
    admin_username = "you@symantec.com"
    admin_password = "your admin pass"
    wiMgmtURL = "https://demo-mgmt.isolation.symantec.com:9000"
    # DONT CHANGE ANYTHING BELOW THIS LINE
    # #####################

    token = generateToken(admin_username,admin_password, wiMgmtURL)
    addUser(args.username, args.password, wiMgmtURL, token)

    if args.commit:
        commitConfig(wiMgmtURL, token)

def generateToken(admin_username, admin_password, url):
    username = str(sys.argv[1]).lower() #transform e-mail to lowercase for standarization.
    password = str(sys.argv[2])

    url = url + "/authentication/newtoken"
    data = {"username": admin_username,"password": admin_password}

    r = requests.post((url), data=data, verify=False)
    json_response = json.loads(r.text)
    token = json_response['token']

    return token

def addUser(username,password,url,token):
    url2 = url + "/users"
    data2 = {"groups": [],"type": "custom","name": username,"email": username,"password": password,"passwordagain": password}
    headers = {"Authorization": "Bearer "+token}
    #print str(headers)

    r = requests.post((url2), data=data2, headers=headers, verify=False)
    json_response = json.loads(r.text)

	#print r.request.headers
	#print r.text
    if json_response['name'] == username:
        print "User Created successfully"
        print
        print "Username:", username
        print "Password:", password
        print
    else:
        print "Ops! Something went wrong:", r.text
        sys.exit()

def commitConfig(url, token):
    url2 = url + "/gateways/reconfigure"
    headers = {"Authorization": "Bearer "+token}

    r = requests.get((url2), headers=headers, verify=False)

    loopUntilCompleted(url, token)

def loopUntilCompleted(url, token):
    url2 = url + "/managementaudit/pendingpush"
    headers = {"Authorization": "Bearer "+token}

    while True:
        time.sleep(0.5)
        r = requests.get((url2), headers=headers, verify=False)
        json_response = json.loads(r.text)
        pendingChanges = json_response['pendingChanges']
        if pendingChanges == 0:
            print
            print "Configuration applied successfully!"
            break
        else:
            sys.stdout.write('.')


if __name__ == "__main__":
	main()
