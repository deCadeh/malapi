################################################################################
# VTAPI                                                                        #
# Simple CLI for interfacing with VirusTotal's API.                            #
# So far, it can only retrieve scans from API based on SHA256 hash values.     #
# (JFGI: Warnings about uploading files for scanning.)                         #
# Absolute path to file/s is/are required.                                     #
# Will return number of positive detections and total number of engines.       #
#                                                                              #
# NOTES:                                                                       #
# Have not yet tested on non-Linux platforms.                                  #
# But should work.                                                             #
#                                                                              #
# REQUIREMENTS:                                                                #
# Python requests                                                              #
# VirusTotal API key                                                           #
#                                                                              #
# TODO:                                                                        #
# Implement ability to scan hashes from a text file.                           #
################################################################################
#!/usr/bin/python3

import os
import requests
import hashlib
import time

#config
# path to file with VTAPI key
apifile = ""

header = ("===== VTAPI =====\n"
    "Edit config file with your VirusTotal API key.\n\n"
    "The program will timeout after four consecutive retrievals.\n"
    "(This is to stay under VT API rate limit.)\n\n"
    "Currently only retrieves scans via SHA256 hashes of files.\n"
    "For proper usage, specify absolute filepath to samples directory.\n")

print(header)

url = 'https://www.virustotal.com/vtapi/v2/file/report'
headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  Mozilla"
}

with open(apifile, "r") as f:
    vtapikey = f.read().strip()

path = str(input("Enter /full/path/to/files: "))
print()

for root, subdirs, files in os.walk(path):
    for filename in files:
        f = os.path.join(root, filename)
        f = open(f, "rb")
        fbytes = f.read()
        sha256 = hashlib.sha256(fbytes).hexdigest()
        params = {
            'apikey': vtapikey,
            'resource': sha256
        }
        res = requests.get(url, params=params, headers=headers)
        if res.status_code is 204:
            print("Reached API limit. Please wait.\n")
            time.sleep(60)
            res = requests.get(url, params=params, headers=headers)
        positives = res.json()['positives'] if 'positives' in res.json() else 0
        total = res.json()['total'] if 'total' in res.json() else 0
        print("File: %s\nNo scans conducted for this file.\n" % (f.name))\
            if total is 0 else\
            print("File: %s\nPositives: %d\nTotal: %d\nDetection rate: %f%%\n"
                % (f.name, positives, total, (positives / total) * 100))
    f.close()

