# -*- coding: utf-8 -*-
"""
POE DreamCatcher script.
Created on Wed Mar 27 20:49:11 2019
@author: JCChen
"""

import json
import requests
import hashlib
import base64
import time
import random
import sys
from Crypto.Cipher import AES

# Login URL
LOGIN_URL = 'https://dreamcatcher.poe.garena.tw/oauth/login'
PRELOGIN_API_URL = 'https://sso.garena.com/api/prelogin?format=json&app_id=200033'
LOGIN_API_URL = 'https://auth.garena.com/api/login?format=json&app_id=200033'
GRANT_URL = 'https://auth.garena.com/oauth/token/grant'
LOGINCHECK_URL = 'https://dreamcatcher.poe.garena.tw/oauth/logincheck?'
DREAMCATCHER_URL = 'https://dreamcatcher.poe.garena.tw/'

# DreamCatcher URL
CATCHDREAM_URL = 'https://dreamcatcher.poe.garena.tw/api/catch_dream'
RECYCLE_URL = 'https://dreamcatcher.poe.garena.tw/api/recycle'
USESEDATIVE_URL = 'https://dreamcatcher.poe.garena.tw/api/use_sedative'

USERNAME = input("UserName: ")
PASSWORD = input("Password: ")

SESSIONID = ''
CSRFTOKEN = ''
SSO_KEY = ''
ACCESSTOKEN = ''

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:66.0) Gecko/20100101 Firefox/66.0', \
           'Accept': 'application/json, text/javascript, */*; q=0.01', 'Accept-Language': 'zh-TW,zh;q=0.8,en-US;q=0.5,en;q=0.3', \
           'Accept-Encoding': 'gzip, deflate, br',\
           'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest', \
           'DNT': '1', 'Connection': 'keep-alive'}

client = requests.session()

stable_points = 0
sedative = 0
current_floor = 0
current_stage = 0
min_path_count = 0


def Login():
    global SESSIONID
    global CSRFTOKEN
    global SSO_KEY
    global ACCESSTOKEN
    # Get SessionID
    client.get(LOGIN_URL)
    SESSIONID = client.cookies.get_dict()['sessionid']
    print('SessionID: ' + SESSIONID)
    
    # Prelogin
    result = client.get(PRELOGIN_API_URL + "&account=" + USERNAME)
    content_json = json.loads(result.text)
    
    # MD5
    passwordMd5_hex = hashlib.md5(PASSWORD.encode("utf-8")).hexdigest()
    passwordMd5_bytes = hashlib.md5(PASSWORD.encode("utf-8")).digest()
    
    # SHA256
    passwordKey = hashlib.sha256((hashlib.sha256((passwordMd5_hex + content_json['v1']).encode("utf-8")).hexdigest() + content_json['v2']).encode("utf-8")).digest()
    
    # AES
    cipher = AES.new(passwordKey, AES.MODE_ECB)
    encryptedPassword = cipher.encrypt(passwordMd5_bytes)
    encryptedPassword = base64.b64decode(str(base64.b64encode(encryptedPassword), 'utf-8')).hex()
    
    
    
    # Login
    result = client.get(LOGIN_API_URL + "&account=" + USERNAME + "&password=" + encryptedPassword)
    SSO_KEY = result.cookies.get_dict()['sso_key']
    print('SSO Key: ' + SSO_KEY)
    
    cookies = {'sso_key': SSO_KEY}
    payload = {'client_id': '200033', 'redirect_uri': 'https://dreamcatcher.poe.garena.tw/oauth/logincheck', \
               'response_type': 'token', 'all_platforms': '1', 'locale': 'zh-TW', 'platform': '1', \
               'format': 'json', 'app_id': '200033', 'id': '1553715310429'}
    grant_headers = headers
    grant_headers.update({'Host': 'auth.garena.com'})
    grant_headers.update({'Cookie': 'sso_key='+SSO_KEY})
    grant_headers.update({'Content-Length': '194'})
    grant_headers.update({'Referer': 'https://auth.garena.com/oauth/login?client_id=200033&redirect_uri=https%3A%2F%2Fdreamcatcher.poe.garena.tw%2Foauth%2Flogincheck&response_type=token&all_platforms=1&locale=zh-TW&platform=1'})
    result = client.post(GRANT_URL, data=payload, headers=headers)
    content_json = json.loads(result.text)
    ACCESSTOKEN = content_json['access_token']
    print('Access Token: ' + ACCESSTOKEN)
    cookies = {'sessionid': SESSIONID}
    result = client.get(LOGINCHECK_URL + 'access_token=' + ACCESSTOKEN, cookies=cookies)
    updateData()
    
def getCaptcha():
    uuid = ''
    for index in range(0, 32):
        rand = random.random() * 16 | 0
        if index == 12:
            continue
        elif index == 16:
            uuid += rand & 0x3 | 0x8
        else:
            uuid += rand
    uuid = format(uuid, 'x')
    print(uuid)

def useSedative():
    if sedative == 0:
        return
    cookies = {'sessionid': SESSIONID, 'csrftoken': CSRFTOKEN}
    headers.update({'X-CSRFToken': CSRFTOKEN, 'Content-Length': '0', \
                    'TE': 'Trailers', 'Referer': 'https://dreamcatcher.poe.garena.tw/', \
                    'Host': 'dreamcatcher.poe.garena.tw', 'Cookie': 'csrftoken='+CSRFTOKEN+'; sessionid='+SESSIONID})
    client.post(USESEDATIVE_URL, cookies=cookies, headers=headers)
    updateData()

def updateData():
    global stable_points
    global sedative
    global current_floor
    global current_stage
    global min_path_count
    global CSRFTOKEN
    cookies = {'sessionid': SESSIONID}
    if CSRFTOKEN != '':
        cookies.update({'csrftoken': CSRFTOKEN})
    result = client.get(DREAMCATCHER_URL, cookies=cookies)
    if CSRFTOKEN == '' and 'csrftoken' in client.cookies:
        CSRFTOKEN = client.cookies['csrftoken']
        print('CSRF Token: ' + CSRFTOKEN)
    first = result.text.find('var stable_points = ')
    last = result.text.find(';', first)
    stable_points = int(result.text[first + 20:last])
    first = result.text.find('var sedative = ')
    last = result.text.find(';', first)
    sedative = int(result.text[first + 15:last])
    first = result.text.find('var current_floor = ')
    last = result.text.find(';', first)
    current_floor = int(result.text[first + 20:last])
    first = result.text.find('var current_stage = ')
    last = result.text.find(';', first)
    current_stage = int(result.text[first + 20:last])
    first = result.text.find('\'min_path_count\': ')
    last = result.text.find(',', first)
    min_path_count = int(result.text[first + 18:last])
    if stable_points == 0:
        useSedative()

# Strategy reference : https://forum.gamer.com.tw/C.php?bsn=18966&snA=119097
def catchDream():
    cookies = {'sessionid': SESSIONID, 'csrftoken': CSRFTOKEN}
    headers.update({'X-CSRFToken': CSRFTOKEN, 'Content-Length': '31', \
                    'TE': 'Trailers', 'Referer': 'https://dreamcatcher.poe.garena.tw/', \
                    'Host': 'dreamcatcher.poe.garena.tw', 'Cookie': 'csrftoken='+CSRFTOKEN+'; sessionid='+SESSIONID})
    guess_strategy = [3, 5, 8]
    guess_list = [guess_strategy[current_floor-1]] * min_path_count
    guess_list.extend([0] * (6-min_path_count))
    print(guess_list)
    while True:
        # check if stable_points enough
        cnt = 0
        for i in range(0, min_path_count):
            cnt += max(abs(current_floor * 10 - guess_list[i]), abs(guess_list[i] - current_floor * 10))
        if cnt >= stable_points and sedative == 0:
            if current_floor != 1 or current_stage != 1:
                print('Stable points too less, restart!')
                recycle()
                break
        
        # guess
        result = client.post(CATCHDREAM_URL, headers=headers, cookies=cookies, json={"guess_numbers":guess_list})
        print('Guess--------------------------')
        print(result.json())
        if result.json()['success'] == False:
            print(result.json()['message'])
            sys.exit()
        if result.json()['data']['stable_points'] == 0:
            if sedative != 0:
                useSedative()
            else:
                break
        if result.json()['data']['success'] == True:
            break
        time.sleep(10)
        number_abs = result.json()['data']['numbers_abs']
        for index in range(0, current_stage):
            if guess_list[index] - number_abs[index] < 1:
                guess_list[index] += number_abs[index]
            else:
                guess_list[index] -= number_abs[index]
    updateData()
    
def recycle():
    if current_floor == 1 and current_stage == 1:
        return
    print('Recycle------------------------')
    cookies = {'sessionid': SESSIONID, 'csrftoken': CSRFTOKEN}
    headers.update({'X-CSRFToken': CSRFTOKEN, 'Content-Length': '0', \
                    'TE': 'Trailers', 'Referer': 'https://dreamcatcher.poe.garena.tw/', \
                    'Host': 'dreamcatcher.poe.garena.tw', 'Cookie': 'csrftoken='+CSRFTOKEN+'; sessionid='+SESSIONID})
    client.post(RECYCLE_URL, cookies=cookies, headers=headers)
    updateData()
    
# Main------------------------
Login()
while stable_points > 0 or sedative > 0:
    catchDream()
    if current_floor > 1 or current_stage > 1:
        recycle()
"""
while 1:
    if stable_points == 0 and sedative == 0:
        break
"""