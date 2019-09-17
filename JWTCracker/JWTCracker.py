#!/usr/bin/env python3
#--*--coding: utf-8--*--

# Color codes

W = '\033[0m'   # White
R = '\033[31m'   # Red
G = '\033[32m'   # Green
Y = '\033[33m'   # Yellow

# End color codes

# Import modules

import sys
import argparse
try:
    import jwt
except ImportError:
    print(R + '[!] Failed to import JWT' + W)
    try:
        choice = raw_input(Y + '[*] Would you like to install PyJWT module ? [yY/nN] ' + W)
    except KeyboardInterrupt:
        print(R + '[!] User keyboard interrupt !' + W)
        raise SystemExit
    if choice.strip().lower()[0] == 'y':
        print(Y + '[*] Trying to install PyJWT...' + W)
        sys.stdout.flush()
        try:
            import pip
            pip.main(['install', '--upgrade', 'PyJWT'])
            import jwt
            print(G + '[+] Successfully import PyJWT' +W)
        except Exception:
            print(R + '[!] Fail to install PyJWT' + W)
            raise SystemExit
    elif choice.strip().lower()[0] == 'n':
        print(Y + '[*] PyJWT module will not be installed' + W)
        raise SystemExit
    else:
        print(R + '[!] Invalid user input !' + W)
        raise SystemExit
    
# End import modules

def check_alg(token):
    header = jwt.get_unverified_header(token)
    return header["alg"]

def valid_jwt(token):
    chain = token.split(".")
    if len(chain) != 3:
        return False
    return True

def crack_JWT(token = False, dic = False):
    if not valid_jwt(token):
        print(R + '[!] Token supplied is not a valid JWT' + W)
        raise SystemExit
    alg = check_alg(token)
    with open(dic, 'r') as f:
        for word in f:
            try:
                jwt.decode(token, word.rstrip(), algorithms=[str(alg)])
                return word.rstrip()
            except:
                pass

def main():
    if len(sys.argv) == 1:
        print(R + '[!] No arguments specified type --help to get the man page' + W)
        raise SystemExit       
    parser = argparse.ArgumentParser(prog = 'JWTCracker.py', description = 'JWT token cracker', epilog = 'Made with <3')
    parser.add_argument('-t', '--token', help = 'JSON Web Token to crack', type = str, action = 'store', default = False, dest = 'token')
    parser.add_argument('-d', '--dictionnary', help = 'Dictionnary to use', type = str, action = 'store', default = False, dest = 'dic')
    parser.add_argument('-v', '--version', help = 'Display the program version', action = 'version', version = 'Made by @Init_1, %(prog)s version is 0.1.')
    args = parser.parse_args()
    try:
        secret = crack_JWT(token = args.token, dic = args.dic)
        print(G + '[+] Secret found : ' + secret + W)
    except Exception:
        print(R + '[!] An unknown error occured' + W)
        raise SystemExit
    except KeyboardInterrupt:
        print(R + '[!] User keyboard interrupt' + W)
        raise SystemExit

if __name__ == '__main__':
    main()