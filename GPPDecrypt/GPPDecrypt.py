#!/usr/bin/env python3
#--*--coding: utf-8--*--

# Color codes

W = '\033[0m'   # White
R = '\033[31m'   # Red
G = '\033[32m'   # Green
Y = '\033[33m'   # Yellow

# End color codes

# Import modules

import argparse
import sys
from base64 import b64decode
try:
    from Crypto.Cipher import AES
except ImportError:
    print(R + '[!] Failed to import PyCrypto' + W)
    try:
        choice = raw_input(Y + '[*] Would you like to install PyCrypto module ? [yY/nN] ' + W)
    except KeyboardInterrupt:
        print(R + '[!] User keyboard interrupt !' + W)
        raise SystemExit
    if choice.strip().lower()[0] == 'y':
        print(Y + '[*] Trying to install PyCrypto...' + W)
        sys.stdout.flush()
        try:
            import pip
            pip.main(['install', '--upgrade', 'pycrypto'])
            from Crypto.Cipher import AES
            print(G + '[+] Successfully import PyCrypto' +W)
        except Exception:
            print(R + '[!] Fail to install PyCrypto' + W)
            raise SystemExit
    elif choice.strip().lower()[0] == 'n':
        print(Y + '[*] PyCrypto module will not be installed' + W)
        raise SystemExit
    else:
        print(R + '[!] Invalid user input !' + W)
        raise SystemExit

# End import modules

def decrypt(cpassword=False):
    key = '4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'
    cpassword += "=" * ((4 - len(cpassword) % 4) % 4)
    pwd = b64decode(cpassword)
    o = AES.new(key.decode('hex'), AES.MODE_CBC, "\x00" * 16).decrypt(pwd)
    print(G + '[+] Password found : ' + o[:-ord(o[-1])].decode('utf16') + W)

def main():
    if len(sys.argv) == 1:
        print(R + '[!] No arguments specified type --help to get the man page' + W)
        raise SystemExit       
    parser = argparse.ArgumentParser(prog = 'GPPDecrypt.py', description = 'GPP cpassword decryptor', epilog = 'Made with <3')
    parser.add_argument('-c', '--cpassword', help = 'cpassword to decrypt', type = str, action = 'store', default = False, dest = 'cpassword')
    parser.add_argument('-v', '--version', help = 'Display the program version', action = 'version', version = 'Made by @Init_1, %(prog)s version is 0.1.')
    args = parser.parse_args()
    try:
        decrypt(cpassword = args.cpassword)
    except Exception:
        print(R + '[!] An unknown error occured' + W)
        raise SystemExit
    except KeyboardInterrupt:
        print(R + '[!] User keyboard interrupt' + W)
        raise SystemExit

if __name__ == '__main__':
    main()
    