import argparse
import binascii
from colorama import Fore, Back, Style 

def read_good_char_file(input_file):
    '''
    Read in good character file and return a List of hex bytes
    '''

    with open(input_file, 'r') as fd:
        contents = fd.readline().strip()

    # convert character string to a list
    contents = contents.replace("\\x", " ")
    contents = contents.replace("\"", " ")
    contents = contents.replace("\'", " ")

    good_char_buffer = list(filter(None, contents.split(" ")))

    return good_char_buffer

def splitAddress(address):
    '''
    Split the address to check up into 4 hex bytes
    Return a list of hex bytes
    '''

    byte1 = address >> 24 & 0xFF
    byte2 = address >> 16 & 0xFF
    byte3 = address >>  8 & 0xFF
    byte4 = address & 0xFF

    return [hex(byte1)[2:],hex(byte2)[2:],hex(byte3)[2:],hex(byte4)[2:].zfill(2)]

def is_address_good(address, good_chars):
    '''
    Check if the address contains only good characters
    Return True if address contains only good characters
      otherwise False
    '''

    int_value = int(address, 16)

    byte_list = splitAddress(int_value)

    is_good = True

    for aByte in byte_list:
        if aByte not in good_chars:
            print(Fore.RED + "[-] {} is not a good char in address {}".format(aByte, address))
            is_good = False
            break

    return is_good   

def main():

    parser = argparse.ArgumentParser(description='Check if an address contains all good characters')
    parser.add_argument('goodCharFile', type=str,  help='File containing good characters')
    parser.add_argument('--address', type=str, help='Single Address to check in the form 0xABCDEFGH')
    parser.add_argument('--address_file', type=str, help='File containing list of address to check in the form 0xABCDEFGH')

    args = parser.parse_args()

    good_char_list = read_good_char_file(args.goodCharFile)

    print("Good Character List:\n{}".format(' '.join(good_char_list)))

    address_list = []

    if args.address_file:

        with open(args.address_file, 'r') as fd:
            address_list = [address.strip() for address in fd.readlines()]

    if args.address:

        address_list.append(args.address)

    for address in address_list:
        print(Fore.WHITE + "\nChecking Address: {}".format(address))

        is_good = is_address_good(address, good_char_list)

        if is_good:
            print(Fore.GREEN + "[+] {} is safe address".format(address))
        
        else:
            print(Fore.RED + "[-] {} is not safe address".format(address))

if __name__ == '__main__':
    main()
