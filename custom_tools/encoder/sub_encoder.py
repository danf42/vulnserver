import argparse
import binascii
import sys
import os

"""
For the type of encoder we are going to use, this is a list of characters that
will conflict with the bad character list

first, check if there are no bad char conflicts - AND eAX, SUB r8, SUB eAX, XOR r/m16/32, XOR r8, XOR eAX, 
DEC eDX , DEC eBP, DEC eSI
PUSH eAX, PUSH eBP, POP eSP
"""
NOBADCHARS = "\x25\x2a\x2d\x31\x32\x35\x4a\x4d\x4e\x50\x55\x5c"

# Instruction dictionary
ASM_DICT = {
    'NOP':"\x90",
    'AND':{ 
        'EAX':"\x25" 
    },
    'SUB':{ 
        'EAX':"\x2D" 
    },
    'PUSH':{
        'EBP':"\x55",
        'ESP':"\x54",
        'EAX':"\x50",
        'EBX':"\x53",
        'ECX':"\x51",
        'EDX':"\x52",
        'EDI':"\x57",
        'ESI':"\x56"
    },
    'POP':{ 
        'ESP':"\x5C", 
        'EAX':"\x58"
    }
}

def find_opposit_bytes(char_list):
    '''
    Given a list of characters, find opposit bytes that 
    when AND'd together equal 0

    return two values in hex
    '''

    is_found = False

    ord1 = None
    ord2 = None

    for val1 in char_list:
        for val2 in char_list:

            ord1 = '{:02x}'.format(ord(val1)) * 4
            ord2 = '{:02x}'.format(ord(val2)) * 4

            int1 = hex_str_to_int(ord1)
            int2 = hex_str_to_int(ord2)

            if int1 & int2 == 0:
                print("[+] Opposite Values Founds: {} & {}".format(ord1, ord2))
                is_found = True
                break

        if is_found:
            break

    if not is_found:
        print("[-] Failed to find opposite values")
    
    return (ord1, ord2)

def prepare_shellcode(pShelcode):
    '''
    Align shellcode and split into 4 byte chunks
    '''

    rem = len(pShelcode) % 4

    if rem != 0:
        nop_sled = [ASM_DICT['NOP']] * (4-rem)
        pShelcode = pShelcode + nop_sled

        # Verify that we are aligned now
        if (len(pShelcode) % 4) == 0:
            print("[+] Added {} nops to alight shellcode to 4 bytes".format(len(nop_sled)))
        
        else:
            print("[-] Shellcode is not 4 byte aligned, can't continue.")
            return None


    # get hex value from shellcode
    hex_str = bin2hex(pShelcode)

    chunks = hex2array(hex_str, size=8)
    reversed_chunks = chunks[::-1]

    print("[+] Number of chunks: {}".format(len(chunks)))
    print("[+] Chunks:           {}".format(chunks))
    print("[+] Reversed Chunks:  {}".format(chunks))

    return reversed_chunks

def process_inputfile(input_file):
    '''
    Read in the input file and convert contents to Hex string list
    '''

    with open(input_file, 'r') as fd:
        contents = fd.readline().strip()

    # convert character string to a list
    contents = contents.replace("\\x", "")
    contents = contents.replace("\"", "")
    contents = contents.replace("\'", "")

    hex_str = [binascii.a2b_hex(i + j) for i, j in zip(str(contents[0::2]), str(contents[1::2]))]

    return hex_str

def bin2hex(bin_bytes):
    ''' 
    Converts hex string to a string of space separated hex bytes
    '''
    hex_str = ''.join('%02x' % ord(c) for c in bin_bytes)
    return hex_str

def hex2array(hex_str, size=2):
    '''
    Convert a string of hex bytes into an array of size chunks
    Default is 2 (1 byte)
    '''
    hex_array = [hex_str[i:i+size] for i in range(0, len(hex_str),size)] 

    return hex_array

def hex2bin(pattern):
    """
    Converts a hex string (\\x??\\x??\\x??\\x??) to real hex bytes
    Arguments:
    pattern - A string representing the bytes to convert
    Return:
    the bytes
    """
    pattern = pattern.replace("\\x", "")
    pattern = pattern.replace("\"", "")
    pattern = pattern.replace("\'", "")

    hex_str = [binascii.a2b_hex(i + j) for i, j in zip(str(pattern[0::2]), str(pattern[1::2]))]

    return hex_str

def hex_str_to_int(input_str):
    """
    Converts a string with hex bytes to a numeric value
    """
    try:
        val_to_return = int(input_str, 16)
    except Exception as e:
        val_to_return = 0
        print('Exception converting hex to int: {}'.format(e))
    return val_to_return

def to_hex(input_int):
    '''
    Convert integer value to hex
    '''
    return '{:08x}'.format(input_int)


def tohex(val, nbits=32):
    '''
    Convert an integer value to hex
    use nbits to compute twos complement value
    '''
    #return hex((val + (1 << nbits)) % (1 << nbits))

    intval = ((val + (1 << nbits)) % (1 << nbits))
    return '{:08x}'.format(intval)


def validatebadchars_enc(val1, val2, val3, badchars):
    newvals = []
    allok = 0
    giveup = 0
    type = 0
    origval1 = val1
    origval2 = val2
    origval3 = val3
    d1 = 0
    #d2 = 0
    d3 = 0
    #lastd1 = 0
    #lastd2 = 0
    lastd3 = 0
    while allok == 0 and giveup == 0:
        # check if there are bad chars left
        charcnt = 0
        val1ok = 1
        val2ok = 1
        val3ok = 1
        while charcnt < len(badchars):
            if (("{:02x}".format(int(val1)))in badchars):
                val1ok = 0
            if (("{:02x}".format(int(val2))) in badchars):
                val2ok = 0
            if (("{:02x}".format(int(val3))) in badchars):
                val3ok = 0
            charcnt = charcnt + 1
        if (val1ok == 0) or (val2ok == 0) or (val3ok == 0):
            allok = 0
        else:
            allok = 1
        if allok == 0:
            # try first by sub 1 from val1 and val2, and add more to val3
            if type == 0:
                val1 = val1 - 1
                val2 = val2 - 1
                val3 = val3 + 2
                if (val1 < 1) or (val2 == 0) or (val3 > 126):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    type = 1
            if type == 1:
                # then try by add 1 to val1 and val2, and sub more from val3
                val1 = val1 + 1
                val2 = val2 + 1
                val3 = val3 - 2
                if (val1 > 126) or (val2 > 126) or (val3 < 1):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    type = 2
            if type == 2:
                # try by sub 2 from val1, and add 1 to val2 and val3
                val1 = val1 - 2
                val2 = val2 + 1
                val3 = val3 + 1
                if (val1 < 1) or (val2 > 126) or (val3 > 126):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    type = 3
            if type == 3:
                # try by add 2 to val1, and sub 1 from val2 and val3
                val1 = val1 + 2
                val2 = val2 - 1
                val3 = val3 - 1
                if (val1 > 126) or (val2 < 1) or (val3 < 1):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    type = 4
            if type == 4:
                if (val1ok == 0):
                    val1 = val1 - 1
                    d1 = d1 + 1
                else:
                    # now spread delta over other 2 values
                    if (d1 > 0):
                        val2 = val2 + 1
                        val3 = origval3 + d1 - 1
                        d1 = d1 - 1
                    else:
                        val1 = 0
                if (val1 < 1) or (val2 > 126) or (val3 > 126):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    d1 = 0
                    type = 5
            if type == 5:
                if (val1ok == 0):
                    val1 = val1 + 1
                    d1 = d1 + 1
                else:
                    # now spread delta over other 2 values
                    if (d1 > 0):
                        val2 = val2 - 1
                        val3 = origval3 - d1 + 1
                        d1 = d1 - 1
                    else:
                        val1 = 255
                if (val1 > 126) or (val2 < 1) or (val3 < 1):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    val1ok = 0
                    val2ok = 0
                    val3ok = 0
                    d1 = 0
                    d2 = 0
                    d3 = 0
                    type = 6
            if type == 6:
                if (val1ok == 0):
                    val1 = val1 - 1
                # d1=d1+1
                if (val2ok == 0):
                    val2 = val2 + 1
                # d2=d2+1
                d3 = origval1 - val1 + origval2 - val2
                val3 = origval3 + d3
                if (lastd3 == d3) and (d3 > 0):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    giveup = 1
                else:
                    lastd3 = d3
                if (val1 < 1) or (val2 < 1) or (val3 > 126):
                    val1 = origval1
                    val2 = origval2
                    val3 = origval3
                    giveup = 1
    # check results
    charcnt = 0
    val1ok = 1
    val2ok = 1
    val3ok = 1
    val1text = "OK"
    val2text = "OK"
    val3text = "OK"
    while charcnt < len(badchars):
        if (val1 == badchars[charcnt]):
            val1ok = 0
            val1text = "NOK"
        if (val2 == badchars[charcnt]):
            val2ok = 0
            val2text = "NOK"
        if (val3 == badchars[charcnt]):
            val3ok = 0
            val3text = "NOK"
        charcnt = charcnt + 1

    if (val1ok == 0) or (val2ok == 0) or (val3ok == 0):
        print("  ** Unable to fix bad char issue !")
        print("	  -> Values to check : %s(%s) %s(%s) %s(%s) " % (
            bin2hex(origval1), val1text, bin2hex(origval2), val2text, bin2hex(origval3), val3text))
        val1 = origval1
        val2 = origval2
        val3 = origval3
    newvals.append(val1)
    newvals.append(val2)
    newvals.append(val3)
    
    return newvals

def sub_3(shellcode, goodchars=[], badchars=[]):

    # convert nobadchar str to an array
    nobadchars = hex2array(bin2hex(NOBADCHARS))

    if badchars:

        badchar_found = False
        for b in badchars:
            if b in nobadchars:
                print("[-] Error: Byte {} cannot be a bad char with this encoder".format(b))
                badchar_found = True 
                break

        if badchar_found:
            return None    

    # Determine how to AND EAX together to get 0 
    eax_and_val1 = '554E4D4A'
    eax_and_val2 = '2A313235'

    if goodchars:
        eax_and_val1, eax_and_val2 = find_opposit_bytes(goodchars)

    # Prepare shellcode
    reversed_payload = prepare_shellcode(shellcode)

    encodedline = 0
    encodedbytes = {}

    num_chunks = len(reversed_payload)
    blockcnt = num_chunks
    total_length = 0

    for chunk in reversed_payload:

        print("Processing chunk {} of {}".format(blockcnt, num_chunks))

        # reverse the value so that LSB is first
        reverse_chunk = "".join(reversed([chunk[i:i+2] for i in range(0, len(chunk), 2)]))

        # convert hex to int
        revval = hex_str_to_int(reverse_chunk)

        # Get two's complement 
        # hex(4294967296) == 0x100000000
        twoval = 4294967296 - revval

        # convert two's complement back to hex
        twobytes = tohex(twoval)

        print("[+]\tOpcode to Produce: {}".format(chunk))
        print("[+]\tReversed Opcode:   {}".format(reverse_chunk))
        print("[+]\tTwos complement:   {}\n".format(twobytes))

        # for each byte, start with the last one first
        bcnt = 3
        overflow = 0
        opcodes = []

        while bcnt >= 0:

            # This is getting the last byte from the chunk
            curbyte = twobytes[(bcnt * 2)] + twobytes[(bcnt * 2) + 1]

            # convert hex value to int
            curval = hex_str_to_int(curbyte) - overflow

            testval = curval/3

            # handle overflow
            if testval < 32:
                curbyte = "1" + curbyte
                curval = hex_str_to_int(curbyte) - overflow
                overflow = 1

            else:
                overflow = 0

            val1 = int(curval / 3)
            val2 = int(curval / 3)
            val3 = int(curval / 3)
            sumval = val1 + val2 + val3 

            if sumval < curval:
                val3 = val3 + (curval - sumval)

            # verify bad characters 
            fixvals = validatebadchars_enc(val1, val2, val3, badchars)

            val1 = "%02x" % (int(fixvals[0]))
            val2 = "%02x" % (int(fixvals[1]))
            val3 = "%02x" % (int(fixvals[2]))
            opcodes.append(val1)
            opcodes.append(val2)
            opcodes.append(val3)
            bcnt = bcnt - 1

        # Create shellcode 
        thisencodedbyte = bin2hex(ASM_DICT['AND']['EAX'])
        thisencodedbyte += eax_and_val1

        # Store shellcode plus Assembly instructions
        encodedbytes[encodedline] = [thisencodedbyte, 'AND EAX, 0x{}'.format(eax_and_val1)]
        encodedline += 1
        total_length += len(thisencodedbyte)

        # Create shellcode
        thisencodedbyte = bin2hex(ASM_DICT['AND']['EAX'])
        thisencodedbyte += eax_and_val2

        # Store shellcode plus Assembly instructions
        encodedbytes[encodedline] = [thisencodedbyte, 'AND EAX, 0x{}'.format(eax_and_val2)]
        encodedline += 1
        total_length += len(thisencodedbyte)

        # Create shellcode -- Sub Insruction 1
        thisencodedbyte = bin2hex(ASM_DICT['SUB']['EAX'])
        thisencodedbyte += '{}{}{}{}'.format(opcodes[0], opcodes[3], opcodes[6],  opcodes[9])
        
        # Store shellcode plus Assembly instructions -- Sub Insruction 1
        encodedbytes[encodedline] = [thisencodedbyte, "SUB EAX, 0x{}{}{}{}".format(opcodes[9], opcodes[6], opcodes[3], opcodes[0])]
        encodedline += 1
        total_length += len(thisencodedbyte)

        # Create shellcode -- Sub Insruction 2
        thisencodedbyte = bin2hex(ASM_DICT['SUB']['EAX'])
        thisencodedbyte += '{}{}{}{}'.format(opcodes[1], opcodes[4], opcodes[7],  opcodes[10])

        # Store shellcode plus Assembly instructions -- Sub Insruction 2
        encodedbytes[encodedline] = [thisencodedbyte, "SUB EAX, 0x{}{}{}{}".format(opcodes[10], opcodes[7], opcodes[4], opcodes[1])]
        encodedline += 1
        total_length += len(thisencodedbyte)

        # Create shellcode -- Sub Insruction 3
        thisencodedbyte = bin2hex(ASM_DICT['SUB']['EAX'])
        thisencodedbyte += '{}{}{}{}'.format(opcodes[2], opcodes[5], opcodes[8],  opcodes[11])

        # Store shellcode plus Assembly instructions -- Sub Insruction 3
        encodedbytes[encodedline] = [thisencodedbyte, "SUB EAX, 0x{}{}{}{}".format(opcodes[11], opcodes[8], opcodes[5], opcodes[2])]
        encodedline += 1
        total_length += len(thisencodedbyte)

        # Store shellcode plus Assembly instructions
        thisencodedbyte = bin2hex(ASM_DICT['PUSH']['EAX'])
        encodedbytes[encodedline] = [thisencodedbyte, "PUSH EAX"]
        encodedline += 1
        total_length += len(thisencodedbyte)

        # Decrement block count
        blockcnt -= 1

    return encodedbytes

# def printEncodedPayload(encodedbytes): 
#     '''
#     Print out the encoded bytes
#     '''

#     for line in encodedbytes:

#         print(encodedbytes[line][0])

def printEncodedPayload(encodedbytes): 
    '''
    Print out the encoded bytes
    '''
    shellcode_string = ""
    print("\n\n ======== Results ========")

    for line in encodedbytes:
        shellcode = "\\x" + '\\x'.join(hex2array(encodedbytes[line][0]))
        shellcode_string += shellcode
        assembly = encodedbytes[line][1]

        print("{} : {}".format(shellcode, assembly))

    print("\n\n ======== Assembly Code ========")
    for line in encodedbytes:

        print(encodedbytes[line][1])

    print("\n\n ======== Shellcode ========")
    for line in encodedbytes:
        print("\\x" + '\\x'.join(hex2array(encodedbytes[line][0])))

    print("\n\n ======== Shellcode String ========")
    print("Encoded Shellcode Length: {}".format(len(hex2bin(shellcode_string))))
    print(shellcode_string)


def main():

    parser = argparse.ArgumentParser(description="Encode payload using sub instructions")
    parser.add_argument("-p", "--payload", 
                                help="File containg payload to encode containing hex string (eg. \\x41\\x42)",
                                required=True)
    parser.add_argument("-b", "--bad_characters", 
                                help="File containing bad characters to ignore in hex string (eg. \\x00\\x0A)",
                                required=True)

    parser.add_argument("-g", "--good_characters", 
                                help="File containing good characters in hex string (eg. \\x00\\x0A)",
                                required=True)

    args = parser.parse_args()

    
    # Read in good character list
    goodchars_list = []
    if args.good_characters:
        goodchars_list = process_inputfile(args.good_characters)
        print("[+] Number of good characters: {}".format(len(goodchars_list)))
      
    # Process bad characters
    badchars_list = []
    if args.bad_characters:
        badchars_list = process_inputfile(args.bad_characters)
        print("[+] Number of bad characters: {}".format(len(badchars_list)))

    if args.payload:
       
        payload = process_inputfile(args.payload)

        encoded_bytes = sub_3(payload, goodchars=goodchars_list, badchars=badchars_list)
        printEncodedPayload(encoded_bytes)


    else:
        print(parser.print_help(sys.stderr))


if __name__ == "__main__":
    main()
