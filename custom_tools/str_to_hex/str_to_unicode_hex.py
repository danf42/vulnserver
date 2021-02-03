import os
import sys

# Get commandline argument for filename
filename = sys.argv[1].strip()

with open(filename, 'r') as fd:
    commands = [line.strip() for line in fd.readlines()]

for command in commands:
    # Check to see if string will be 4-byte aligned
    # if not pad the end of the string with spaces
    rem = len(command) % 4

    if rem != 0:
        new_str_length = len(command) + (4  - rem)

        command = command.ljust(new_str_length)

    # convert string to hex bytes
    h = ["00" + hex(ord(x))[2:] for x in command]

    # reverse the bytes
    h.reverse()

    # break the list into chunks
    n = 2
    chunks = [h[i * n:(i + 1) * n] for i in range((len(h) + n - 1) // n )]

    # Null terminate string
    chunks.insert(0, "00000000")

    print("\n; '{}'".format(command))
    for chunk in chunks:

        strbytes = ''
        
        for token in chunk:
            
            strbytes += token

        print("push 0x" + strbytes)
