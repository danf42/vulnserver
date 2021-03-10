import sys

ip = sys.argv[1]

# split the ip address and reverse the order
octets = ip.split('.')[::-1]

print(octets)
print("push 0x"+"".join(str(hex(int(i)))[2:].zfill(2) for i in octets))
