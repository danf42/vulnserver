[BITS 32]

global _start			

section .text
_start:

   xor edx, edx		; zero out edx
   push edx		; push null byte onto stack
   push 0x6578652e   	; push '.exe' onto stack
   push 0x636c6163	; push 'calc' onto stack
   mov ebx, esp		; save stack pointer 

   inc edx		; add 1 for SW_SHOWNORMAL 
   push edx		; push SW_SHOWNORMAL onto stack
   push ebx		; push pointer to 'calc.exe'
   mov edx, 0x7c8623ad	; mov address of WinExec
   call edx
