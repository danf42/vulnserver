[BITS 32]

global _start			

section .text
_start:

xor edx, edx		; zero out edx
push edx		; push null byte onto stack to null-terminate the string
push 0x20646c72         ; Hello World
push 0x6f57206f
push 0x6c6c6548
mov ebx, esp		; save pointer to string

push edx		; push null value for uType
push ebx		; push pointer to text for lpCaption
push ebx		; push pointer to text for lpText
push edx		; push null value for hWnd
mov edx, dword 0x7e4507ea
call edx 		; call user32.dll/MessageBoxA

