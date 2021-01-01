[BITS 32]

; Shellcode to redirect execution back 768 bytes from instruction following CALL

global _start

section .text

_start:
  jmp short jmpspot   
  callspot:        ; The CALL lands here, stack now has address of next instruction
  pop ecx          ; pops address of next instruction into ECX
  dec ch           ; decrement CH register by 1 = ECX - 256
  dec ch           ; decrement CH register by 1 = ECX - 256
  dec ch           ; decrement CH register by 1 = ECX - 256
  jmp ecx          ; jmp to ECX
  jmpspot:
  call callspot
