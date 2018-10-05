BITS 64
;stack: RTN(4b) | process handle(8b) | BaseAddress(8b) | MemoryInformation(8b) | MemoryInformationLength(8b) | ReturnLength(8b)

mov eax, dword [rsp]
mov dword [rsp + 44], eax ; extra space for retn address(we allocate the extra space so we don't overwrite last parameter)
add rsp, 4
mov rcx, qword [rsp] ;ProcessHandle
mov rdx, qword [rsp + 8] ;BaseAddress
mov r8, 0 ;MemoryInformationClass
mov r9, qword [rsp + 16] ;MemoryInformation
;first 4 parameters are passed in the registers, the other 2 are passed on the stack
add rsp, 24 ; get rid of the 3 passed onto stack; they are stored in the registers: RCX, RDX, R8, R9.
sub rsp, 40 ;allocate memory for shadow space(32b) + 8b for imitating x64 call to NtQueryVirtualMemory.
mov r10, rcx
mov eax, 0x0A0A0A0A;NtQueryVirtualMemory syscall index will be written here.
syscall
add rsp, 40
add rsp, 16 ; 2 parameters on stack
mov rdx, rax
mov rcx, rsp
mov rax, 2Bh
push rax
push rcx
mov rax, 246h
push rax
mov rax, 23h
push rax
mov rax, 0h ;return address
push rax
mov rax, rdx ;return value
iretq

; 6 parameters in total, 1 unused, 4 bytes for return address
; 5 * 8 + 4 = 44, 6 * 8 + 4 = 52
; you must allocate an extra 8 bytes for syscall, as the normally you call a subroutine, so 8 bytes need to be added.