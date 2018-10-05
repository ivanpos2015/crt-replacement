BITS 64

mov eax, dword [rsp] ;return address
mov dword [rsp + 92], eax ; 92 ; store return address at the end of the parameters(no worries about corrupting the stack, we did sub esp, 4 in wow64 mode remember?)
mov rcx, qword [rsp + 4] ; hThread
mov rdx, qword [rsp + 12] ; Access Mask
mov r8, qword [rsp + 20] ; Object Attributes
mov r9, qword [rsp + 28] ; hProcess
sub rsp, 4 ; imitate a call as a syscall wrapper function
mov r10, rcx
mov eax, 0x0A0A0A0A
syscall
mov rdx, rax
add rsp, 4
add rsp, 92 ; for all the parameters(11 * 8) = 88 + return address(4) = 92
mov rcx, rsp
mov rax, 2Bh
push rax
push rcx
mov rax, 246h
push rax
mov rax, 23h
push rax
mov rax, 0h ;return address -> will be patched, ex: *(PDWORD)&x64_code_crt[sizeof(x64_code_CRT) - 10] = (DWORD)&retfunc;
push rax
mov rax, rdx
iretq