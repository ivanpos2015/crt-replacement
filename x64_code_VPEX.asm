BITS 64

mov eax, dword [rsp]
mov dword [rsp + 44], eax
mov rcx, qword [rsp + 4h]
mov rdx,qword [rsp + 12]
mov r8, qword [rsp + 20]
mov r9, qword [rsp + 28]
mov rax, qword [rsp + 36]
mov qword [rsp + 20h], rax
sub rsp, 8 
mov r10, rcx
mov eax, 0x0A0A0A0A
syscall
mov rdx, rax
add rsp, 52
mov rcx, rsp
mov rax, 2Bh
push rax
push rcx
mov rax, 246h
push rax
mov rax, 23h
push rax
mov rax, 0h
push rax
mov rax, rdx
iretq