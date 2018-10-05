BITS 64

;mov r10, rcx ;mov r10, 0x00000000000000D4
mov eax, dword [rsp]
mov dword [rsp + 36], eax
mov rcx, qword [rsp + 4h] ;process handle
mov rdx, qword [rsp + 12] ;base address
mov r8, qword [rsp + 20] ;region size
mov r9, qword [rsp + 28] ;free type
mov r10, rcx
mov eax, 0x0A0A0A0A;syscall index will get written here
syscall
mov rdx, rax
add rsp, 36
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