BITS 64

;mov r10, rcx ;mov r10, 0x00000000000000D4
mov eax, dword [rsp]
mov dword [rsp + 44], eax
mov rcx, qword [rsp + 4h]
mov rdx,qword [rsp + 20]
mov r8, qword [rsp + 0Ch] ;pBuf
mov r9, qword [rsp + 28] ;number of bytes to write
mov rax, qword [rsp + 36]
mov qword [rsp + 20h], rax ;ullBytesWritten
sub rsp, 8 ;imitating x64 call to NtWriteVirtualMemory, if we called NtWriteVirtualMemory, it'd push the return address of 8 bytes so to make up for not calling it, we allocate 8 bytes on the stack.
mov r10, rcx
mov eax, 0x0A0A0A0A;NtWriteVirtualMemory/NtReadVirtualMemory syscall index
syscall
mov rdx, rax
add rsp, 48
add rsp, 4
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