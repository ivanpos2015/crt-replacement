#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN64
//so 32-bit crt doesn't conflict.
#define __STDC_WANT_SECURE_LIB__ 0
#define _CRT_SECURE_NO_WARNINGS
#define __STRALIGN_H_
#define _SYS_GUID_OPERATORS_
#define _INC_STRING
#define __STDC__ 1
#else
//so 64-bit crt doesn't conflict.
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#define _SYS_GUID_OPERATORS_
#define __STRALIGN_H_
#define _INC_STRING
#define __STDC__ 1
#define __STDC_WANT_SECURE_LIB__ 0
#define _STRALIGN_USE_SECURE_CRT 0
#endif
#include <Windows.h>
#include "crt.h"
#include "ext64.h"
//#include "helpers.h"
#include <winternl.h>
#include "petools.h"
#include <Aclapi.h> // for GetSecurityInfo

void _cdecl retfunc(){ } //simple RETN

/*
notepad.exe+14030 - 48 8B CC              - mov rcx,rsp
notepad.exe+14033 - 48 B8 2B00000000000000 - mov rax,000000000000002B
notepad.exe+1403D - 50                    - push rax
notepad.exe+1403E - 51                    - push rcx
notepad.exe+1403F - 48 B8 4602000000000000 - mov rax,0000000000000246
notepad.exe+14049 - 50                    - push rax
notepad.exe+1404A - 48 B8 2300000000000000 - mov rax,0000000000000023
notepad.exe+14054 - 50                    - push rax
notepad.exe+14055 - 48 B8 0000000000000000 - mov rax,0000000000000000
notepad.exe+1405F - 50                    - push rax
notepad.exe+14060 - 48 CF                 - iretq
*/

/*
BYTE x64_code[] = { 0x48, 0x8B, 0xCC, 0x48, 0xB8, 0x2B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x50, 0x51, 0x48, 0xB8, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50,
					0x48, 0xB8, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0xB8,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0xCF };
*/

/*
ntdll.ZwWriteVirtualMemory - 4C 8B D1              - mov r10,rcx
ntdll.NtWriteVirtualMemory+3- B8 3A000000           - mov eax,0000003A
ntdll.NtWriteVirtualMemory+8- 0F05                  - syscall
ntdll.NtWriteVirtualMemory+A- C3                    - ret

https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
In the Microsoft x64 calling convention,
it's the caller's responsibility to allocate 32 bytes of "shadow space" on the stack right before calling the function
(regardless of the actual number of parameters used),
and to pop the stack after the call. The shadow space is used to spill RCX, RDX, R8, and R9,[13]
but must be made available to all functions, even those with fewer than four parameters.
*/

/*
cleanup:
BITS 64

mov eax, dword [rsp]
add rsp, 0x20
mov dword [rsp], eax
mov rcx, rsp
mov rax, 2Bh
push rax
push rcx
mov rax, 246h
push rax
mov rax, 23h
push rax
mov rax, 0000000000000000
push rax
iretq
*/

/*
ConsoleApplication1.exe+101D - BA 02000000           - mov edx,00000002 ;2nd
ConsoleApplication1.exe+1022 - 48 C7 44 24 20 05000000 - mov [rsp+20],00000005 ;5th
ConsoleApplication1.exe+102B - 44 8D 4A 02           - lea r9d,[rdx+02] ; 4
ConsoleApplication1.exe+102F - 44 8D 42 01           - lea r8d,[rdx+01] ;3
ConsoleApplication1.exe+1033 - 8D 4A FF              - lea ecx,[rdx-01] ; 1
ConsoleApplication1.exe+1036 - FF 15 C40F0000        - call qword ptr [ConsoleApplication1.exe+2000]
*/

unsigned char x64_code_WPMRPM[] = {
	0x8B, 0x04, 0x24, 0x89, 0x44, 0x24, 0x2C, 0x48, 0x8B, 0x4C, 0x24, 0x04,
	0x48, 0x8B, 0x54, 0x24, 0x14, 0x4C, 0x8B, 0x44, 0x24, 0x0C, 0x4C, 0x8B,
	0x4C, 0x24, 0x1C, 0x48, 0x8B, 0x44, 0x24, 0x24, 0x48, 0x89, 0x44, 0x24,
	0x20, 0x48, 0x83, 0xEC, 0x08, 0x49, 0x89, 0xCA, 0xB8, 0x0A, 0x0A, 0x0A,
	0x0A, 0x0F, 0x05, 0x48, 0x89, 0xC2, 0x48, 0x83, 0xC4, 0x30, 0x48, 0x83,
	0xC4, 0x04, 0x48, 0x89, 0xE1, 0xB8, 0x2B, 0x00, 0x00, 0x00, 0x50, 0x51,
	0xB8, 0x46, 0x02, 0x00, 0x00, 0x50, 0xB8, 0x23, 0x00, 0x00, 0x00, 0x50,
	0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xD0, 0x48, 0xCF
};

unsigned char x64_code_VQEX[] = {
	0x8B, 0x04, 0x24, 0x89, 0x44, 0x24, 0x2C, 0x48, 0x83, 0xC4, 0x04, 0x48,
	0x8B, 0x0C, 0x24, 0x48, 0x8B, 0x54, 0x24, 0x08, 0x41, 0xB8, 0x00, 0x00,
	0x00, 0x00, 0x4C, 0x8B, 0x4C, 0x24, 0x10, 0x48, 0x83, 0xC4, 0x18, 0x48,
	0x83, 0xEC, 0x28, 0x49, 0x89, 0xCA, 0xB8, 0x0A, 0x0A, 0x0A, 0x0A, 0x0F,
	0x05, 0x48, 0x83, 0xC4, 0x28, 0x48, 0x83, 0xC4, 0x10, 0x48, 0x89, 0xC2,
	0x48, 0x89, 0xE1, 0xB8, 0x2B, 0x00, 0x00, 0x00, 0x50, 0x51, 0xB8, 0x46,
	0x02, 0x00, 0x00, 0x50, 0xB8, 0x23, 0x00, 0x00, 0x00, 0x50, 0xB8, 0x00,
	0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xD0, 0x48, 0xCF
};



unsigned char x64_code_VAEX[] = {
	0x8B, 0x04, 0x24, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x04,
	0x48, 0x8B, 0x54, 0x24, 0x0C, 0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x4C,
	0x8B, 0x4C, 0x24, 0x14, 0x48, 0x83, 0xEC, 0x08, 0x49, 0x89, 0xCA, 0xB8,
	0x0A, 0x0A, 0x0A, 0x0A, 0x0F, 0x05, 0x48, 0x89, 0xC2, 0x48, 0x83, 0xC4,
	0x08, 0x48, 0x83, 0xC4, 0x30, 0x48, 0x89, 0xE1, 0xB8, 0x2B, 0x00, 0x00,
	0x00, 0x50, 0x51, 0xB8, 0x46, 0x02, 0x00, 0x00, 0x50, 0xB8, 0x23, 0x00,
	0x00, 0x00, 0x50, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xD0,
	0x48, 0xCF
};
unsigned char x64_code_VFEX[] = {
	0x8B, 0x04, 0x24, 0x89, 0x44, 0x24, 0x24, 0x48, 0x8B, 0x4C, 0x24, 0x04,
	0x48, 0x8B, 0x54, 0x24, 0x0C, 0x4C, 0x8B, 0x44, 0x24, 0x14, 0x4C, 0x8B,
	0x4C, 0x24, 0x1C, 0x49, 0x89, 0xCA, 0xB8, 0x0A, 0x0A, 0x0A, 0x0A, 0x0F,
	0x05, 0x48, 0x89, 0xC2, 0x48, 0x83, 0xC4, 0x24, 0x48, 0x89, 0xE1, 0xB8,
	0x2B, 0x00, 0x00, 0x00, 0x50, 0x51, 0xB8, 0x46, 0x02, 0x00, 0x00, 0x50,
	0xB8, 0x23, 0x00, 0x00, 0x00, 0x50, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50,
	0x48, 0x89, 0xD0, 0x48, 0xCF
};

unsigned char x64_code_VPEX[] = {
	0x8B, 0x04, 0x24, 0x89, 0x44, 0x24, 0x2C, 0x48, 0x8B, 0x4C, 0x24, 0x04,
	0x48, 0x8B, 0x54, 0x24, 0x0C, 0x4C, 0x8B, 0x44, 0x24, 0x14, 0x4C, 0x8B,
	0x4C, 0x24, 0x1C, 0x48, 0x8B, 0x44, 0x24, 0x24, 0x48, 0x89, 0x44, 0x24,
	0x20, 0x48, 0x83, 0xEC, 0x08, 0x49, 0x89, 0xCA, 0xB8, 0x0A, 0x0A, 0x0A,
	0x0A, 0x0F, 0x05, 0x48, 0x89, 0xC2, 0x48, 0x83, 0xC4, 0x34, 0x48, 0x89,
	0xE1, 0xB8, 0x2B, 0x00, 0x00, 0x00, 0x50, 0x51, 0xB8, 0x46, 0x02, 0x00,
	0x00, 0x50, 0xB8, 0x23, 0x00, 0x00, 0x00, 0x50, 0xB8, 0x00, 0x00, 0x00,
	0x00, 0x50, 0x48, 0x89, 0xD0, 0x48, 0xCF
};

unsigned char x64_code_CRT[] = {
	0x8B, 0x04, 0x24, 0x89, 0x44, 0x24, 0x5C, 0x48, 0x8B, 0x4C, 0x24, 0x04,
	0x48, 0x8B, 0x54, 0x24, 0x0C, 0x4C, 0x8B, 0x44, 0x24, 0x14, 0x4C, 0x8B,
	0x4C, 0x24, 0x1C, 0x48, 0x83, 0xEC, 0x04, 0x49, 0x89, 0xCA, 0xB8, 0x0A,
	0x0A, 0x0A, 0x0A, 0x0F, 0x05, 0x48, 0x89, 0xC2, 0x48, 0x83, 0xC4, 0x04,
	0x48, 0x83, 0xC4, 0x5C, 0x48, 0x89, 0xE1, 0xB8, 0x2B, 0x00, 0x00, 0x00,
	0x50, 0x51, 0xB8, 0x46, 0x02, 0x00, 0x00, 0x50, 0xB8, 0x23, 0x00, 0x00,
	0x00, 0x50, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xD0, 0x48,
	0xCF
};


PDWORD FindSysCallIndexPatchable(PBYTE pData, DWORD dwDataLen){
	BYTE occurances = 0;
	for (DWORD i = 0; i < dwDataLen; i++)
		if (pData[i] == 0x0A){
			occurances++;
			if (occurances == 4)
				return (PDWORD)&pData[i - 3];
		}
		else
			occurances = 0;
	return nullptr;
}


Nt64::Nt64()
{
	bUsable = false;
	heavensgate = nullptr;
	heavensgate = (PBYTE)VirtualAlloc(nullptr, sizeof(_heavensgate), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!heavensgate)
		return;
	memcpy(heavensgate, _heavensgate, sizeof(_heavensgate));
	if (!bInitialized) {
		WindowsSystemCallTableIndexGrabber syscall;
		if (!syscall.Usable())
			return;
		x64_code_wpm = (PBYTE)VirtualAlloc(nullptr, sizeof(x64_code_WPMRPM), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(x64_code_wpm, x64_code_WPMRPM, sizeof(x64_code_WPMRPM));
		*(PDWORD)&x64_code_wpm[sizeof(x64_code_WPMRPM) - 10] = (DWORD)&retfunc;
		*FindSysCallIndexPatchable(&x64_code_wpm[0], sizeof(x64_code_WPMRPM)) = syscall.GetIndex("NtWriteVirtualMemory");
		x64_code_rpm = (PBYTE)VirtualAlloc(nullptr, sizeof(x64_code_WPMRPM), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(x64_code_rpm, x64_code_WPMRPM, sizeof(x64_code_WPMRPM));
		*(PDWORD)&x64_code_rpm[sizeof(x64_code_WPMRPM) - 10] = (DWORD)&retfunc;
		*FindSysCallIndexPatchable(&x64_code_rpm[0], sizeof(x64_code_WPMRPM)) = syscall.GetIndex("NtReadVirtualMemory");
		x64_code_qvm = (PBYTE)VirtualAlloc(nullptr, sizeof(x64_code_VQEX), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(x64_code_qvm, x64_code_VQEX, sizeof(x64_code_VQEX));
		*(PDWORD)&x64_code_qvm[sizeof(x64_code_VQEX) - 10] = (DWORD)&retfunc;
		*FindSysCallIndexPatchable(&x64_code_qvm[0], sizeof(x64_code_VQEX)) = syscall.GetIndex("NtQueryVirtualMemory");
		x64_code_avm = (PBYTE)VirtualAlloc(nullptr, sizeof(x64_code_VAEX), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(x64_code_avm, x64_code_VAEX, sizeof(x64_code_VAEX));
		*(PDWORD)&x64_code_avm[sizeof(x64_code_VAEX) - 10] = (DWORD)&retfunc;
		*FindSysCallIndexPatchable(&x64_code_avm[0], sizeof(x64_code_VAEX)) = syscall.GetIndex("NtAllocateVirtualMemory");
		x64_code_fvm = (PBYTE)VirtualAlloc(nullptr, sizeof(x64_code_VFEX), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(x64_code_fvm, x64_code_VFEX, sizeof(x64_code_VFEX));
		*(PDWORD)&x64_code_fvm[sizeof(x64_code_VFEX) - 10] = (DWORD)&retfunc;
		*FindSysCallIndexPatchable(&x64_code_fvm[0], sizeof(x64_code_VFEX)) = syscall.GetIndex("NtFreeVirtualMemory");
		x64_code_pvm = (PBYTE)VirtualAlloc(nullptr, sizeof(x64_code_VPEX), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(x64_code_pvm, x64_code_VPEX, sizeof(x64_code_VPEX));
		*(PDWORD)&x64_code_pvm[sizeof(x64_code_VPEX) - 10] = (DWORD)&retfunc;
		*FindSysCallIndexPatchable(&x64_code_pvm[0], sizeof(x64_code_VPEX)) = syscall.GetIndex("NtProtectVirtualMemory");
		x64_code_crt = (PBYTE)VirtualAlloc(nullptr, sizeof(x64_code_CRT), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		memcpy(x64_code_crt, x64_code_CRT, sizeof(x64_code_CRT));
		*(PDWORD)&x64_code_crt[sizeof(x64_code_CRT) - 10] = (DWORD)&retfunc;
		*FindSysCallIndexPatchable(&x64_code_crt[0], sizeof(x64_code_CRT)) = syscall.GetIndex("NtCreateThreadEx");
		bInitialized = true;
	}

	bUsable = true;
}

Nt64::~Nt64()
{
	if (heavensgate != nullptr)
		VirtualFree(heavensgate, 0, MEM_RELEASE);
	/*
	if (x64_code_wpm != nullptr)
		VirtualFree(x64_code_wpm, 0, MEM_RELEASE);
	if (x64_code_rpm != nullptr)
		VirtualFree(x64_code_rpm, 0, MEM_RELEASE);
	if (x64_code_qvm != nullptr)
		VirtualFree(x64_code_qvm, 0, MEM_RELEASE);
	if (x64_code_avm != nullptr)
		VirtualFree(x64_code_avm, 0, MEM_RELEASE);
	if (x64_code_fvm != nullptr)
		VirtualFree(x64_code_fvm, 0, MEM_RELEASE);
	if (x64_code_pvm != nullptr)
		VirtualFree(x64_code_pvm, 0, MEM_RELEASE);
	if (x64_code_crm != nullptr)
		VirtualFree(x64_code_crm, 0, MEM_RELEASE);
	*/
}

BOOL Nt64::WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, PBYTE pBuf, DWORD dwSize, PULONGLONG ullBytesWritten)
{
	if (!this->Usable())
		return FALSE;
	*(PDWORD)&heavensgate[1] = (DWORD)x64_code_wpm;
	__asm{
			sub esp, 4

			push 0
			push dword ptr[ullBytesWritten]

			push 0
			push dwSize

			lea eax, [lpBaseAddress]
			push dword ptr[eax + 4] //you could also do push dword ptr [lpBaseAddress + 4], push dword ptr [lpBaseAddress]
			push dword ptr[eax]

			lea eax, [pBuf]
			push 0
			push[eax]

			push 0
			push hProcess
	}
	return (NT_SUCCESS(((NTSTATUS(*)())(&heavensgate[0]))()));
}

BOOL Nt64::ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, PBYTE pBuf, DWORD dwSize, PULONGLONG ullBytesWritten)
{
	if (!this->Usable())
		return FALSE;
	*(PDWORD)&heavensgate[1] = (DWORD)&x64_code_rpm[0];
	__asm{
			sub esp, 4

			push 0
			push dword ptr[ullBytesWritten]

			push 0
			push dwSize

			lea eax, [lpBaseAddress]
			push dword ptr[eax + 4]
			push dword ptr[eax]

			lea eax, [pBuf]
			push 0
			push[eax]

			push 0
			push hProcess
	}
	return (NT_SUCCESS(((NTSTATUS(*)())(&heavensgate[0]))()));
}


/*
NTSTATUS ZwQueryVirtualMemory(
_In_      HANDLE                   ProcessHandle,
_In_opt_  PVOID                    BaseAddress,
_In_      MEMORY_INFORMATION_CLASS MemoryInformationClass,
_Out_     PVOID                    MemoryInformation,
_In_      SIZE_T                   MemoryInformationLength,
_Out_opt_ PSIZE_T                  ReturnLength
);
*/
ULONG Nt64::VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, ULONG ulLength)
{
	if (!this->Usable())
		return FALSE;
	//const MemoryBasicInformation = 0;
	*(PDWORD)&heavensgate[1] = (DWORD)&x64_code_qvm[0];
	ULONGLONG len = 0; //I noticed that the stack was being corrupted for no apparent reason, and found out it was due to this being set incorrectly, SIZE_T = 64-bits on x64.
	__asm{
			sub esp, 4 //extra space for return address
			push 0
			lea eax, [len] //ReturnLength
			push eax

			push 0
			push ulLength //MemoryInformationLength

			push 0
			push dword ptr[lpBuffer] //MemoryInformation

			lea eax, lpAddress //BaseAddress
			push dword ptr[eax + 4]
			push dword ptr[eax]

			push 0
			push hProcess //ProcessHandle
	}
	return (NT_SUCCESS(((NTSTATUS(*)())(&heavensgate[0]))())) ? ULONG(len) : 0;
}

ULONGLONG Nt64::VirtualAllocEx(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD flAllocationType, DWORD flProtect)
{
	if (!this->Usable())
		return FALSE;
	*(PDWORD)&heavensgate[1] = (DWORD)&x64_code_avm[0];
	ULONGLONG ullAddress = lpAddress;
	ULONGLONG ullSize = dwSize;
	__asm{
			sub esp, 4
			push 0
			push dword ptr [flProtect]
			push 0
			push dword ptr [flAllocationType]
			push 0

			push 0
			lea eax, [ullSize]
			push eax

			lea eax, [ullAddress]
			push 0
			push eax

			push 0
			push dword ptr [ hProcess ]
	}
	return (NT_SUCCESS(((NTSTATUS(*)())(&heavensgate[0]))())) ? ullAddress : 0;
}

BOOL Nt64::VirtualFreeEx(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD dwFreeType)
{
	if (!this->Usable())
		return FALSE;
	*(PDWORD)&heavensgate[1] = (DWORD)&x64_code_fvm[0];
	ULONGLONG ullSize = dwSize;
	__asm{
		sub esp, 4

			push 0
			push dword ptr[dwFreeType]

			lea eax, [ullSize]
			push 0
			push eax

			lea eax, [lpAddress]
			push 0
			push eax

			push 0
			push dword ptr[hProcess]
	}
	return (NT_SUCCESS(((NTSTATUS(*)())(&heavensgate[0]))()));
}


BOOL Nt64::VirtualProtectEx(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	if (!this->Usable())
		return FALSE;
	*(PDWORD)&heavensgate[1] = (DWORD)&x64_code_pvm[0];
	ULONGLONG ullSize = dwSize;
	__asm{
			sub esp, 4

			push 0
			push dword ptr[lpflOldProtect]

			push 0
			push dword ptr[flNewProtect]

			lea eax, [ullSize]
			push 0
			push eax

			lea eax, [lpAddress]
			push 0
			push eax

			push 0
			push dword ptr[hProcess]
	}
	return (NT_SUCCESS(((NTSTATUS(*)())(&heavensgate[0]))()));
}

typedef struct _OBJECT_ATTRIBUTES64 {
	ULONG            Length;
	ULONG64          RootDirectory;
	ULONG64			 ObjectName;
	ULONG            Attributes;
	ULONG64          SecurityDescriptor;
	ULONG64          SecurityQualityOfService;
}  OBJECT_ATTRIBUTES64, *POBJECT_ATTRIBUTES64;

#define InitializeObjectAttributes64(p, n, a, r, s) { \
          (p)->Length = sizeof(OBJECT_ATTRIBUTES64); \
          (p)->RootDirectory = r; \
          (p)->Attributes = a; \
          (p)->ObjectName = n; \
          (p)->SecurityDescriptor = (ULONG64)s; \
          (p)->SecurityQualityOfService = NULL; \
          }


HANDLE Nt64::CreateRemoteThread(HANDLE hProcess, DWORD64 lpStartAddress, DWORD64 lpParameter, bool bCreateSuspended)
{
	/*
NTSTATUS WINAPI NtCreateThreadEx(
  OUT PHANDLE hThread,
  IN ACCESS_MASK DesiredAccess,
  IN LPVOID ObjectAttributes,
  IN HANDLE ProcessHandle,
  IN LPTHREAD_START_ROUTINE lpStartAddress,
  IN LPVOID lpParameter,
  IN BOOL CreateSuspended, 
  IN ULONG StackZeroBits,
  IN ULONG SizeOfStackCommit,
  IN ULONG SizeOfStackReserve,
  OUT LPVOID lpBytesBuffer
);
	*/

	if (!this->Usable())
		return FALSE;
	/*
	//note: GetSecurityInfo requires READ_CONTROL access right in the process handle and Helpers::EnablePrivilege(SE_SECURITY_NAME);
	PVOID sd;
	DWORD dwRet = GetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
	DACL_SECURITY_INFORMATION,
	NULL, NULL, NULL, NULL, &sd);
	if (dwRet != ERROR_SUCCESS)
	return NULL;
	OBJECT_ATTRIBUTES64 oa;
	InitializeObjectAttributes64(&oa, NULL, OBJ_CASE_INSENSITIVE, NULL, (ULONG64)sd);
	*/

	*(PDWORD)&heavensgate[1] = (DWORD)&x64_code_crt[0];
	ULONGLONG hThread = 0;
	
	__asm{
			sub esp, 4
			
			push 0 //lpBytesBuffer
			push 0

			push 0
			push 0 //size of stack reserve

			push 0
			push 0 //size of stack commit
			
			push 0
			push 0 // stack zero bits

			push 0
			movzx eax, [bCreateSuspended]
			push eax
			
			push dword ptr[lpParameter + 4]
			push dword ptr[lpParameter + 0]

			lea eax, dword ptr [lpStartAddress]
			push [eax + 4]
			push [eax]

			push 0
			push dword ptr [hProcess]

			push 0 //ObjectAttributes
			push 0
			//lea eax, [oa] 
			// push eax

			push 0 // Access Mask
			push THREAD_ALL_ACCESS//THREAD_ALL_ACCESS == 0x001FFFFF

			push 0
			lea eax, [hThread]
			push eax
	}
	NTSTATUS nt = ((NTSTATUS(*)())(&heavensgate[0]))();
	if (SUCCEEDED(nt)) {
		/*if (sd != nullptr)
			LocalFree(sd);*/
		return (HANDLE)hThread;
	}
	else {
		/*if (sd != nullptr)
			LocalFree(sd);*/
		char buf[64];
		sprintf_s(buf, "%X", nt);
		MessageBoxA(0, buf, "Failure", 64);
		return NULL;
	}
}

bool Nt64::bInitialized = false;
PBYTE Nt64::x64_code_wpm = nullptr;
PBYTE Nt64::x64_code_rpm = nullptr;
PBYTE Nt64::x64_code_qvm = nullptr;
PBYTE Nt64::x64_code_avm = nullptr;
PBYTE Nt64::x64_code_fvm = nullptr;
PBYTE Nt64::x64_code_pvm = nullptr;
PBYTE Nt64::x64_code_crt = nullptr;

WindowsSystemCallTableIndexGrabber::WindowsSystemCallTableIndexGrabber()
{
	bUsable = false;
	DWORD dwIndex = 0;
	PVOID pv;
	if (!Wow64DisableWow64FsRedirection(&pv))
		return;
	wchar_t filename[MAX_PATH];
	GetSystemDirectory(filename, MAX_PATH);
	wcscat_s(filename, sizeof(filename) / sizeof(wchar_t), L"\\ntdll.dll");
	HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	Wow64RevertWow64FsRedirection(pv);
	if (hFile == INVALID_HANDLE_VALUE) {
		return;
	}
	dwSize = GetFileSize(hFile, nullptr);
	ntdll_buffer = new BYTE[dwSize];
	if (ntdll_buffer.ptr() == nullptr || dwSize < sizeof(IMAGE_DOS_HEADER)) {
		CloseHandle(hFile);
		return;
	}
	BOOL bRead = ReadFile(hFile, &ntdll_buffer[0], dwSize, &dwSize, nullptr);
	CloseHandle(hFile);
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)ntdll_buffer.ptr();
	if (!bRead || pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hFile);
		return;
	}
	pINH = (PIMAGE_NT_HEADERS64)(ntdll_buffer.ptr() + pIDH->e_lfanew);
	if (pINH->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC/*pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64*/) {
		CloseHandle(hFile);
		return;
	}
	pIED = PIMAGE_EXPORT_DIRECTORY(PETools::ImageRvaToVa64(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, (DWORD)ntdll_buffer.ptr(), pINH));
	if (pIED == nullptr)
		return;
	bUsable = true;
}

DWORD WindowsSystemCallTableIndexGrabber::GetIndex(PCHAR pFunc)
{
	if (!Usable())
		return NULL;
	for (DWORD i = 0; i < pIED->NumberOfNames; i++) {
		DWORD dwAddress = (DWORD)PETools::ImageRvaToVa64(pIED->AddressOfNames + (i * 4), (ULONG_PTR)ntdll_buffer.ptr(), pINH);
		PCHAR pName = PCHAR(PETools::ImageRvaToVa64(*PDWORD(dwAddress), (ULONG_PTR)ntdll_buffer.ptr(), pINH));
		if (strcmp(pName, pFunc) == 0) {
			dwAddress = pIED->AddressOfNameOrdinals + (i * 2);
			WORD wOrdinal = WORD(*PDWORD(PETools::ImageRvaToVa64(dwAddress, ULONG_PTR(ntdll_buffer.ptr()), pINH)));
			dwAddress = pIED->AddressOfFunctions + (wOrdinal * 4);
			PBYTE pFunc = PBYTE(PETools::ImageRvaToVa64(*PDWORD(PETools::ImageRvaToVa64(dwAddress, ULONG_PTR(ntdll_buffer.ptr()), pINH)), ULONG_PTR(ntdll_buffer.ptr()), pINH));
			return *PDWORD(&pFunc[4]);
		}
	}
	return NULL;
}