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
#define __STDC__ 1
#define __STDC_WANT_SECURE_LIB__ 0
#define _STRALIGN_USE_SECURE_CRT 0
#endif
#include <Windows.h>
#include "crt.h"
#include <TlHelp32.h>
#include "string.h"
#include "manualmap.h"
#include "ext64.h"
#include <winternl.h>
#include "petools.h"
#include "../mutex.hpp"
#include "../list.hpp"
#include "strutils.h"

/*
steps to manually mapping dll into remote process:
1)Allocate memory for dll
2)Write pe header & map sections
3)resolve imports
4)fix base relocations

optional:
Resolve exports
(there are some other things, but i'm not familiar with them)
*/

/*
//moved to petools.cpp
PBYTE GetPtrFromRVA32(DWORD dwRVA, DWORD dwBase, PIMAGE_NT_HEADERS32 pINH)
{
PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
if (pISH == nullptr)
return nullptr;
for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++) {
if (dwRVA >= pISH[i].VirtualAddress && dwRVA < pISH[i].VirtualAddress + pISH[i].Misc.VirtualSize)
return PBYTE((dwBase + dwRVA) - (pISH[i].VirtualAddress - pISH[i].PointerToRawData));
}
return nullptr;
}

DWORD64 GetPtrFromRVA64(DWORD64 dwRVA, DWORD64 dwBase, PIMAGE_NT_HEADERS64 pINH)
{
PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
if (pISH == nullptr)
return 0;
for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++){
if (dwRVA >= pISH[i].VirtualAddress && dwRVA < pISH[i].VirtualAddress + pISH[i].Misc.VirtualSize)
return DWORD64((dwBase + dwRVA) - (pISH[i].VirtualAddress - pISH[i].PointerToRawData));
}
return 0;
}
*/

//NtCreateThreadEx() is used to bypass Windows 7 Session Separation:
//http://securityxploded.com/ntcreatethreadex.php

typedef NTSTATUS(WINAPI *tNtCreateThreadEx)
(
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

struct NtCreateThreadExBuffer
{
	ULONG Size;
	ULONG Unknown1;
	ULONG Unknown2;
	PULONG Unknown3;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONG Unknown6;
	PULONG Unknown7;
	ULONG Unknown8;
};

HMODULE RemoteGetModuleHandleA32(DWORD dwPID, PCHAR pModule)
{
	wchar_t wide[MAX_PATH];
	int iRet = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, pModule, -1, wide, sizeof(wide) / sizeof(WCHAR));
	if (iRet == NULL) return NULL;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hSnapShot == INVALID_HANDLE_VALUE) return NULL;
	MODULEENTRY32 mod;
	mod.dwSize = sizeof(mod);
	if (!Module32First(hSnapShot, &mod))
	{
		CloseHandle(hSnapShot);
		return NULL;
	}
	HMODULE hMod = NULL;
	do {
		if (!wcsicmp(wide, mod.szModule))
		{
			hMod = mod.hModule;
			break;
		}
	} while (Module32Next(hSnapShot, &mod));
	CloseHandle(hSnapShot);
	return hMod;
}

HMODULE MapRemoteMod32(HANDLE hProcess, DWORD dwPID, PCHAR pModule)
{
	PBYTE pLoadLib = (PBYTE)GetProcAddress(GetModuleHandleA("KERNEL32"), "LoadLibraryA");
	if (pLoadLib == nullptr)
		return NULL;
	HMODULE hRemote = RemoteGetModuleHandleA32(dwPID, "kernel32.dll");
	if (hRemote == nullptr)
		return NULL;
	pLoadLib += (hRemote - GetModuleHandleA("KERNEL32"));
	DWORD dwLen = strlen(pModule) + 1;
	PBYTE pTmp = (PBYTE)VirtualAllocEx(hProcess, NULL, dwLen, MEM_COMMIT, PAGE_READWRITE);
	if (pTmp == nullptr)
		return NULL;
	BOOL bWritten = WriteProcessMemory(hProcess, pTmp, pModule, dwLen, NULL);
	if (bWritten == FALSE)
	{
		VirtualFreeEx(hProcess, pTmp, NULL, MEM_RELEASE);
		return NULL;
	}

	//HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLib, (LPVOID)pTmp, NULL, NULL);
	
	tNtCreateThreadEx NtCreateThreadEx = (tNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

	if (!NtCreateThreadEx) {
		VirtualFreeEx(hProcess, pTmp, NULL, MEM_RELEASE);
		return NULL;
	}
	NtCreateThreadExBuffer ntbuffer;

	memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
	DWORD temp1 = 0;
	DWORD temp2 = 0;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = 0x8;
	ntbuffer.Unknown3 = &temp2;
	ntbuffer.Unknown4 = 0;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = 4;
	ntbuffer.Unknown7 = &temp1;
	ntbuffer.Unknown8 = 0;
	HANDLE hRemoteThread;
	NTSTATUS status = NtCreateThreadEx(
		&hRemoteThread,
		0x1FFFFF,
		NULL,
		hProcess,
		(LPTHREAD_START_ROUTINE)pLoadLib,
		pTmp,
		FALSE, //start instantly
		NULL,
		NULL,
		NULL,
		&ntbuffer
	);

	if (hRemoteThread != NULL)
	{
		WaitForSingleObject(hRemoteThread, 10000);
		DWORD dwResult;
		BOOL bSuccess = GetExitCodeThread(hRemoteThread, &dwResult);
		CloseHandle(hRemoteThread);
		if (bSuccess) {
			if (dwResult != STILL_ACTIVE)
				VirtualFreeEx(hProcess, pTmp, NULL, MEM_RELEASE);
		}
		return RemoteGetModuleHandleA32(dwPID, pModule);
	}
	else
		return NULL;
}

PBYTE RemoteGetProcAddress32(DWORD dwPID, HANDLE hProcess, PCHAR pModule, PCHAR pFunc)
{
	HMODULE hLocal = LoadLibraryA(pModule), hRemote = RemoteGetModuleHandleA32(dwPID, pModule);
	if (hRemote == NULL)
		hRemote = MapRemoteMod32(hProcess, dwPID, pModule);
	if (!hRemote || !hLocal) return nullptr;
	FARPROC fpTmp = GetProcAddress(hLocal, pFunc);
	return fpTmp == nullptr ? nullptr : PBYTE((DWORD)fpTmp + (hRemote - hLocal)); //not sure if this will work for forwarded exports
}

bool FixImports32(DWORD dwPID, HANDLE hProcess, PBYTE pData, PIMAGE_NT_HEADERS32 pINH, PIMAGE_IMPORT_DESCRIPTOR pIID)
{
	PCHAR pModule;
	while ((pModule = (PCHAR)PETools::ImageRvaToVa(pIID->Name, (DWORD)pData, pINH)) != nullptr) {
		PIMAGE_THUNK_DATA32 pITD = (PIMAGE_THUNK_DATA32)PETools::ImageRvaToVa(pIID->FirstThunk, (DWORD)pData, pINH);
		if (pITD == nullptr)
			break;
		while (pITD->u1.AddressOfData != NULL)
		{
			PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)PETools::ImageRvaToVa(pITD->u1.AddressOfData, (DWORD)pData, pINH);
			if (pIIBN == nullptr)
				break;
			pITD->u1.Function = (DWORD)RemoteGetProcAddress32(dwPID, hProcess, pModule, pIIBN->Name);
			if (pITD->u1.Function == NULL)
				return false;
			pITD++;
		}
		pIID++;
	}
	return true;
}

void FixRelocs32(DWORD dwLocalBase, DWORD dwRemoteBase, PIMAGE_NT_HEADERS32 pINH, PIMAGE_BASE_RELOCATION pIBN)
{
	DWORD dwSize = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, dwBytes = NULL,
		delta = (dwRemoteBase - pINH->OptionalHeader.ImageBase);

	while (dwBytes < dwSize)
	{
		PBYTE locBase = (PBYTE)PETools::ImageRvaToVa(pIBN->VirtualAddress, dwLocalBase, pINH);
		PWORD locData = PWORD((DWORD)pIBN + sizeof(IMAGE_BASE_RELOCATION));
		DWORD dwNumRelocs = (pIBN->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION));
		if (dwNumRelocs)
		{
			dwNumRelocs /= sizeof(WORD);
			for (DWORD i = 0; i < dwNumRelocs; i++)
			{
				if (((*locData >> 12) & IMAGE_REL_BASED_HIGHLOW) > 0)
				{
					*PDWORD(DWORD(locBase) + (*locData & 0x0FFF)) += delta;
				}
				locData++;
			}
		}
		dwBytes += pIBN->SizeOfBlock;
		pIBN = (PIMAGE_BASE_RELOCATION)locData;
	}

}

bool ManualMap32(DWORD dwPID, PBYTE pDll, DWORD dwDllLen)
{
	if (pDll == nullptr || dwDllLen < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32))
		return false;
	SmartPtr<BYTE> pMem = new BYTE[dwDllLen];
	if (pMem.ptr() == nullptr)
		return false;
	memcpy(&pMem[0], pDll, dwDllLen);
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)&pMem[0];
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((PBYTE)pIDH + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE || pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || pINH->OptionalHeader.AddressOfEntryPoint == NULL || (pINH->FileHeader.Characteristics & IMAGE_FILE_DLL) == FALSE)
		return false;

	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, dwPID);
	if (hProcess == NULL)
		return false;

	PBYTE pModule = (PBYTE)VirtualAllocEx(hProcess, nullptr, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pModule == nullptr) {
		CloseHandle(hProcess);
		return false;
	}
	//Write the PE header into the remote process's memory space
	WriteProcessMemory(hProcess, pModule, &pMem[0], pINH->OptionalHeader.SizeOfHeaders/*pINH->FileHeader.SizeOfOptionalHeader + sizeof(pINH->FileHeader) + sizeof(pINH->Signature)*/, NULL);
	/*
	process.exe   - 55                     - push ebp
	process.exe+1 - 8B EC                  - mov ebp,esp
	process.exe+3 - 6A 00                  - push 00
	process.exe+5 - 6A 01                  - push 01
	process.exe+7 - 6A 00                  - push 00
	process.exe+9 - FF 55 08               - call dword ptr [ebp+08]
	process.exe+C - 5D                     - pop ebp
	process.exe+D - C2 0400                - ret 0004
	*/
	const BYTE Stub[16] = { 0x55, 0x8B, 0xEC, 0x6A, 0x00, 0x6A, 0x01, 0x6A, 0x00, 0xFF, 0x55, 0x08, 0x5D, 0xC2, 0x04, 0x00 };
	PBYTE pStub = (PBYTE)VirtualAllocEx(hProcess, NULL, sizeof(Stub), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pStub == nullptr)
	{
		VirtualFreeEx(hProcess, pModule, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	WriteProcessMemory(hProcess, pStub, &Stub[0], sizeof(Stub), NULL);

	//fix imports
	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)PETools::ImageRvaToVa(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, (DWORD)&pMem[0], pINH);
		if (!FixImports32(dwPID, hProcess, &pMem[0], pINH, pIID)) {
			VirtualFreeEx(hProcess, pModule, 0, MEM_RELEASE);
			VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return false;
		}
	}

	//fix base relocations
	//base relocations explained:
	//   Fix "base relocations" of the new module.  Base relocations are places
	//   in the module that use absolute addresses to reference data.  Since
	//   the base address of the module can be different at different times,
	//   the base relocation data is necessary to make the module loadable
	//   at any address.

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		PIMAGE_BASE_RELOCATION pIBR = (PIMAGE_BASE_RELOCATION)PETools::ImageRvaToVa(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, (DWORD)&pMem[0], pINH);
		FixRelocs32((DWORD)&pMem[0], (DWORD)pModule, pINH, pIBR);
	}

	//map sections
	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
	DWORD dwBytes = 0;
	for (WORD i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		if (dwBytes >= pINH->OptionalHeader.SizeOfImage)
			break;
		WriteProcessMemory(hProcess, pModule + pISH->VirtualAddress, &pMem[0] + pISH->PointerToRawData, pISH->SizeOfRawData, NULL);
		DWORD virtualSize = pISH->VirtualAddress;
		virtualSize = pISH[1].VirtualAddress - virtualSize;
		dwBytes += virtualSize;
		DWORD dwOld;
		VirtualProtectEx(hProcess, pModule + pISH->VirtualAddress, virtualSize, pISH->Characteristics & 0x00FFFFFF, &dwOld);
		pISH++;
	}
	//HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pStub, (PVOID)((DWORD)pModule + pINH->OptionalHeader.AddressOfEntryPoint), NULL, NULL);
	tNtCreateThreadEx NtCreateThreadEx = (tNtCreateThreadEx)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");
	if (!NtCreateThreadEx) {
		VirtualFreeEx(hProcess, pStub, NULL, MEM_RELEASE);
		VirtualFreeEx(hProcess, pModule, NULL, MEM_RELEASE);
		::CloseHandle(hProcess);
		return NULL;
	}
	NtCreateThreadExBuffer ntbuffer;

	memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
	DWORD temp1 = 0;
	DWORD temp2 = 0;

	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = 0x8;
	ntbuffer.Unknown3 = &temp2;
	ntbuffer.Unknown4 = 0;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = 4;
	ntbuffer.Unknown7 = &temp1;
	ntbuffer.Unknown8 = 0;
	HANDLE hRemoteThread;
	NTSTATUS status = NtCreateThreadEx(
		&hRemoteThread,
		0x1FFFFF,
		NULL,
		hProcess,
		(LPTHREAD_START_ROUTINE)pStub,
		(PVOID)((DWORD)pModule + pINH->OptionalHeader.AddressOfEntryPoint),
		FALSE, //start instantly
		NULL,
		NULL,
		NULL,
		&ntbuffer
	);
	if (hRemoteThread == NULL)
	{
		VirtualFreeEx(hProcess, pModule, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	DWORD dwResult = WaitForSingleObject(hRemoteThread, 10000);
	BOOL bSuccess = GetExitCodeThread(hRemoteThread, &dwResult);
	CloseHandle(hRemoteThread);
	//if (dwResult == WAIT_TIMEOUT) return false;
	if (dwResult == WAIT_OBJECT_0 && bSuccess) {
		if (dwResult != STILL_ACTIVE)
			VirtualFreeEx(hProcess, pStub, NULL, MEM_RELEASE);
	}
	CloseHandle(hProcess);
	return true;
}

// NtQueryInformationProcess for pure 32 and 64-bit processes
typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef LONG		KPRIORITY;
typedef struct _PROCESS_BASIC_INFORMATION64
{
	NTSTATUS	ExitStatus;
	ULONG		Reserved0;
	ULONG64		PebBaseAddress;
	ULONG64		AffinityMask;
	KPRIORITY	BasePriority;
	ULONG		Reserved1;
	ULONG64		uUniqueProcessId;
	ULONG64		uInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

struct _LIST_ENTRY64
{
	PVOID64 Flink;
	PVOID64 Blink;
};

typedef struct _PEB_LDR_DATA64
{
	ULONG			Length;
	BOOLEAN			Initialized;
	ULONG64			SsHandle;
	LIST_ENTRY64	InLoadOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InLoadOrderModuleList
	LIST_ENTRY64	InMemoryOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InMemoryOrderModuleList
	LIST_ENTRY64	InInitializationOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InInitializationOrderModuleList
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

/*
typedef struct _PEB {
BYTE Reserved1[2];
BYTE BeingDebugged;
BYTE Reserved2[21];
PPEB_LDR_DATA LoaderData;
PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
BYTE Reserved3[520];
PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
BYTE Reserved4[136];
ULONG SessionId;
} PEB64;
*/

#define x64PEBLdrOffset 0x18 //24d

typedef struct _UNICODE_STRING64
{
	USHORT	Length;
	USHORT	MaximumLength;
	ULONG	Reserved;
	ULONG64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64		InLoadOrderModuleList;
	LIST_ENTRY64		InMemoryOrderModuleList;
	LIST_ENTRY64		InInitializationOrderModuleList;
	ULONG64				DllBase;
	ULONG64				EntryPoint;
	ULONG				SizeOfImage;
	UNICODE_STRING64	FullDllName;
	UNICODE_STRING64	BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

/*
https://github.com/w4kfu/whook/blob/master/src/modules.cpp
big thanks to w4kfu for his struct definitions + GetModuleList64, really saved me a lot of time.
Also thank you to nyx0 for the KINS GetRemoteProcAddress() function: https://github.com/nyx0/KINS/blob/master/source/dropper/x64utils.cpp, it helped me understand how i'd write my own.
*/

DWORD64 GetModuleHandle64(HANDLE hProcess, PCHAR pModule, Nt64& nt64)
{
	wchar_t modulename[MAX_PATH];
	if (!MultiByteToWideChar(CP_ACP, 0, pModule, -1, modulename, sizeof(modulename) / sizeof(wchar_t)))
		return 0;
	_NtQueryInformationProcess query = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64QueryInformationProcess64");
	if (!query)
		return 0;
	PROCESS_BASIC_INFORMATION64 pbi;
	DWORD err = query(hProcess, 0, &pbi, sizeof(pbi), NULL);
	if (err != 0)
		return 0;
	DWORD64 ldr64;
	if (!nt64.ReadProcessMemory64(hProcess, pbi.PebBaseAddress + x64PEBLdrOffset, (PBYTE)&ldr64, sizeof(ldr64), nullptr))
		return 0;
	PEB_LDR_DATA64 LdrData64;
	if (!nt64.ReadProcessMemory64(hProcess, (DWORD64)ldr64, (PBYTE)&LdrData64, sizeof(LdrData64), nullptr))
		return 0;
	LDR_DATA_TABLE_ENTRY64 LdrDataTable64;
	if (!nt64.ReadProcessMemory64(hProcess, LdrData64.InLoadOrderModuleList.Flink, (PBYTE)&LdrDataTable64, sizeof(LdrDataTable64), nullptr))
		return 0;
	wchar_t unicodeBuffer[MAX_PATH];
	ZeroMemory((PBYTE)unicodeBuffer, sizeof(unicodeBuffer));
	if (!nt64.ReadProcessMemory64(hProcess, LdrDataTable64.BaseDllName.Buffer, (PBYTE)&unicodeBuffer[0], LdrDataTable64.BaseDllName.Length, nullptr))
		return 0;
	if (!wcsicmp(modulename, unicodeBuffer))
		return LdrDataTable64.DllBase;

	while (LdrData64.InLoadOrderModuleList.Flink != LdrDataTable64.InLoadOrderModuleList.Flink) {
		if (!nt64.ReadProcessMemory64(hProcess, LdrDataTable64.InLoadOrderModuleList.Flink, (PBYTE)&LdrDataTable64, sizeof(LdrDataTable64), nullptr))
			return 0;
		if (LdrData64.InLoadOrderModuleList.Flink == LdrDataTable64.InLoadOrderModuleList.Flink)
			break;
		memset(unicodeBuffer, 0, sizeof(unicodeBuffer));
		if (!nt64.ReadProcessMemory64(hProcess, LdrDataTable64.BaseDllName.Buffer, (PBYTE)&unicodeBuffer[0], LdrDataTable64.BaseDllName.Length, nullptr))
			return 0;
		//if (!_wcsicmp(modulename, unicodeBuffer))
		//return LdrDataTable64.DllBase;
		if (!wcsicmp(modulename, unicodeBuffer))
			return LdrDataTable64.DllBase;
	}
	return 0;
}

DWORD64 RemoteGetProcAddress64(HANDLE hProcess, PCHAR pModule, PCHAR pFunction, Nt64& nt64, const bool bLoadLibFunc);

DWORD64 MapRemoteMod64(HANDLE hProcess, PCHAR pModule, Nt64& nt64)
{
	DWORD64 dw64LoadLibraryA = RemoteGetProcAddress64(hProcess, "kernel32.dll", "LoadLibraryA", nt64, true);
	DWORD dwLen = strlen(pModule) + 1;
	DWORD64 dwLoadLibParameter = nt64.VirtualAllocEx(hProcess, NULL, dwLen, MEM_COMMIT, PAGE_READWRITE);
	if (dwLoadLibParameter == NULL)
		return NULL;
	BOOL bWritten = nt64.WriteProcessMemory64(hProcess, dwLoadLibParameter, (PBYTE)pModule, dwLen, nullptr);
	if (bWritten == FALSE)
	{
		nt64.VirtualFreeEx(hProcess, dwLoadLibParameter, NULL, MEM_RELEASE);
		return NULL;
	}

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)dw64LoadLibraryA, (LPVOID)dwLoadLibParameter, NULL, NULL);
	if (hRemoteThread != NULL)
	{
		WaitForSingleObject(hRemoteThread, 10000);
		DWORD dwResult;
		GetExitCodeThread(hRemoteThread, &dwResult);
		CloseHandle(hRemoteThread);
		if (dwResult != STILL_ACTIVE)
			nt64.VirtualFreeEx(hProcess, dwLoadLibParameter, NULL, MEM_RELEASE);
	}
	return GetModuleHandle64(hProcess, pModule, nt64);
}

DWORD64 RemoteGetProcAddress64(HANDLE hProcess, PCHAR pModule, PCHAR pFunction, Nt64& nt64, const bool bLoadLibFunc = false)
{
	DWORD64 hRemoteMod = GetModuleHandle64(hProcess, pModule, nt64);
	if (hRemoteMod == 0) { //to-do: map the required module into memory through manual mapping instead of LoadLibrary.
		if (bLoadLibFunc)
			return NULL;
		hRemoteMod = MapRemoteMod64(pModule, pModule, nt64);
		if (!hRemoteMod)
			return NULL;
	}
	SmartPtr<BYTE> buf(new BYTE[4096]);
	ZeroMemory(&buf[0], sizeof(buf));
	if (!nt64.ReadProcessMemory64(hProcess, hRemoteMod, &buf[0], 4096, nullptr)) {
		return 0;
	}

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)&buf[0];
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}
	PIMAGE_NT_HEADERS64 pINH = (PIMAGE_NT_HEADERS64)((DWORD)pIDH + pIDH->e_lfanew);
	DWORD dwEATSize = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)VirtualAlloc(nullptr, dwEATSize, MEM_COMMIT, PAGE_READWRITE);
	if (!nt64.ReadProcessMemory64(hProcess, hRemoteMod + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, (PBYTE)pIED, dwEATSize, nullptr)) {
		VirtualFree(pIED, 0, MEM_RELEASE);
		return 0;
	}
	DWORD dwNewBase = (ULONG_PTR)pIED - pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PDWORD pAddrOfNames = PDWORD(dwNewBase + pIED->AddressOfNames);
	DWORD64 dwResult64 = 0;
	for (DWORD i = 0; i < pIED->NumberOfNames; i++) {
		if (dwNewBase + pAddrOfNames[i] > (ULONG_PTR)pIED + dwEATSize || dwNewBase + pAddrOfNames[i] < (ULONG_PTR)pIED)
			break;
		if (!strcmp(PCHAR(dwNewBase + pAddrOfNames[i]), pFunction)) {  //!lstrcmpA
			PDWORD pAddrOfFunctions = PDWORD(dwNewBase + pIED->AddressOfFunctions);
			PWORD pAddrOfOrdinals = PWORD(dwNewBase + pIED->AddressOfNameOrdinals);
			DWORD dwFuncOffset = pAddrOfFunctions[pAddrOfOrdinals[i]];

			if (dwFuncOffset >= pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && dwFuncOffset < pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + dwEATSize) {
				//function is forwarded to another dll.
				PCHAR pForwardedFunc = PCHAR(dwNewBase + dwFuncOffset);
				auto parsed = Split(pForwardedFunc, '.'); //ex: NTDLL.RtlInitializeCriticalSection, which is forwarded from kernel32.dll!InitializeCritialSection
				parsed[0].get() += ".DLL";
				//MessageBoxA(0, parsed[0].get().c_str(), parsed[1].get().c_str(), 0);
				return RemoteGetProcAddress64(hProcess, parsed[0]->c_str(), parsed[1]->c_str(), nt64);
			}
			else
				dwResult64 = hRemoteMod + dwFuncOffset;
			break;
		}

	}

	VirtualFree(pIED, 0, MEM_RELEASE);
	return dwResult64;
}

bool FixImports64(DWORD dwPID, HANDLE hProcess, PBYTE pData, PIMAGE_NT_HEADERS64 pINH, PIMAGE_IMPORT_DESCRIPTOR pIID, Nt64& nt64)
{
	PCHAR pModule;
	while ((pModule = (PCHAR)PETools::ImageRvaToVa64(pIID->Name, (DWORD)pData, pINH)) != nullptr) {
		PIMAGE_THUNK_DATA64 pITD = (PIMAGE_THUNK_DATA64)PETools::ImageRvaToVa64(pIID->FirstThunk, (DWORD)pData, pINH);
		if (pITD == nullptr)
			break;
		while (pITD->u1.AddressOfData != NULL)
		{
			PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)PETools::ImageRvaToVa64(pITD->u1.AddressOfData, (DWORD)pData, pINH);
			if (pIIBN == nullptr)
				break;
			pITD->u1.Function = RemoteGetProcAddress64(hProcess, pModule, (PCHAR)&pIIBN->Name[0], nt64);
			//if (pITD->u1.Function == NULL)
				//MessageBoxA(0, pModule, (PCHAR)&pIIBN->Name[0], 0);
			if (pITD->u1.Function == NULL)
				return false;
			pITD++;
		}
		pIID++;
	}
	return true;
}

void FixRelocs64(DWORD dwLocalBase, DWORD64 dwRemoteBase, PIMAGE_NT_HEADERS64 pINH, PIMAGE_BASE_RELOCATION pIBN)
{
	DWORD dwSize = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, dwBytes = NULL;

	DWORD64 delta = (dwRemoteBase - pINH->OptionalHeader.ImageBase);

	while (dwBytes < dwSize)
	{
		PBYTE locBase = (PBYTE)PETools::ImageRvaToVa64(pIBN->VirtualAddress, dwLocalBase, pINH);
		PWORD locData = PWORD((DWORD)pIBN + sizeof(IMAGE_BASE_RELOCATION));
		DWORD dwNumRelocs = (pIBN->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION));
		if (dwNumRelocs)
		{
			dwNumRelocs /= sizeof(WORD);
			for (DWORD i = 0; i < dwNumRelocs; i++)
			{
				if (((*locData >> 12) & IMAGE_REL_BASED_HIGHLOW) > 0)
				{
					*PDWORD64(DWORD(locBase) + (*locData & 0x0FFF)) += delta;
				}
				locData++;
			}
		}
		dwBytes += pIBN->SizeOfBlock;
		pIBN = (PIMAGE_BASE_RELOCATION)locData;
	}

}

bool IsProcessInitialized(HANDLE hProcess, Nt64& nt64)
{
	_NtQueryInformationProcess query = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64QueryInformationProcess64");
	if (!query)
		return false;
	PROCESS_BASIC_INFORMATION64 pbi;
	DWORD err = query(hProcess, 0, &pbi, sizeof(pbi), NULL);
	if (err != 0)
		return false;
	DWORD64 ldr64;
	if (!nt64.ReadProcessMemory64(hProcess, pbi.PebBaseAddress + x64PEBLdrOffset, (PBYTE)&ldr64, sizeof(ldr64), nullptr))
		return false;
	PEB_LDR_DATA64 LdrData64;
	if (!nt64.ReadProcessMemory64(hProcess, (DWORD64)ldr64, (PBYTE)&LdrData64, sizeof(LdrData64), nullptr))
		return false;
	return LdrData64.Initialized == TRUE;
}

bool ManualMap64(DWORD dwPID, PBYTE pDll, DWORD dwDllLen)
{
	if (dwDllLen < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) || pDll == nullptr)
		return false;
	SmartPtr<BYTE> pMem(new BYTE[dwDllLen]);
	if (pMem.ptr() == nullptr)
		return false;
	memcpy(&pMem[0], pDll, dwDllLen);
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pMem.ptr();
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	PIMAGE_NT_HEADERS64 pINH = (PIMAGE_NT_HEADERS64)((PBYTE)pIDH + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE || (pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64 && pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) || pINH->OptionalHeader.AddressOfEntryPoint == NULL || (pINH->FileHeader.Characteristics & IMAGE_FILE_DLL) == FALSE)
		return false;
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION /*| READ_CONTROL*/, FALSE, dwPID);
	if (hProcess == NULL)
		return false;
	Nt64 nt64;
	if (nt64.Usable() == false)
		return false;
	ULONGLONG ullTick = GetTickCount64();
	while (!IsProcessInitialized(hProcess, nt64)) {
		if (GetTickCount64() - ullTick > 10000) {
			CloseHandle(hProcess);
			return false;
		}
		else
			Sleep(250);
	}
	
	DWORD64 pModule = nt64.VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pModule == NULL) {
		CloseHandle(hProcess);
		return false;
	}
	//Write the PE header into the remote process's memory space
	nt64.WriteProcessMemory64(hProcess, pModule, &pMem[0], pINH->OptionalHeader.SizeOfHeaders/*pINH->FileHeader.SizeOfOptionalHeader + sizeof(pINH->FileHeader) + sizeof(pINH->Signature)*/, NULL);
	static BYTE Stub[31] = {
		0x55, 0x48, 0x89, 0xE5, 0x49, 0x89, 0xC9, 0x48, 0x31, 0xC9, 0xBA, 0x01,
		0x00, 0x00, 0x00, 0x4D, 0x31, 0xC0, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xFF,
		0xD1, 0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3
	};
	
	DWORD64 pStub = nt64.VirtualAllocEx(hProcess, NULL, sizeof(Stub), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (pStub == NULL)
	{
		nt64.VirtualFreeEx(hProcess, pModule, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	nt64.WriteProcessMemory64(hProcess, pStub, &Stub[0], sizeof(Stub), NULL);
	//fix imports
	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)PETools::ImageRvaToVa64(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, (DWORD)&pMem[0], pINH);
		if (!FixImports64(dwPID, hProcess, &pMem[0], pINH, pIID, nt64)) {
			nt64.VirtualFreeEx(hProcess, pModule, 0, MEM_RELEASE);
			nt64.VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return false;
		}
	}
	//fix base relocations
	//base relocations explained:
	//   Fix "base relocations" of the new module.  Base relocations are places
	//   in the module that use absolute addresses to reference data.  Since
	//   the base address of the module can be different at different times,
	//   the base relocation data is necessary to make the module loadable
	//   at any address.

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
	{
		PIMAGE_BASE_RELOCATION pIBR = (PIMAGE_BASE_RELOCATION)PETools::ImageRvaToVa64(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, (DWORD)&pMem[0], pINH);
		FixRelocs64((DWORD)&pMem[0], (DWORD)pModule, pINH, pIBR);
	}

	//map sections
	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
	DWORD dwBytes = 0;
	for (WORD i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		if (dwBytes >= pINH->OptionalHeader.SizeOfImage)
			break;
		nt64.WriteProcessMemory64(hProcess, pModule + pISH->VirtualAddress, PBYTE((ULONG_PTR)&pMem[0] + pISH->PointerToRawData), pISH->SizeOfRawData, NULL);
		DWORD virtualSize = pISH->VirtualAddress;
		virtualSize = pISH[1].VirtualAddress - virtualSize;
		dwBytes += virtualSize;
		DWORD dwOld;
		nt64.VirtualProtectEx(hProcess, pModule + pISH->VirtualAddress, virtualSize, pISH->Characteristics & 0x00FFFFFF, &dwOld);
		pISH++;
	}
	ULONGLONG dw64EntryPoint = pModule + pINH->OptionalHeader.AddressOfEntryPoint;
	/*
	char buf[32];
	sprintf_s(buf, 32, "%X%X", static_cast<UINT32>((dw64EntryPoint >> 32) & 0xFFFFFFFF), static_cast<UINT32>(dw64EntryPoint & 0xFFFFFFFF));
	MessageBoxA(0, buf, "", 0);
	*/

	HANDLE hRemoteThread = nt64.CreateRemoteThread(hProcess, pStub, dw64EntryPoint, false);

	if (hRemoteThread == NULL)
	{
		nt64.VirtualFreeEx(hProcess, pModule, 0, MEM_RELEASE);
		nt64.VirtualFreeEx(hProcess, pStub, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	DWORD dwResult = WaitForSingleObject(hRemoteThread, 10000);
	CloseHandle(hRemoteThread);
	//if (dwResult == WAIT_TIMEOUT) return false;
	if (dwResult == WAIT_OBJECT_0) {
		//DWORD dwCode;
		//if (GetExitCodeThread(hRemoteThread, &dwCode))
		//if (dwCode == STILL_ACTIVE) //if (dwCode == NULL)
		nt64.VirtualFreeEx(hProcess, pStub, NULL, MEM_RELEASE);
	}
	CloseHandle(hProcess);
	return true;
}