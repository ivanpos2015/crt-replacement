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
#include <winternl.h>
#include "petools.h"
#include "string.h"
#include "../mutex.hpp"
#include "../list.hpp"
#include "strutils.h"

#define JMPX64_SIZE 12 //KERNEL32.CreateFileA - FF 25 0A150500        - jmp qword ptr [KERNEL32.QuirkIsEnabledForProcessWorker+8DD0]
#define JMPX32_SIZE 5

#define QWORD ULONGLONG

//add ntdll.lib to additional libraries, since GetPIDFromThrdHnd uses ntdll.dll!NtQueryInformationThread

bool match(const PBYTE memory, const PBYTE sig, const char* mask, const DWORD dwSigSize)
{
	for (DWORD j = 0; j < dwSigSize; j++)
		if (mask[j] == 'x' && memory[j] != sig[j])
			return false;
	return true;
}

namespace PETools {
	bool WriteProtectedMemory(PVOID dst, PVOID src, ULONG size)
	{
		if (!dst || !src || !size)
			return false;
		DWORD dwOld;
		if (!::VirtualProtect(dst, size, PAGE_READWRITE, &dwOld))
			return false;
		memcpy(dst, src, size);
		::VirtualProtect(dst, size, dwOld, &dwOld);
		return true;
	}
	PVOID ScanMemory(ULONG_PTR address, SIZE_T size, const PBYTE sig, const char* sigmask)
	{
		PBYTE pStart = (PBYTE)address;
		DWORD dwSigSize = (DWORD)strlen(sigmask);
		if (size < dwSigSize || address == NULL)
			return nullptr;
		for (SIZE_T i = 0; i < size - dwSigSize; i++) {
			if (match(&pStart[i], sig, sigmask, dwSigSize))
				return &pStart[i];
		}
		return nullptr;
	}

	PVOID ScanMemoryRegions(ULONG_PTR start, DWORD dwSize, const PBYTE sig, const char * mask, DWORD dwMemoryProtection)
	{
		ULONG_PTR end = start + dwSize;
		DWORD dwSigSize = (DWORD)strlen(mask);
		if (dwSize < dwSigSize || !start)
			return nullptr;
		MEMORY_BASIC_INFORMATION mbi;
		ULONG_PTR address = start;
		while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
			if (address >= end)
				break;
			if (mbi.RegionSize >= dwSigSize && (mbi.Protect & dwMemoryProtection) > 0) {
				for (PBYTE p = (PBYTE)mbi.BaseAddress; p < (PBYTE)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize - dwSigSize); p++) {
					if (match(p, sig, mask, dwSigSize))
						return p;
				}
			}
			address = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
		}
		return nullptr;
	}

	PVOID ScanModuleMemorySection(HMODULE hModule, char * section_name, const PBYTE sig, const char * sigmask)
	{
		if (!hModule)
			return nullptr;
		PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)hModule;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;
		PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((ULONG_PTR)pIDH + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH); //PIMAGE_SECTION_HEADER pISH = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pINH + sizeof(IMAGE_NT_HEADERS));
		for (WORD i = 0; i < pINH->FileHeader.NumberOfSections; i++) {
			if (!memcmp(pISH[i].Name, section_name, strlen(section_name))) {
				return ScanMemory((ULONG_PTR)pIDH + pISH->VirtualAddress, pISH->SizeOfRawData, sig, sigmask);
			}
		}
		return nullptr;
	}


	/*
	chrome.GetHandleVerifier+D9720 - 48 8D 05 4977B301     - lea rax,[chrome.IsSandboxedProcess+124F988] { ["enable_http2"] }
	chrome.GetHandleVerifier+D9720 = 7FFCBEF50E80, chrome.IsSandboxedProcess+124F988 = 7FFCC0A885D0
	7FFCC0A885D0 - (7FFCBEF50E80 + 7) = 01B37749 = 4977B301 in little endian.
	*/
	DWORD x64CalculateLEADistance(ULONGLONG opcode_address, DWORD dwOpcodeLen, ULONGLONG target_address) //opcode_address = where address is loaded, target_address = address you want to load.
	{
		return static_cast<DWORD>(target_address - (opcode_address + dwOpcodeLen)); //or (target_address - opcode_address) - dwOpcodeLen
	}

	PVOID FindReferenceToPushedString(ULONG_PTR start_address, DWORD dwSize, char * string)
	{
		AsciiString strmask;
		strmask.reserve(strlen(string) + 1);
		strmask.fill('x');
		PVOID str_address = ScanMemory(start_address, dwSize, (PBYTE)string, strmask);
#ifndef _WIN64
		BYTE sig[5] = { 0x68, 0, 0, 0, 0 };
		*(DWORD *)(&sig[1]) = reinterpret_cast<DWORD>(str_address);
		return ScanMemory(start_address, dwSize, sig, "xxxxx");
#else
		BYTE sig[7] = { 0x48, 0x8D, 0x05, 0, 0, 0, 0 };
		PBYTE pStart = (PBYTE)start_address;
		for (DWORD i = 0; i < dwSize - sizeof(sig); i++) {
			*PDWORD(&sig[3]) = x64CalculateLEADistance(start_address + i, sizeof(sig), (ULONG_PTR)str_address);
			if (match(&pStart[i], sig, "xxxxxxx", sizeof(sig)))
				return &pStart[i];
		}
		return nullptr;
#endif
	}

	PVOID GetStartOfFunc(PVOID func)
	{
		while (func) {
			if (memcmp(func, "\x55\x8B\xEC", 3) == 0)
				return func;
			func = PVOID(ULONG_PTR(func) - 1);
		}
		return nullptr;
	}

	DWORD GetModuleSize(ULONG_PTR module)
	{
		PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)(module);
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;
		PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(ULONG_PTR(pIDH) + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return 0;
		return pINH->OptionalHeader.SizeOfImage + pINH->OptionalHeader.SizeOfHeaders;
	}

	bool PETools::IsPtrInModule(ULONG_PTR module, const void* ptr)
	{
		PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)module;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return false;
		PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(module + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return false;
		return ((ULONG_PTR)ptr >= module && (ULONG_PTR)ptr < module + pINH->OptionalHeader.SizeOfImage);
		//return ((ULONG_PTR)ptr < module + pINH->OptionalHeader.BaseOfCode + pINH->OptionalHeader.SizeOfCode);
	}

	sSectionData GetSectionData(const char* section, ULONG_PTR const module)
	{
		sSectionData tmp = { 0 };
		PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)(module);
		if (!pIDH || pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return tmp;
		PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(ULONG_PTR(pIDH) + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return tmp;
		PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
		for (WORD w = 0; w < pINH->FileHeader.NumberOfSections; w++) {
			if (!memcmp((char*)pISH->Name, section, strlen(section) + 1)) {
				tmp.lpMemory = (PBYTE)((ULONG_PTR)pIDH + pISH->VirtualAddress);
				tmp.dwSize = pISH->Misc.VirtualSize;
				break;
			}
			pISH++;
		}
		return tmp;
	}

	PPEB _cdecl GetPEB()
	{
#ifdef _WIN64
		return reinterpret_cast<PPEB>(__readgsqword(0x060));
#else
		__asm {
			mov eax, FS:[0x18] //linear address of TEB
			mov eax, [eax + 0x30] //linear address to PEB
		}
#endif
	}

	bool PETools::Is64Bit(HANDLE hProcess)
	{
		FARPROC p = GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
		if (!p)
			return false;

		BOOL bResult, bSuccess = ((BOOL(WINAPI*)(HANDLE, PBOOL))p)(hProcess, &bResult);
		if (!bSuccess)
			return false;
		return (bResult == FALSE) && (Is64BitOS()); //it's not running under wow64 & it's a 64-bit O.S. = 64-bit process. 
	}

	bool PETools::Is64Bit(DWORD dwProcess)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcess);
		if (!hProcess)
			return Is64BitOS();
		bool bResult = Is64Bit(hProcess);
		CloseHandle(hProcess);
		return bResult;
	}

	bool PETools::Is32Bit(HANDLE hProcess)
	{
		return !Is64Bit(hProcess);
	}

	bool PETools::Is32Bit(DWORD dwProcess)
	{
		return !Is64Bit(dwProcess);
	}

	bool PETools::Is64BitOS()
	{
		SYSTEM_INFO si;
		GetNativeSystemInfo(&si);
		return ((si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64) || (si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64));
	}

	bool PETools::IsPrivileged()
	{
		HANDLE hToken;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken))
			return false;
		TOKEN_ELEVATION elevation;
		DWORD dwInfoLen;
		if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwInfoLen)) {
			CloseHandle(hToken);
			return false;
		}
		CloseHandle(hToken);
		return (elevation.TokenIsElevated > 0);
	}

	PVOID GetImageHandle(PCWCHAR dll) //GetModuleHandle
	{
		PPEB peb = GetPEB();
		if (!peb)
			return nullptr;
		PLIST_ENTRY flink = peb->Ldr->InMemoryOrderModuleList.Flink,
			blink = peb->Ldr->InMemoryOrderModuleList.Blink;
		while (flink != blink) {
			PLDR_DATA_TABLE_ENTRY_ entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY_>(flink);
			if (0 == wcsicmp(dll, entry->BaseDllName.Buffer))
				return entry->DllBase;
			flink = flink->Flink;
		}
		return nullptr;
	}

	PBYTE GetProcAddress_IAT(PVOID pModule, const PCHAR dll, const PCHAR func) //basically GetProcAddress except it walks the IAT table; however, the module must import the function & the original thunk must not be destroyed(packers often do this to prevent PE reconstruction).
	{
		PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;
		PIMAGE_NT_HEADERS pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)pModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		if (!pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
			return nullptr;
		for (PIMAGE_IMPORT_DESCRIPTOR pIID = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((ULONG_PTR)pModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); pIID->Name != NULL; pIID++) {
			PCHAR pDllName = reinterpret_cast<PCHAR>((ULONG_PTR)pModule + pIID->Name);
			if (!stricmp(pDllName, dll)) {
				for (int index = 0; PIMAGE_THUNK_DATA((ULONG_PTR)pModule + pIID->OriginalFirstThunk + (sizeof(IMAGE_THUNK_DATA) * index))->u1.AddressOfData != NULL; index++) {
					PIMAGE_THUNK_DATA thunk = PIMAGE_THUNK_DATA((ULONG_PTR)pModule + pIID->OriginalFirstThunk + (sizeof(IMAGE_THUNK_DATA) * index));
					if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						continue;
					PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pModule + thunk->u1.AddressOfData);
					if (!stricmp(pIIBN->Name, func)) {
						return PBYTE(PIMAGE_THUNK_DATA((ULONG_PTR)pModule + pIID->FirstThunk + (sizeof(IMAGE_THUNK_DATA) * index))->u1.Function);
					}
				}
			}
		}
		return nullptr;
	}

	PVOID GetProcAddress_EAT(PVOID pModule, const PCHAR func)
	{
		if (!pModule)
			return nullptr;
		PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;
		PIMAGE_NT_HEADERS pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)pModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		if (!pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
			return nullptr;
		PIMAGE_DATA_DIRECTORY pIDD_EAT = &pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		PIMAGE_EXPORT_DIRECTORY pIED = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((ULONG_PTR)pModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		for (DWORD i = 0; i < pIED->NumberOfNames; i++) {
			PCHAR pFuncName = reinterpret_cast<PCHAR>((ULONG_PTR)pModule + PDWORD((ULONG_PTR)pModule + pIED->AddressOfNames)[i]);
			if (stricmp(func, pFuncName) == 0) {
				ULONG_PTR address = ULONG_PTR((ULONG_PTR)pModule + PDWORD((ULONG_PTR)pModule + pIED->AddressOfFunctions)[PWORD((ULONG_PTR)pModule + pIED->AddressOfNameOrdinals)[i]]);
				if (address >= (ULONG_PTR)pModule + pIDD_EAT->VirtualAddress && address < (ULONG_PTR)pModule + (pIDD_EAT->VirtualAddress + pIDD_EAT->Size)) {
					//function is forwarded.
					List<AsciiString> parsed = Split((PCHAR)address, '.');
					parsed[0].get() += ".DLL";
					return GetProcAddress_EAT(AsciiString(parsed[0].get() + "!" + parsed[1].get()).c_str());
				}
				else
					return PVOID(address);
			}
		}
		return nullptr;
	}

	PVOID GetProcAddress_EAT(const PCHAR func)
	{
		//return GetProcAddress_EAT(GetImageHandle(&UnicodeString::FromAsciiString(dll)[0]), func);
		auto parsed = Split(func, '!');
		return (parsed.size() == 2) ? GetProcAddress_EAT(GetImageHandle(UnicodeString::FromAsciiString(parsed[0]->c_str()).c_str()), &parsed[1].get()[0]) : nullptr;
	}

	bool RedirectIAT(PVOID pModule, const PVOID pOriginalFunc, const PVOID pNewFunc)
	{
		if (!pModule || !pOriginalFunc || !pNewFunc)
			return false;
		PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;
		PIMAGE_NT_HEADERS pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)pModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		if (!pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
			return nullptr;
		bool bSuccess = false;
		for (PIMAGE_IMPORT_DESCRIPTOR pIID = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((ULONG_PTR)pModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress); pIID->FirstThunk != NULL; pIID++) {
			//MessageBoxA(0, PCHAR((ULONG_PTR)pModule + pIID->Name), "", 64);
			for (PIMAGE_THUNK_DATA thunk = PIMAGE_THUNK_DATA((ULONG_PTR)pModule + pIID->FirstThunk); thunk->u1.Function != NULL; thunk++) {
				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					continue;
				if (thunk->u1.Function == (ULONG_PTR)pOriginalFunc) {
					DWORD dwOld;
					VirtualProtect(&thunk->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &dwOld);
					thunk->u1.Function = (ULONG_PTR)pNewFunc;
					VirtualProtect(&thunk->u1.Function, sizeof(ULONG_PTR), dwOld, &dwOld);
					bSuccess = true;
				}
			}
		}
		return bSuccess;
	}

//http://blog.airesoft.co.uk/code/importlister.cpp - if(importFiles->grAttrs & 1) - to-do
	//note: only after the delayed dll is loaded will this work(a delayed dll will only load after a function of that dll is to be called).
	bool RedirectDelayedIAT(LPVOID pModule, const PVOID pOriginalFunc, const PVOID pNewFunc)
	{
		if (!pModule || !pOriginalFunc || !pNewFunc)
			return false;
		PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;
		PIMAGE_NT_HEADERS pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)pModule + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		if (!pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
			return nullptr;
		bool bSuccess = false;

		for (PIMAGE_DELAYLOAD_DESCRIPTOR pIID = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>((ULONG_PTR)pModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress); pIID->ImportAddressTableRVA != NULL; pIID++) {
			//MessageBoxA(0, PCHAR((ULONG_PTR)pModule + pIID->DllNameRVA), "", 64);
			for (PIMAGE_THUNK_DATA thunk = PIMAGE_THUNK_DATA((ULONG_PTR)pModule + pIID->ImportAddressTableRVA); thunk->u1.Function != NULL; thunk++) {
				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					continue;
				if (thunk->u1.Function == (ULONG_PTR)pOriginalFunc) {
					DWORD dwOld;
					VirtualProtect(&thunk->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &dwOld);
					thunk->u1.Function = (ULONG_PTR)pNewFunc;
					VirtualProtect(&thunk->u1.Function, sizeof(ULONG_PTR), dwOld, &dwOld);
					bSuccess = true;
				}
			}
		}
		return bSuccess;
	}

	PVOID RedirectEAT(PVOID module, const PCHAR function, const PVOID replacement)
	{
		if (!module)
			return nullptr;
		PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;
		PIMAGE_NT_HEADERS pINH = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)module + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;
		if (!pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
			return nullptr;
		PIMAGE_EXPORT_DIRECTORY pIED = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((ULONG_PTR)module + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PDWORD name_table = reinterpret_cast<PDWORD>((ULONG_PTR)module + pIED->AddressOfNames);
		PDWORD func_table = reinterpret_cast<PDWORD>((ULONG_PTR)module + pIED->AddressOfFunctions);
		PWORD ord_table = reinterpret_cast<PWORD>((ULONG_PTR)module + pIED->AddressOfNameOrdinals);//ordinal table.
		for (DWORD i = 0; i < pIED->NumberOfNames; i++) {
			PCHAR pFuncName = reinterpret_cast<PCHAR>((ULONG_PTR)module + name_table[i]);
			if (stricmp(function, pFuncName) == 0) {
				PVOID original = PVOID((ULONG_PTR)module + func_table[ord_table[i]]);
				PVOID address = &func_table[ord_table[i]];
				DWORD dwOld;
				VirtualProtect(address, sizeof(DWORD), PAGE_READWRITE, &dwOld);
#pragma warning(disable:4267)
				*PDWORD(address) = static_cast<DWORD>((ULONG_PTR)replacement - (ULONG_PTR)module); //note: since it can only store DWORDs, if the function you're redirecting it to is too far away, it will cause an integer overflow(will most definitely happen in x64 processes).
#pragma warning(default:4267)
				VirtualProtect(address, sizeof(DWORD), dwOld, &dwOld);
				return original;
			}
		}
		return nullptr;
	}

	DWORD GetPIDFromThrdHnd(HANDLE hThread)
	{
		THREAD_BASIC_INFORMATION tbi;
		DWORD dwReturnLen;
		if (NT_ERROR(NtQueryInformationThread(hThread, THREADINFOCLASS(ThreadBasicInformation), &tbi, sizeof(tbi), &dwReturnLen)))
			return 0;
#pragma warning(disable:4311)
#pragma warning(disable:4302)
		return reinterpret_cast<DWORD>(tbi.ClientId.UniqueProcess);
#pragma warning(default:4302)
#pragma warning(default:4311)
	}
	
	ULONG_PTR ImageRvaToVa(ULONG_PTR tRVA, ULONG_PTR tBase, PIMAGE_NT_HEADERS pINH)
	{
		/*
			ImageRvaToVa description:
			The ImageRvaToVa function locates an RVA within the image header of a file that is mapped as a file and returns the virtual address of the corresponding byte in the file.
			explanation:
					RVA		     RVA 			physical size   physical offset					Characteristics
			Name	VirtualSize	VirtualAddress	SizeOfRawData	PointerToRawData
			.text	0x1000		0x1000			0x200			0x200				CODE_EXECUTE READ
			.rdata  0x1000		0x2000			0x200			0x400				INITIALIZED READ
			.data   0x1000		0x3000			0x200			0x600				DATA READ WRITE
			For each section, a SizeofRawData sized block is read from the file at PointerToRawData offset.
			It will be loaded into memory at the address ImageBase + VirtualAddress in a VirtualSize sized block, with specific characterisitics.

			suppose tRVA = 0x1001
			the rva is in the .text section, to get it's file offset you would do:
			RVA - (VirtualAddress - PointerToRawData)
			ex:
			0x1001 - (0x1000 - 0x200) = 0x1001 - 0xE00 = 0x201 
		*/
		PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
		if (pISH == nullptr)
			return NULL;
		for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++) {
			if (tRVA >= pISH[i].VirtualAddress && tRVA < pISH[i].VirtualAddress + pISH[i].Misc.VirtualSize)
				return ULONG_PTR((tBase + tRVA) - (pISH[i].VirtualAddress - pISH[i].PointerToRawData));
		}
		return NULL;
	}

	ULONGLONG ImageRvaToVa64(ULONGLONG ullRVA, ULONGLONG ullBase, PIMAGE_NT_HEADERS64 pINH)
	{
		PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
		if (pISH == nullptr)
			return NULL;
		for (WORD i = 0; i < pINH->FileHeader.NumberOfSections; i++) {
			if (ullRVA >= pISH[i].VirtualAddress && ullRVA < pISH[i].VirtualAddress + pISH[i].Misc.VirtualSize)
				return (ullBase + ullRVA) - (pISH[i].VirtualAddress - pISH[i].PointerToRawData);
		}
		return NULL;
	}

//hook engine

	namespace HookEngine {

		PVOID HookIAT(const PCHAR func, const PVOID dst)
		{
			if (!dst)
				return nullptr;
			PBYTE Original_Address = (PBYTE)PETools::GetProcAddress_EAT(func);
			if (!Original_Address)
				return nullptr;
			//now we enumerate through the loaded modules and replace their IAT.
			PPEB peb = PETools::GetPEB();
			PLIST_ENTRY flink = peb->Ldr->InMemoryOrderModuleList.Flink,
				blink = peb->Ldr->InMemoryOrderModuleList.Blink;
			bool bRedirected = false;
			while (flink != blink && flink != nullptr) {
				PLDR_DATA_TABLE_ENTRY_ entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY_>(flink);
				bool bresult = PETools::RedirectIAT(entry->DllBase, Original_Address, dst);
				bool bresult2 = PETools::RedirectDelayedIAT(entry->DllBase, Original_Address, dst);
				bRedirected = bRedirected ? true : (bresult || bresult2);
				flink = flink->Flink;
			}
			return bRedirected ? Original_Address : nullptr;
		}

		PVOID HookEAT(const PCHAR func, const PVOID dst)
		{
			auto parsed = Split(func, '!');
			if (parsed.size() != 2)
				return nullptr;
			PCHAR function_name = parsed[1]->c_str();
			UnicodeString udll = UnicodeString::FromAsciiString(&parsed[0].get()[0]);
			PPEB peb = PETools::GetPEB();
			PLIST_ENTRY flink = peb->Ldr->InMemoryOrderModuleList.Flink,
				blink = peb->Ldr->InMemoryOrderModuleList.Blink;
			while (flink != blink && flink != nullptr) {
				PLDR_DATA_TABLE_ENTRY_ entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY_>(flink);
				if (!wcsicmp(&udll[0], entry->BaseDllName.Buffer))
					return PETools::RedirectEAT(entry->DllBase, function_name, dst);
				flink = flink->Flink;
			}
			return nullptr;
		}

		void UnhookIAT(PVOID hook, PVOID original)
		{
			if (hook == nullptr || original == nullptr)
				return;
			PPEB peb = PETools::GetPEB();
			PLIST_ENTRY flink = peb->Ldr->InMemoryOrderModuleList.Flink,
				blink = peb->Ldr->InMemoryOrderModuleList.Blink;
			while (flink != blink && flink != nullptr) {
				PLDR_DATA_TABLE_ENTRY_ entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY_>(flink);
				PETools::RedirectIAT(entry->DllBase, hook, original);
				PETools::RedirectDelayedIAT(entry->DllBase, hook, original);
				flink = flink->Flink;
			}
		}

		void UnhookEAT(PCHAR func, PVOID original)
		{
			HookEAT(func, original);
		}

		PBYTE HookFunc(PBYTE src, PBYTE dst, DWORD dwLen)
		{
			if (!src || !dst || !dwLen) return nullptr;
#ifdef _WIN64
			if (dwLen < JMPX64_SIZE)
			{
				PBYTE tmp = (PBYTE)VirtualAlloc(NULL, dwLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (tmp == nullptr) return nullptr;
				for (DWORD i = 0; i < dwLen; i++) tmp[i] = src[i];
				DWORD dwOldProtection;
				VirtualProtect(src, JMPX64_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection);
				src[0] = 0x48;
				src[1] = 0xB8;
				*(QWORD*)(&src[2]) = (QWORD)dst;
				*(WORD*)(&src[2 + sizeof(QWORD)]) = (WORD)0xE0FF;
				VirtualProtect(src, JMPX64_SIZE, dwOldProtection, &dwOldProtection);
				return tmp;
			}
			else
			{
				PBYTE tmp = (PBYTE)VirtualAlloc(NULL, dwLen + 17, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (tmp == nullptr)
					return nullptr;
				for (DWORD i = 0; i < dwLen; i++)
					tmp[i] = src[i];
#pragma region trick explained
				/*
					7FFCBF11E7F4 - FF 35 02000000 - push[7FFCBF11E7FC]
					7FFCBF11E7FA - EB 08 - jmp 7FFCBF11E804
					7FFCBF11E7FC - 90 - nop; fill in address here, can store up to 8 bytes; P
					7FFCBF11E7FD - 90 - nop
					7FFCBF11E7FE - 90 - nop
					7FFCBF11E7FF - 90 - nop
					7FFCBF11E800 - 90 - nop
					7FFCBF11E801 - 90 - nop
					7FFCBF11E802 - 90 - nop
					7FFCBF11E803 - 90 - nop
					7FFCBF11E804 - C3 - ret; neat trick eh ? No need to fuck up any registers!
					*/
#pragma endregion
				memcpy(&tmp[dwLen], "\xFF\x35\x02\x00\x00\x00\xEB\x08", 8);
				*(QWORD*)(&tmp[dwLen + 8]) = (QWORD)(src + dwLen);
				*(BYTE*)(&tmp[dwLen + 16]) = 0xC3;
				
				DWORD dwOldProtection;
				VirtualProtect(src, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtection);
				*(WORD*)(&src[0]) = (WORD)0xB848; //mov rax, [8 bytes]   src[0] = 0x48;src[1] = 0xB8;
				*(QWORD*)(&src[2]) = (QWORD)dst;
				*(WORD*)(&src[2 + sizeof(QWORD)]) = (WORD)0xE0FF; //jmp rax
				for (DWORD i = JMPX64_SIZE; i < dwLen; i++)
					src[i] = 0x90;
				VirtualProtect(src, dwLen, dwOldProtection, &dwOldProtection);
				return tmp;
			}
#else
			PBYTE tmp = (PBYTE)VirtualAlloc(NULL, dwLen + JMPX32_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (tmp == nullptr) return nullptr;
			for (DWORD i = 0; i < dwLen; i++) tmp[i] = src[i];
			tmp[dwLen] = 0xE9;
			*(PDWORD)(&tmp[dwLen + 1]) = ((src + dwLen) - &tmp[dwLen]) - JMPX32_SIZE;
			DWORD dwOldProtection;
			VirtualProtect(src, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtection);
			src[0] = 0xE9;
			*(PDWORD)(&src[1]) = (dst - src) - JMPX32_SIZE;
			for (DWORD i = JMPX32_SIZE; i < dwLen; i++) src[i] = 0x90;
			VirtualProtect(src, dwLen, dwOldProtection, &dwOldProtection);
			return tmp;
#endif
		}
		void UnhookFunc(PBYTE src, PBYTE midfunc, DWORD dwLen)
		{
			if (!src || !midfunc || !dwLen)
				return;
			DWORD dwOldProtection;
			VirtualProtect(src, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtection);
			for (DWORD i = 0; i < dwLen; i++)
				src[i] = midfunc[i];
			VirtualProtect(src, dwLen, dwOldProtection, &dwOldProtection);
			VirtualFree(midfunc, NULL, MEM_RELEASE);
		}

		PBYTE HookFunc(PCHAR func, PBYTE dst, DWORD dwLen)
		{
			return HookFunc((PBYTE)PETools::GetProcAddress_EAT(func), dst, dwLen);
		}

		void UnhookFunc(PCHAR hooked, PBYTE midfunc, DWORD dwLen)
		{
			UnhookFunc((PBYTE)PETools::GetProcAddress_EAT(hooked), midfunc, dwLen);
		}
	}
};

PIMAGE_SECTION_HEADER IMAGE_NEW_SECTION(PIMAGE_NT_HEADERS32 pINH)
{
	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
	pISH += pINH->FileHeader.NumberOfSections;
	return pISH;
}

PIMAGE_SECTION_HEADER IMAGE_LAST_SECTION(PIMAGE_NT_HEADERS32 pINH)
{
	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH);
	pISH += pINH->FileHeader.NumberOfSections - 1;
	return pISH;
}

DWORD Align(DWORD dwSize, DWORD dwAlignment)
{
	if (!dwAlignment || dwSize % dwAlignment == 0)
		return dwSize;
	return (DWORD(dwSize / dwAlignment) + 1) * dwAlignment; //let's say size=1000 bytes and it's aligned by 512 bytes, then the aligned size = 1024
}

bool PETools::CreateSection32(const wchar_t* filename, const char* section, const PBYTE pSectionData, const DWORD dwSectionDataSize)
{
	HANDLE hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	bool bSuccess = false;
	DWORD dwFileSize = GetFileSize(hFile, nullptr);
	SmartPtr<BYTE> pMemory(new BYTE[dwFileSize]);
	if (!*pMemory) {
		CloseHandle(hFile);
		return false;
	}
	DWORD dwRead, dwWritten;
	if (!ReadFile(hFile, *pMemory, dwFileSize, &dwRead, nullptr)) {
		CloseHandle(hFile);
		return false;
	}
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)&pMemory[0];
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
		CloseHandle(hFile);
		return false;
	}
	PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((ULONG_PTR)&pMemory[0] + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE) {
		CloseHandle(hFile);
		return false;
	}
	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pINH), pISH_last = IMAGE_LAST_SECTION(pINH), pISH_new = IMAGE_NEW_SECTION(pINH);

	if (pINH->OptionalHeader.SizeOfHeaders - (pIDH->e_lfanew + sizeof(pINH->Signature) + sizeof(IMAGE_FILE_HEADER) + pINH->FileHeader.SizeOfOptionalHeader + (++pINH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))) <= 0)
	{
		CloseHandle(hFile);
		return false;
	}
	//pINH->OptionalHeader.SizeOfHeaders = Align(pINH->OptionalHeader.SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER), pINH->OptionalHeader.FileAlignment);
	ZeroMemory(pISH_new, sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&pISH_new->Name[0], (void*)section, strlen(section) > sizeof(pISH_new->Name) ? sizeof(pISH_new->Name) - 1 : strlen(section));
	pISH_new->Misc.VirtualSize = dwSectionDataSize;
	pISH_new->PointerToRawData = Align(pISH_last->PointerToRawData + pISH_last->SizeOfRawData, pINH->OptionalHeader.FileAlignment); //pISH_last->PointerToRawData + pISH_last->SizeOfRawData - always seems to be aligned for me but I guess it's better to be safe than to be sorry.
	pISH_new->SizeOfRawData = Align(dwSectionDataSize, pINH->OptionalHeader.FileAlignment);
	pISH_new->VirtualAddress = Align(pISH_last->VirtualAddress + pISH_last->Misc.VirtualSize, pINH->OptionalHeader.SectionAlignment);
	pISH_new->Characteristics = IMAGE_SCN_MEM_READ;
	pINH->OptionalHeader.SizeOfImage += pINH->OptionalHeader.SectionAlignment;
	OVERLAPPED ovl = { 0 };
	bSuccess = WriteFile(hFile, *pMemory, dwFileSize, &dwWritten, &ovl) == TRUE;
	ovl.Offset = 0xFFFFFFFF;
	ovl.OffsetHigh = 0xFFFFFFFF;
	bSuccess = WriteFile(hFile, pSectionData, dwSectionDataSize, &dwWritten, &ovl) == TRUE;
	DWORD dwPadding = Align(dwSectionDataSize, pINH->OptionalHeader.FileAlignment) - dwSectionDataSize;
	memset(*pMemory, 0, dwPadding);
	bSuccess = WriteFile(hFile, *pMemory, dwPadding, &dwWritten, &ovl) == TRUE;
	CloseHandle(hFile);
	return bSuccess;
}

bool PETools::CreateSection32(const char* filename, const char* section, const PBYTE pSectionData, const DWORD dwSectionDataSize)
{
	size_t len = strlen(filename);
	UnicodeString wfilename;
	wfilename.reserve(len);
	if (wfilename.c_str() == nullptr)
		return false;
	int result = MultiByteToWideChar(CP_OEMCP, 0, filename, -1, &wfilename[0], (int)len + 1);
	bool bSuccess = false;
	if (result != 0)
		bSuccess = CreateSection32(wfilename.c_str(), section, pSectionData, dwSectionDataSize);
	return bSuccess;
}