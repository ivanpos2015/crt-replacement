#pragma once
struct sSectionData {
	PBYTE lpMemory;
	DWORD dwSize;
};

namespace PETools {
	/****************************************
	https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
	*/
	PTEB inline _cdecl GetTEB()
	{
#ifdef _WIN64
		return reinterpret_cast<PTEB>(__readgsqword(0x30));
#else
		__asm {
			mov eax, FS:[0x18]
		}
#endif
	}
	PPEB _cdecl GetPEB();
	/****************************************/
	bool WriteProtectedMemory(PVOID dest, PVOID src, ULONG ulSize);
	PVOID ScanMemory(ULONG_PTR start_address, SIZE_T size, const PBYTE sig, const char* sigmask);
	PVOID ScanMemoryRegions(ULONG_PTR start_address, DWORD dwApproximateSize, const PBYTE sig, const char* sigmask, DWORD dwMemoryProtection = PAGE_EXECUTE_READ);
	PVOID ScanModuleMemorySection(HMODULE hModule, char* section, const PBYTE sig, const char* sigmask);
	DWORD x64CalculateLEADistance(ULONGLONG opcode_address, DWORD dwOpcodeLen, ULONGLONG target_address);
	PVOID FindReferenceToPushedString(ULONG_PTR start_address, DWORD dwSize, char* string);
	PVOID GetStartOfFunc(PVOID func);
	sSectionData GetSectionData(const char* section, ULONG_PTR const module);
	DWORD GetModuleSize(ULONG_PTR module);
	bool CreateSection32(const wchar_t* filename, const char* section, const PBYTE pSectionData, DWORD dwSectionDataSize);
	bool CreateSection32(const char* filename, const char* section, const PBYTE pSectionData, DWORD dwSectionDataSize);
	bool IsPtrInModule(ULONG_PTR module, const void* ptr);
	bool Is64Bit(HANDLE hProcess);
	bool Is64Bit(DWORD dwProcess);
	bool Is32Bit(HANDLE hProcess);
	bool Is32Bit(DWORD dwProcess);
	bool IsPrivileged();
	bool Is64BitOS();
	PVOID GetImageHandle(PCWCHAR dll);
	DWORD GetPIDFromThrdHnd(HANDLE hThread);
	PBYTE GetProcAddress_IAT(const PVOID pModule, const PCHAR dll, const PCHAR func);
	PVOID GetProcAddress_EAT(const PCHAR func);
	PVOID GetProcAddress_EAT(PVOID pModule, const PCHAR func);
	bool RedirectIAT(PVOID pModule, const PVOID pOriginalFunc, const PVOID pNewFunc);
	bool RedirectDelayedIAT(LPVOID pModule, const PVOID pOriginalFunc, const PVOID pNewFunc); //delay loaded dlls
	PVOID RedirectEAT(PVOID module, const PCHAR function, const PVOID replacement);
	ULONG_PTR ImageRvaToVa(ULONG_PTR tRVA, ULONG_PTR tBase, PIMAGE_NT_HEADERS pINH); //Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns the virtual address of the corresponding byte in the file.
	ULONGLONG ImageRvaToVa64(ULONGLONG ullRVA, ULONGLONG ullBase, PIMAGE_NT_HEADERS64 pINH);

	namespace HookEngine {
		PVOID HookIAT(const PCHAR func, const PVOID dst); //func format: dll.dll!functionname
		PVOID HookEAT(const PCHAR func, const PVOID dst); //func format: dll.dll!functionname, not recommended for x64 as there often is an integer overflow.
		void UnhookIAT(const PVOID hook, const PVOID original);
		void UnhookEAT(const PCHAR func, const PVOID original);
		PBYTE HookFunc(PBYTE src, PBYTE dst, DWORD dwLen);
		PBYTE HookFunc(const PCHAR func, PBYTE dst, DWORD dwLen);
		void UnhookFunc(PBYTE hooked, PBYTE midfunc, DWORD dwLen);
		void UnhookFunc(const PCHAR hooked, PBYTE midfunc, DWORD dwLen);
	};
};

/**********************************/
typedef struct
{
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;

	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};

	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};

	_ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_, *PLDR_DATA_TABLE_ENTRY_;

typedef struct _CLIENT_ID
{
	HANDLE	UniqueProcess;
	HANDLE	UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef LONG KPRIORITY;

typedef enum _full_THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,				// KERNEL_USER_TIMES
	ThreadPriority,
	ThreadBasePriority,			// BASE_PRIORITY_INFORMATION
	ThreadAffinityMask,			// AFFINITY_MASK
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	_ThreadIsIoPending,
	ThreadHideFromDebugger,
	MaxThreadInfoClass
}full_THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;