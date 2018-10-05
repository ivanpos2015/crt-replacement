#ifndef EXT_64
#define EXT_64
/*
pretty much just c+p'd from:
http://scrammed.blogspot.com/2014/10/code-obfunscation-mixing-32-and-64-bit.html
I have put comments on line 0x00401019, 0x0040101d etc. to indicate the 64bit instructions, they are simply pushing the correct values on the stack in order to be able to switch back to 32bit mode. In order, the following values are pushed:
the stack segment selector
the stack pointer
the eflags register
the code segment selector (0x0023 is the standard usermode code segment)
the instruction pointer (in this case, it is 0x00401080)
The iretq will restore all these values, starting the execution in 32bit mode from address 0x0023:0x00401080, but bear in mind that the 64bit code also changes the state of the registers in 32bit mode. So it's up to you to preserve the registers that need to be saved across switches.

EA 00000000 3300      - jmp 0033:00000000 - BYTE heavensgate[7] = { 0xEA, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00 };
*/
static BYTE _heavensgate[7] = { 0xEA, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00 };

class WindowsSystemCallTableIndexGrabber {
public:
	WindowsSystemCallTableIndexGrabber();
	DWORD GetIndex(PCHAR pFunc);
	bool Usable() { return bUsable; };
private:
	bool bUsable;
	DWORD dwSize;
	SmartPtr<BYTE> ntdll_buffer;
	PIMAGE_NT_HEADERS64 pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;
};

class Nt64{
public:
	Nt64();
	~Nt64();
	BOOL WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, PBYTE pBuf, DWORD dwSize, PULONGLONG ullBytesWritten);
	BOOL ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, PBYTE pBuf, DWORD dwSize, PULONGLONG ullBytesWritten);
	ULONG VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, PMEMORY_BASIC_INFORMATION64 lpBuffer, ULONG ulLength);
	ULONGLONG VirtualAllocEx(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD flAllocationType, DWORD flProtect);
	BOOL VirtualFreeEx(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD dwFreeType);
	BOOL VirtualProtectEx(HANDLE hProcess, DWORD64 lpAddress, DWORD64 dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
	HANDLE CreateRemoteThread(HANDLE hProcess, DWORD64 lpStartAddress, DWORD64 lpParameter, bool bCreateSuspended);

	bool Usable(){ return bUsable; };
private:
	PBYTE heavensgate;
	static bool bInitialized;
	static PBYTE x64_code_wpm, x64_code_rpm, x64_code_qvm, x64_code_avm, x64_code_fvm, x64_code_pvm, x64_code_crt;
	bool bUsable;
};

#endif