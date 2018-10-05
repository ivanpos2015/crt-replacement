#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifdef NO_CRT
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
#define _SYS_GUID_OPERATORS_
#define __STRALIGN_H_
#define _INC_STRING
#define __STDC__ 1
#endif
#endif
#include <Windows.h>
#ifdef NO_CRT
#include "utils/crt.h"
#endif
#include "string.h"
#include "pipe.h"
#include <sddl.h>
#include <aclapi.h>

/*
note: I should really consider making an 
asynchronous pipe i/o similar to my 
asynchronous socket i/o model.
*/

//https://support.microsoft.com/en-us/help/813414/how-to-create-an-anonymous-pipe-that-gives-access-to-everyone
//https://support.microsoft.com/en-us/kb/813414
//http://stackoverflow.com/questions/9589141/low-integrity-to-medium-high-integrity-pipe-security-descriptor
void InitializePipeSA(SECURITY_ATTRIBUTES& sa) //InitializeAnonymousSA
{
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	/*if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
		TEXT("S:(ML;;NW;;;LW)D:(A;;GRGW;;;WD)(A;;GRGW;;;S-1-15-2-1)"), //S-1-15-2-1 = ALL_APP_PACKAGES(UWP)
		SDDL_REVISION_1,
		&sa.lpSecurityDescriptor, NULL)) {
		MessageBoxA(0, "err", "", 0);
	}
	*/
	if (!InitializeSecurityDescriptor(&sa, SECURITY_DESCRIPTOR_REVISION))
		return;
	EXPLICIT_ACCESS ea[2];
	PSID pEveryoneSID = NULL, pAppPackagesSID = NULL, pLowSID = NULL; //EVERYONE / ALL APPLICATION PACKAGES
	PACL pDacl = NULL, pSacl = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
		goto Cleanup;
	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE; //FILE_ALL_ACCESS
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;
	//https://msdn.microsoft.com/en-us/library/cc980032.aspx
	/*
	//maybe use IsValidSid?
	if (!ConvertStringSidToSid(L"S-1-15-2-1", &pAppPackagesSID))
				goto Cleanup;
	ea[1].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE; //FILE_ALL_ACCESS
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pAppPackagesSID;
	*/
	//this code is used instead of the above as it's a lot simpler.
	ea[1].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE; //FILE_ALL_ACCESS
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[1].Trustee.ptstrName = L"ALL APPLICATION PACKAGES";
	if (SetEntriesInAcl(2, ea, NULL, &pDacl) != ERROR_SUCCESS)
		goto Cleanup;

	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
		SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (pSD == NULL)
		goto Cleanup;
	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
		goto Cleanup;
	if (!SetSecurityDescriptorDacl(pSD, TRUE, pDacl, FALSE))
		goto Cleanup;
	//build sacl to allow low integrity processes to access the pipe.

	DWORD dwACLSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetSidLengthRequired(1);
	pSacl = (PACL)LocalAlloc(LPTR, dwACLSize);
	InitializeAcl(pSacl, dwACLSize, ACL_REVISION);
	AllocateAndInitializeSid(&sia, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 
		0, 0, 0, &pLowSID); //pLowSID = low integrity sid
	
			//https://github.com/huku-/injectdso/blob/master/injectdll/pipe.c
			//http://stackoverflow.com/a/38414023

	if (!AddMandatoryAce(pSacl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, pLowSID))
		goto Cleanup;
	if (!SetSecurityDescriptorSacl(pSD, TRUE, pSacl, FALSE))
		goto Cleanup;
	
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;
	//note: the dacl/sacl we allocated will be used in the security descriptor so we must also make sure they aren't freed.
	pSD = nullptr; pDacl = pSacl = nullptr;
	
	Cleanup:
	if (pDacl)
		LocalFree(pDacl);
	if (pSacl)
		LocalFree(pSacl);
	if (pEveryoneSID)
		FreeSid(pEveryoneSID);
	if (pAppPackagesSID)
		FreeSid(pAppPackagesSID);
	if (pLowSID)
		FreeSid(pLowSID);
	if (pSD)
		LocalFree(pSD);
}

void FreeSA(PSECURITY_ATTRIBUTES pSec)
{
	/*
	if (pSec != nullptr && pSec->lpSecurityDescriptor != nullptr)
		delete[] pSec->lpSecurityDescriptor;
		*/
	if (pSec && pSec->lpSecurityDescriptor) {
		auto descriptor = reinterpret_cast<SECURITY_DESCRIPTOR*>(pSec->lpSecurityDescriptor);
		pSec->lpSecurityDescriptor = nullptr;
		LocalFree(descriptor->Dacl);
		LocalFree(descriptor->Sacl);
		LocalFree(descriptor);
	}
}

namespace Pipe {

	Client::Client(HANDLE hPipe)
	{
		this->hPipe = hPipe;
		this->bConnected = hPipe != INVALID_HANDLE_VALUE;
	}

	Client::Client(sPipeServerHandle && handle)
	{
		this->s_ovl = std::move(handle.ovl);
		this->hPipe = handle.pipe;
		handle.pipe = INVALID_HANDLE_VALUE;
		this->bConnected = hPipe != INVALID_HANDLE_VALUE;
	}
	
	bool Client::Connect(AsciiString pipe)
	{
		if (hPipe != INVALID_HANDLE_VALUE) {
			::CloseHandle(hPipe);
			hPipe = INVALID_HANDLE_VALUE;
			bConnected = false;
		}
		AsciiString name = AsciiString("\\\\.\\pipe\\") + pipe;
		hPipe = CreateFileA(name.c_str(), GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, NULL, NULL);	
		//bBusy = (GetLastError() == ERROR_PIPE_BUSY); //ERROR_PIPE_NOT_CONNECTED
		return (bConnected = hPipe != INVALID_HANDLE_VALUE);
	}

	bool Client::read(LPVOID pBuffer, DWORD len)
	{
		DWORD dwRead;
		BOOL bRead = ::ReadFile(hPipe, pBuffer, len, &dwRead, nullptr);			
		bConnected = bRead == TRUE;
		return bRead && dwRead == len;
	}

	bool Client::write(LPCVOID pBuffer, DWORD len)
	{
		DWORD dwWritten;
		BOOL bWritten = ::WriteFile(hPipe, pBuffer, len, &dwWritten, nullptr);
		bConnected = bWritten == TRUE;
		return bWritten && dwWritten == len;
	}

	bool Client::wait(AsciiString pipe, DWORD dwTimeOut)
	{
		AsciiString name = AsciiString("\\\\.\\pipe\\") + pipe;
		return (WaitNamedPipeA(name.c_str(), dwTimeOut) == TRUE);
	}

	Client::~Client()
	{
		if (hPipe != INVALID_HANDLE_VALUE) {
			FlushFileBuffers(hPipe);
			DisconnectNamedPipe(hPipe);
			CloseHandle(hPipe);
		}
	}

	//---------------------------------------

	Server::Server(AsciiString name)
	{
		server = "\\\\.\\pipe\\";
		server += name;
		InitializePipeSA(sec);
		hPipe = this->listen();
	}

	sPipeServerHandle Server::accept()
	{
		HANDLE hPipeTmp = listen();
		SmartPtr<OVERLAPPED> ovl(new OVERLAPPED);
		if (hPipe == INVALID_HANDLE_VALUE || ovl.ptr() == nullptr) {
			if (hPipe) {
				::CancelIo(hPipe);
				::CloseHandle(hPipe);
			}
			hPipe = hPipeTmp;
			return{ nullptr, INVALID_HANDLE_VALUE };
		}
		
		ZeroMemory(ovl.ptr(), sizeof(OVERLAPPED));
		ovl->hEvent = ::CreateEvent(nullptr, TRUE, FALSE, nullptr);
		ConnectNamedPipe(hPipe, ovl.ptr());
		int gle = GetLastError();
		if (gle != ERROR_IO_PENDING && gle != ERROR_PIPE_CONNECTED)
		{
			CancelIo(hPipe);
			if (ovl->hEvent)
				CloseHandle(ovl->hEvent);
			CloseHandle(hPipe);
			hPipe = hPipeTmp;
			return{ nullptr, INVALID_HANDLE_VALUE };
		}
		else {
			if (gle == ERROR_IO_PENDING) {
				if (WaitForSingleObject(ovl->hEvent, 1000) != WAIT_OBJECT_0) {
					CancelIo(hPipe);
					CloseHandle(ovl->hEvent);
					CloseHandle(hPipe);
					hPipe = hPipeTmp;
					return{ nullptr, INVALID_HANDLE_VALUE };
				}
				DWORD dwIgnore;
				if (!GetOverlappedResult(hPipe, ovl.ptr(), &dwIgnore, FALSE)) {
					CancelIo(hPipe);
					CloseHandle(ovl->hEvent);
					CloseHandle(hPipe);
					hPipe = hPipeTmp;
					return{ nullptr, INVALID_HANDLE_VALUE };
				}
				CloseHandle(ovl->hEvent);
				ovl->hEvent = NULL;
			}
			HANDLE hTmp = hPipe;
			hPipe = hPipeTmp;
			return{ std::move(ovl), hTmp };
		}
	}

	bool Server::isAvailable()
	{
		return hPipe != INVALID_HANDLE_VALUE;
	}

	HANDLE Server::listen()
	{
		return CreateNamedPipeA(server.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 512, 512, NULL, &sec);
	}

	Server::~Server()
	{
		if (hPipe != INVALID_HANDLE_VALUE)
			CloseHandle(hPipe);
		FreeSA(&sec);
	}

};