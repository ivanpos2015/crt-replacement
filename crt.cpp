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

#pragma function(strlen)
#pragma function(wcslen)
#pragma function(memcmp)
#pragma function(memcpy)
#pragma function(strcat)
#pragma function(wcscat)
#pragma function(strcmp)
#pragma function(wcscmp)
#pragma function(strcpy)
#pragma function(wcscpy)


/*
//win32_crt_math.cpp takes care of this
#ifndef _WIN64
__declspec(naked) void __cdecl _aullshr(void)
{
	__asm {
		;
		; Handle shifts of 64 bits or more(if shifting 64 bits or more, the result
		; depends only on the high order bit of edx).
		;
		cmp     cl, 64
		jae     short RETZERO

		;
		; Handle shifts of between 0 and 31 bits
		;
		cmp     cl, 32
		jae     short MORE32
		shrd    eax, edx, cl
		shr     edx, cl
		ret

		;
		; Handle shifts of between 32 and 63 bits
		;
	MORE32:
		mov     eax, edx
		xor     edx, edx
		and     cl, 31
		shr     eax, cl
		ret

		;
		; return 0 in edx : eax
		;
	RETZERO:
		xor     eax, eax
		xor     edx, edx
		ret
	}
}

__declspec(naked) void __cdecl _allshl(void)
{
	__asm {
			cmp     cl, 64
			jae     short RETZERO
			cmp     cl, 32
			jae     short MORE32
			shld    edx, eax, cl
			shl     eax, cl
			ret
	MORE32:
			mov     edx, eax
			xor     eax, eax
			and     cl, 31
			shl     edx, cl
			ret
	RETZERO:
			xor     eax, eax
			xor     edx, edx
			ret
	}
}
#endif
*/

void* operator new[](size_t size)
{
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL)
		return nullptr;//::VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
	return HeapAlloc(hHeap, 0/*HEAP_ZERO_MEMORY*/, size);
}

void* operator new(size_t size)
{
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL)
		return nullptr;//::VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE);
	return HeapAlloc(hHeap, 0/*HEAP_ZERO_MEMORY*/, size);
}

void operator delete(void* p, size_t sz)
{
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL)
		return;//::VirtualFree(p, 0, MEM_RELEASE);
	HeapFree(hHeap, 0, p);
}

void operator delete[](void* p)
{
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL)
		return;//::VirtualFree(p, 0, MEM_RELEASE);
	HeapFree(hHeap, 0, p);
}

void operator delete[](void * p, size_t sz)
{
	HANDLE hHeap = GetProcessHeap();
	if (hHeap == NULL)
		return;//::VirtualFree(p, 0, MEM_RELEASE);
	HeapFree(hHeap, 0, p);
}

size_t strlen(const char* str)
{
	size_t len = NULL;
	while (*str++) //while str[len] != NULL
		len++;
	return len;
}

size_t strlen_s(char* str, size_t max)
{
	if (str == nullptr)
		return NULL;
	size_t i = 0;
	while (str[i] != NULL && i + 1 < max)
		i++;
	return i;
}

size_t wcslen_s(wchar_t* str, size_t max)
{
	if (str == nullptr)
		return NULL;
	size_t i = 0;
	while (str[i] != NULL && i + 1 < max) //have to leave space for null terminator that's why I do i + 1
		i++;
	return i;
}

size_t wcslen(const wchar_t* str)
{
	size_t len = NULL;
	while (*str++)
		len++;
	return len;
}

size_t strlen_s(const char* str)
{
	if (!str)
		return NULL;
	return strlen(str);
}

size_t wcslen_s(const wchar_t* str)
{
	if (!str)
		return NULL;
	return wcslen(str);
}

char toupper(char c)
{
	if (c >= 97 && c <= 122)
		return (c - 0x20);
	else
		return c;
}

wchar_t towupper(wchar_t c)
{
	if (c >= 97 && c <= 122)
		return (c - 0x20);
	else
		return c;
}

char * strcpy(char * destination, const char * source)
{
	for (size_t i = 0; i <= strlen(source); i++)
		destination[i] = source[i];
	return destination;
}

wchar_t * wcscpy(wchar_t* destination, const wchar_t* source)
{
	for (size_t i = 0; i <= wcslen(source); i++)
		destination[i] = source[i];
	return destination;
}

errno_t strcpy_s(char *strDestination, size_t numberOfElements, const char *strSource)
{
	if (!strDestination || !strSource) {
		memset(strDestination, 0, numberOfElements);
		return EINVAL;
	}
	if (numberOfElements <= strlen(strSource)) {
		memset(strDestination, 0, numberOfElements);
		return ERANGE;
	}
	strcpy(strDestination, strSource);
	return 0;
}

errno_t wcscpy_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource)
{
	if (!strDestination || !strSource) {
		memset(strDestination, 0, numberOfElements * sizeof(wchar_t));
		return EINVAL;
	}
	if (numberOfElements <= wcslen(strSource)) {
		memset(strDestination, 0, numberOfElements * sizeof(wchar_t));
		return ERANGE;
	}
	wcscpy(strDestination, strSource);
	return 0;
}

wchar_t* wcscat(wchar_t* destination, const wchar_t* source)
{
	for (size_t i = wcslen(destination), j = 0; j <= wcslen(source); j++, i++)
		destination[i] = source[j];
	return destination;
}

char* strcat(char* destination, const char* source)
{
	for (size_t i = strlen(destination), j = 0; j <= strlen(source); j++, i++)
		destination[i] = source[j];
	return destination;
}

errno_t strcat_s(char* strDestination, size_t numberOfElements, const char* strSource)
{
	if (!strDestination || !strSource)
		return EINVAL;
	if (numberOfElements <= strlen(strDestination) + strlen(strSource))
		return ERANGE;
	strcat(strDestination, strSource);
	return NULL;
}

errno_t wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource)
{
	if (!strDestination || !strSource)
		return EINVAL;
	if (numberOfElements <= wcslen(strDestination) + wcslen(strSource))
		return ERANGE;
	wcscat(strDestination, strSource);
	return NULL;
}

char* _strstr(char * const str1, const char * const str2)
{
	size_t len1 = strlen_s(str1), len2 = strlen_s(str2);
	if (len1 < len2 || !len1 || !len2)
		return nullptr;

	for (size_t i = 0; i <= len1 - len2; i++) {
		bool bMatch = true;
		for (size_t j = 0; j < len2; j++)
			if (str1[i + j] != str2[j]) {
				bMatch = false;
				break;
			}
		if (bMatch)
			return &str1[i];
	}
	return nullptr;
}

char* strstr_s(char * const str1, size_t wStr1Len, const char * const str2)
{
	size_t len1 = wStr1Len, len2 = strlen_s(str2);
	if (len1 < len2 || !len1 || !len2)
		return nullptr;

	for (size_t i = 0; i <= len1 - len2; i++) {
		bool bMatch = true;
		for (size_t j = 0; j < len2; j++)
			if (str1[i + j] != str2[j]) {
				bMatch = false;
				break;
			}
		if (bMatch)
			return &str1[i];
	}
	return nullptr;
}


wchar_t* _wcsstr(wchar_t *str1, const wchar_t * str2)
{
	size_t len1 = wcslen_s(str1), len2 = wcslen_s(str2);
	if (len1 < len2 || !len1 || !len2)
		return nullptr;

	for (size_t i = 0; i <= len1 - len2; i++) {
		bool bMatch = true;
		for (size_t j = 0; j < len2; j++)
			if (str1[i + j] != str2[j]) {
				bMatch = false;
				break;
			}
		if (bMatch)
			return &str1[i];
	}
	return nullptr;
}


wchar_t* wcsstr_s(wchar_t *str1, size_t wStr1Len, const wchar_t * str2)
{
	size_t len1 = wStr1Len, len2 = wcslen_s(str2);
	if (len1 < len2 || !len1 || !len2)
		return nullptr;

	for (size_t i = 0; i <= len1 - len2; i++) {
		bool bMatch = true;
		for (size_t j = 0; j < len2; j++)
			if (str1[i + j] != str2[j]) {
				bMatch = false;
				break;
			}
		if (bMatch)
			return &str1[i];
	}
	return nullptr;
}

/*
//another way to do this, taken from vcruntime.cpp
char* strstr(char * const str1, const char * const str2)
{
	if (!str1 || !str2)
		return nullptr;
	PCHAR cp = str1;
	while (*cp)
	{
		PCHAR s1 = cp, s2 = (PCHAR)str2;
		while (*s1 && *s2 && !(*s1 - *s2))
			s1++, s2++;

		if (!*s2)
			return cp;
		cp++;
	}
	return nullptr;
}*/

char* stristr(char * const str1, const char * const str2)
{
	size_t len1 = strlen_s(str1), len2 = strlen_s(str2);
	if (len1 < len2 || !len1 || !len2)
		return nullptr;

	for (size_t i = 0; i <= len1 - len2; i++) {
		bool bMatch = true;
		for (size_t j = 0; j < len2; j++)
			if (toupper(str1[i + j]) != toupper(str2[j])) {
				bMatch = false;
				break;
			}
		if (bMatch)
			return &str1[i];
	}
	return nullptr;
}

wchar_t* wcsistr(wchar_t *str1, const wchar_t * str2)
{
	size_t len1 = wcslen(str1), len2 = wcslen(str2);
	if (len1 < len2 || !len1 || !len2)
		return nullptr;

	for (size_t i = 0; i <= len1 - len2; i++) {
		bool bMatch = true;
		for (size_t j = 0; j < len2; j++)
			if (towupper(str1[i + j]) != towupper(str2[j])) {
				bMatch = false;
				break;
			}
		if (bMatch)
			return &str1[i];
	}
	return nullptr;
}

//memcmp("test", "tesz", 4); = -1, memcmp("test", "tesa", 4); = 1
int memcmp(const void * ptr1, const void * ptr2, size_t num)
{
	for (size_t i = 0; i < num; i++)
		if (PBYTE(ptr1)[i] != PBYTE(ptr2)[i])
			return PBYTE(ptr1)[i] > PBYTE(ptr2)[i] ? 1 : -1;
	return 0;
}

int strcmp(const char * str1, const char * str2)
{
	size_t a = strlen(str1), b = strlen(str2);
	if (a <= b)
		return memcmp(str1, str2, ++a);
	else
		return memcmp(str1, str2, ++b);
}

int __cdecl wcscmp(const wchar_t * wcs1, const wchar_t * wcs2)
{
	size_t a = wcslen(wcs1), b = wcslen(wcs2);
	if (a <= b)
		return memcmp(wcs1, wcs2, ++a * sizeof(wchar_t));
	else
		return memcmp(wcs1, wcs2, ++b * sizeof(wchar_t));
}

int stricmp(const char * str1, const char * str2)
{
	size_t len1 = strlen(str1), len2 = strlen(str2);
	if (len1 != len2)
		return -1;
	for (size_t i = 0; i < len1; i++)
		if (toupper(str1[i]) != toupper(str2[i]))
			return 1;
	return 0;
}

int wcsicmp(const wchar_t * wcs1, const wchar_t * wcs2)
{
	size_t len1 = wcslen(wcs1), len2 = wcslen(wcs2);
	if (len1 != len2)
		return -1;
	for (size_t i = 0; i < len1; i++)
		if (towupper(wcs1[i]) != towupper(wcs2[i]))
			return 1;
	return 0;
}

void* memcpy(void* _Dst, const void *_Src, size_t _Size)
{
	if (!_Src || !_Dst || !_Size)
		return nullptr;
	size_t t = 0;
	for (PBYTE Dst = (PBYTE)_Dst, Src = (PBYTE)_Src; t < _Size; t++)
		Dst[t] = Src[t];
	return _Dst;
}

errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src, size_t count)
{
	if (!dest || !src || !count || !numberOfElements)
		return EINVAL;
	if (numberOfElements < count) {
		ZeroMemory(dest, numberOfElements);
		return ERANGE;
	}
	memcpy(dest, src, count);
	return 0;
}

#define TO_HEX(i) (i <= 9 ? L'0' + i : L'A' - 10 + i)

template <typename T>
void TtoHA(T v, PCHAR s) //T to hexadecimal ascii string
{
	T And = 0xF;
	for (int j = 1; j < sizeof(v) * 2; j++)
		And <<= 4;
	int i = 0;
	for (int BitsShr = (sizeof(v) * 8) - 4; BitsShr >= NULL; BitsShr -= 4, And >>= 4, i++)
		s[i] = (char)TO_HEX(((v & And) >> BitsShr));
	s[i] = NULL;
}

template <typename T>
void TtoHW(T v, PWCHAR s) //To to hexadecimal unicode string
{
	T And = 0xF;
	for (int j = 1; j < sizeof(v) * 2; j++)
		And <<= 4;
	int i = 0;
	for (int BitsShr = (sizeof(v) * 8) - 4; BitsShr >= NULL; BitsShr -= 4, And >>= 4, i++)
		s[i] = (wchar_t)TO_HEX(((v & And) >> BitsShr));
	s[i] = NULL;
}

template <typename T>
DWORD CalculateTtoHSSize(T asd) //calculate the string size(in characters) through the integral type.
{
	return sizeof(T) * 2;
}

template <typename T>
int CaculateTtoSSize(T value)
{
	int size = (value == NULL) ? 1 : NULL;
	if (value < 0) {
		//1>crt.cpp(360): warning C4146: unary minus operator applied to unsigned type, result still unsigned
#pragma warning(disable:4146)
		value = -value;
#pragma warning(default:4146)
		size++;
	}
	while (value) {
		value /= 10;
		size++;
	}
	return size;
}

template <typename T>
void TtoA(T v, PCHAR s) //integral type to ascii string.
{
	if (v == NULL) {
		s[0] = '0';
		return;
	}
	int size = CaculateTtoSSize(v);
	if (v < 0) {
#pragma warning(disable:4146)
		v = -v;
#pragma warning(default:4146)
		s[0] = '-';
	}
	for (int i = size - 1; i >= 0 && v; i--, v /= 10)
		s[i] = v % 10 + '0';
}

template <typename T>
void TtoW(T v, PWCHAR s) //integral type to unicode string.
{
	if (v == NULL) {
		s[0] = L'0';
		return;
	}
	int size = CaculateTtoSSize(v);
	if (v < 0) {
#pragma warning(disable:4146)
		v = -v;
#pragma warning(default:4146)
		s[0] = L'-';
	}
	for (int i = size - 1; i >= 0 && v; i--, v /= 10)
		s[i] = v % 10 + L'0';
}

size_t sprintf(char* buf, const char* format, ...)
{
	va_list argptr;
	va_start(argptr, format);
	size_t written = 0;
	while (*format != NULL) {
		switch (*format) {
		case '%':
		{
			switch (format[1]) {
			case '%':
				*buf++ = '%';
				written++;
				break;
			case 'c':
			case 'C':
				*buf++ = va_arg(argptr, char);
				written++;
				break;
			case 'X':
			case 'x':
				TtoHA(va_arg(argptr, DWORD), buf);
				buf += CalculateTtoHSSize<DWORD>(1);
				written += CalculateTtoHSSize(DWORD(1));
				break;
			case 'D':
			case 'd':
			{
				DWORD i = va_arg(argptr, DWORD);
				TtoA<DWORD>(i, buf);
				buf += CaculateTtoSSize(i);
				written += CaculateTtoSSize(i);
			}
			break;
			case 'I':
			case 'i':
			{
				int i = va_arg(argptr, int);
				TtoA<int>(i, buf);
				buf += CaculateTtoSSize(i);
				written += CaculateTtoSSize(i);
			}
			break;
			case 'S':
			case 's':
			{
				char* s = va_arg(argptr, char*);
				strcpy(buf, s);
				//MessageBoxA(0, buf, buf, 64);
				buf += strlen(s);
				written += strlen(s);
			}
			break;
			}
			format += 2;
		}
		break;
		default:
			*buf++ = *format++;
			written++;
		}
	}
	*buf = NULL;
	va_end(argptr);
	return written;
}

size_t swprintf(wchar_t* buf, const wchar_t* format, ...)
{
	va_list argptr;
	va_start(argptr, format);
	size_t written = 0;
	while (*format != NULL) {
		switch (*format) {
		case L'%':
		{
			switch (format[1]) {
			case L'%':
				*buf++ = L'%';
				written++;
				break;
			case L'c':
			case L'C':
				*buf++ = va_arg(argptr, wchar_t);
				written++;
				break;
			case L'X':
			case L'x':
				TtoHW(va_arg(argptr, DWORD), buf);
				buf += CalculateTtoHSSize<DWORD>(1);
				written += CalculateTtoHSSize(DWORD(1));
				break;
			case L'D':
			case L'd':
			{
				DWORD i = va_arg(argptr, DWORD);
				TtoW<DWORD>(i, buf);
				buf += CaculateTtoSSize(i);
				written += CaculateTtoSSize(i);
			}
			break;
			case L'I':
			case L'i':
			{
				int i = va_arg(argptr, int);
				TtoW<int>(i, buf);
				buf += CaculateTtoSSize(i);
				written += CaculateTtoSSize(i);
			}
			break;
			case L'S':
			case L's':
			{
				wchar_t* s = va_arg(argptr, wchar_t*);
				wcscpy(buf, s);
				buf += wcslen(s);
				written += wcslen(s);
			}
			break;
			}
			format += 2;
		}
		break;
		default:
			*buf++ = *format++;
			written++;
		}
	}
	*buf = NULL;
	va_end(argptr);
	return written;
}

int sprintf_s(char* buf, size_t sizeOfBuffer, const char* format, va_list argptr)
{
	size_t fpos = NULL, bpos = NULL; //format / buffer position.
	while (format[fpos]) {
		switch (format[fpos++]) {
		case '%':
		{
			switch (format[fpos++]) {
			case '%':
				if (bpos + 1 == sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				buf[bpos++] = '%';
				break;
			case 'X':
			case 'x':
			{
				DWORD size = CalculateTtoHSSize<DWORD>(1);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				TtoHA(va_arg(argptr, DWORD), &buf[bpos]);
				bpos += size;
			}
			break;
			case 'I':
			case 'i':
			{
				int value = va_arg(argptr, int);
				DWORD size = CaculateTtoSSize(value);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				TtoA(value, &buf[bpos]);
				bpos += size;
			}
			break;
			case 'D':
			case 'd':
			{
				DWORD value = va_arg(argptr, DWORD);
				DWORD size = CaculateTtoSSize(value);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				TtoA(value, &buf[bpos]);
				bpos += size;
			}
			break;
			case 'S':
			case 's':
			{
				PCHAR value = va_arg(argptr, char*);
				if (value == nullptr) {
					buf[0] = NULL;
					return EINVAL;
				}
				size_t size = strlen_s(value);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				strcpy(&buf[bpos], value);
				bpos += size;
			}
			break;
			case 'C':
			case 'c':
			{
				char c = va_arg(argptr, char);
				if (bpos + 1 == sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				buf[bpos++] = c;
			}
			break;
			case '1':
			{
				switch (format[fpos++]) {
				case 'X':
				case 'x':
				{
					DWORD size = CalculateTtoHSSize<BYTE>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHA(va_arg(argptr, BYTE), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			case '2':
			{
				switch (format[fpos++]) {
				case 'X':
				case 'x':
				{
					DWORD size = CalculateTtoHSSize<WORD>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHA(va_arg(argptr, WORD), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			case '4':
			{
				switch (format[fpos++]) {
				case 'X':
				case 'x':
				{
					DWORD size = CalculateTtoHSSize<DWORD>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHA(va_arg(argptr, DWORD), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			case '8':
			{
				switch (format[fpos++]) {
				case 'X':
				case 'x':
				{
					DWORD size = CalculateTtoHSSize<ULONGLONG>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHA(va_arg(argptr, ULONGLONG), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			default:
				//an invalid parameter was specified.
				buf[0] = NULL;
				return EINVAL;
			}
		}
		break;
		default:
			if (bpos + 1 == sizeOfBuffer) {
				//out of space!
				buf[0] = NULL;
				return ERANGE;
			}
			buf[bpos++] = format[fpos - 1];
			break;
		}
	}
	buf[bpos] = NULL;
	return NULL;
}


int swprintf_s(wchar_t* buf, size_t sizeOfBuffer, const wchar_t* format, va_list argptr)
{
	size_t fpos = NULL, bpos = NULL; //format / buffer position.
	while (format[fpos]) {
		switch (format[fpos++]) {
		case L'%':
		{
			switch (format[fpos++]) {
			case L'%':
				if (bpos + 1 == sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				buf[bpos++] = L'%';
				break;
			case L'X':
			case L'x':
			{
				DWORD size = CalculateTtoHSSize<DWORD>(1);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				TtoHW(va_arg(argptr, DWORD), &buf[bpos]);
				bpos += size;
			}
			break;
			case L'I':
			case L'i':
			{
				int value = va_arg(argptr, int);
				DWORD size = CaculateTtoSSize(value);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				TtoW(value, &buf[bpos]);
				bpos += size;
			}
			break;
			case L'D':
			case L'd':
			{
				DWORD value = va_arg(argptr, DWORD);
				DWORD size = CaculateTtoSSize(value);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				TtoW(value, &buf[bpos]);
				bpos += size;
			}
			break;
			case L'S':
			case L's':
			{
				PWCHAR value = va_arg(argptr, wchar_t*);
				if (value == nullptr) {
					buf[0] = NULL;
					return EINVAL;
				}
				size_t size = wcslen(value);
				if (bpos + size >= sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				wcscpy(&buf[bpos], value);
				bpos += size;
			}
			break;
			case L'C':
			case L'c':
			{
				wchar_t c = va_arg(argptr, wchar_t);
				if (bpos + 1 == sizeOfBuffer) {
					//out of space!
					buf[0] = NULL;
					return ERANGE;
				}
				buf[bpos++] = c;
			}
			break;
			case L'1':
			{
				switch (format[fpos++]) {
				case L'X':
				case L'x':
				{
					DWORD size = CalculateTtoHSSize<BYTE>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHW(va_arg(argptr, BYTE), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			case L'2':
			{
				switch (format[fpos++]) {
				case L'X':
				case L'x':
				{
					DWORD size = CalculateTtoHSSize<WORD>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHW(va_arg(argptr, WORD), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			case L'4':
			{
				switch (format[fpos++]) {
				case L'X':
				case L'x':
				{
					DWORD size = CalculateTtoHSSize<DWORD>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHW(va_arg(argptr, DWORD), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			case L'8':
			{
				switch (format[fpos++]) {
				case L'X':
				case L'x':
				{
					DWORD size = CalculateTtoHSSize<ULONGLONG>(1);
					if (bpos + size >= sizeOfBuffer) {
						//out of space!
						buf[0] = NULL;
						return ERANGE;
					}
					TtoHW(va_arg(argptr, ULONGLONG), &buf[bpos]);
					bpos += size;
				}
				break;
				default:
					//an invalid parameter was specified.
					buf[0] = NULL;
					return EINVAL;
				}
			}
			break;
			default:
				//an invalid parameter was specified.
				buf[0] = NULL;
				return EINVAL;
			}
		}
		break;
		default:
			if (bpos + 1 == sizeOfBuffer) {
				//out of space!
				buf[0] = NULL;
				return ERANGE;
			}
			buf[bpos++] = format[fpos - 1];
			break;
		}
	}
	buf[bpos] = NULL;
	return NULL;
}

int sprintf_s(char* buf, size_t sizeOfBuffer, const char* format, ...)
{
	if (!buf || !format || !sizeOfBuffer)
		return EINVAL;
	va_list argptr;
	va_start(argptr, format);
	int r = sprintf_s(buf, sizeOfBuffer, format, argptr);
	va_end(argptr);
	return r;
}

int swprintf_s(wchar_t* buf, size_t sizeOfBuffer, const wchar_t* format, ...)
{
	if (!buf || !format || !sizeOfBuffer)
		return EINVAL;
	va_list argptr;
	va_start(argptr, format);
	int r = swprintf_s(buf, sizeOfBuffer, format, argptr);
	va_end(argptr);
	return r;
}

#pragma function(memset)
void * __cdecl memset(void *pTarget, int value, size_t cbTarget) {
	if (pTarget && cbTarget) {
		PBYTE p = static_cast<PBYTE>(pTarget);
		BYTE val = (BYTE)value;
		while (cbTarget-- > 0)
			*p++ = val;
	}
	return pTarget;
}

extern "C" int _cdecl _purecall(void)
{
	return 0;
}