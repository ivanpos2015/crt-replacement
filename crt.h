#pragma once
/**********************************
** Last update: 4/10/2017 06:57 PM **
** Native replacement for MSVCRT **
**********************************/

//std::move for when you don't want to use stl.
namespace std {
	template <typename T>
	T&& move(T&& arg)
	{
		return static_cast<T&&>(arg);
	};

	template <typename T>
	T&& move(T& arg)
	{
		return static_cast<T&&>(arg);
	};
};

#ifndef ERANGE
#define ERANGE          34 
#endif
#ifndef EINVAL
#define EINVAL          22
#endif
//typedef int errno_t;

size_t strlen(const char* _Str);
size_t wcslen(const wchar_t* _Str);
size_t strlen_s(const char* str, size_t max);
size_t wcslen_s(const wchar_t* str, size_t max);
//strlen_s/wcslen_s checks the str pointer to see if it's null, the normal strlen doesn't(like in the original crt).
size_t strlen_s(const char* str);
size_t wcslen_s(const wchar_t* str);
//end of note

char toupper(char c);
wchar_t towupper(wchar_t c);

char * strcpy(char * destination, const char * source);
wchar_t * wcscpy(wchar_t* destination, const wchar_t* source);

errno_t strcpy_s(char *strDestination, size_t numberOfElements, const char *strSource);
errno_t wcscpy_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
wchar_t* wcscat(wchar_t* destination, const wchar_t* source);
char* strcat(char* destination, const char* source);
errno_t strcat_s(char* strDestination, size_t numberOfElements, const char* strSource);
errno_t wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
extern "C++" {
char* _strstr(char * const str1, const char * const str2);
char* strstr_s(char * const str1, size_t wStr1Len, const char * const str2);
wchar_t* _wcsstr(wchar_t *str1, const wchar_t * str2);
wchar_t* wcsstr_s(wchar_t *str1, size_t wStr1Len, const wchar_t * str2);
inline const wchar_t* _wcsstr(const wchar_t *str1, const wchar_t * str2) { return _wcsstr(const_cast<wchar_t*>(str1), str2); };
};
char* stristr(char * const str1, const char * const str2);
wchar_t* wcsistr(wchar_t *str1, const wchar_t * str2);
int memcmp(const void * ptr1, const void * ptr2, size_t num);
int strcmp(const char * str1, const char * str2);
int wcscmp(const wchar_t * wcs1, const wchar_t * wcs2);
int stricmp(const char * str1, const char * str2);
int wcsicmp(const wchar_t * wcs1, const wchar_t * wcs2);
void* memcpy(void* _Dst, const void *_Src, size_t _Size);
errno_t memcpy_s(void *dest, size_t _Size, const void *src, size_t count);
size_t sprintf(char* buf, const char* format, ...);
size_t swprintf(wchar_t* buf, const wchar_t* format, ...);
int sprintf_s(char* buf, size_t sizeOfBuffer, const char* format, va_list args);
int swprintf_s(wchar_t* buf, size_t sizeOfBuffer, const wchar_t* format, va_list args);
int sprintf_s(char* buf, size_t sizeOfBuffer, const char* format, ...);
int swprintf_s(wchar_t* buf, size_t sizeOfBuffer, const wchar_t* format, ...);

template <size_t size>
errno_t inline strcat_s(char(&strDestination)[size], const char* strSource)
{
	return strcat_s(strDestination, size, strSource);
}

template <size_t size>
errno_t inline wcscat_s(wchar_t(&strDestination)[size], const wchar_t *strSource)
{
	return wcscat_s(strDestination, size, strSource);
}

template <size_t size, typename _DstType>
errno_t inline memcpy_s(_DstType(&dest)[size], const void* src, size_t count)
{
	return memcpy_s(dest, size * sizeof(_DstType), src, count);
}


template <size_t size>
int inline sprintf_s(char(&buf)[size], const char* format, ...)
{
	va_list args;
	va_start(args, format);
	int i = sprintf_s(buf, size, format, args);
	va_end(args);
	return i;
}
template <size_t size>
int inline swprintf_s(wchar_t(&buf)[size], const wchar_t* format, ...)
{
	va_list args;
	va_start(args, format);
	int i = swprintf_s(buf, size, format, args);
	va_end(args);
	return i;
}


template <typename T>
T inline StringToNumerical(char* str)
{
	T tmp(0), base(1);
	if (strlen_s(str) == NULL)
		return tmp;
	for (int x = static_cast<int>(strlen(str)) - 1; x > -1; x--) {
		if (str[x] < '0' || str[x] > '9')
			break;
		tmp += (BYTE(str[x]) - '0') * base;
		base *= 10;
	}
#pragma warning(disable:4146)
	if (str[0] == '-')
		tmp = -tmp;
#pragma warning(default:4146)
	return tmp;
}

//slight modification required for C++14
/*
void operator delete(void* p);
void* operator new(size_t t);
*/
//C++14 required small update -  http://en.cppreference.com/w/cpp/memory/new/operator_delete
void operator delete(void* p, size_t sz);
void* operator new(size_t size);
void operator delete[](void* p);
void operator delete[](void* p, size_t sz);
void* operator new[](size_t size);

extern "C" void * __cdecl memset(void *, int, size_t);
#pragma intrinsic(memset)

#ifndef _WIN64
extern "C" void __cdecl _aullshr(void);
extern "C" void __cdecl _allshl(void);
#endif
/*
http://www.drdobbs.com/avoiding-the-visual-c-runtime-library/184416623
To link projects containing one or more classes with pure virtual members without the CRT Library,
you must supply your own definition of this function.
If you are feeling confident (that it will never be called), then this can be as simple as:
extern "C" int _cdecl _purecall(void)
{
return 0;
}
note:- not sure what he meant by it, since when I call the virtual function in my subclass it appears to work perfectly...
*/
extern "C" int _cdecl _purecall(void);

template <typename T>
class SmartPtr {
public:
	SmartPtr() { t = nullptr; len = NULL; };
	SmartPtr(SmartPtr&& other) { t = nullptr; this->operator=(std::move(other)); };
	SmartPtr(T* data) { t = data; len = NULL; };
	SmartPtr(T* data, size_t len) { t = data; this->len = len; };
	~SmartPtr() { this->release(); };
	void release() { if (t) delete t; t = nullptr; len = NULL; }; //note: never use this->~SmartPtr(), this will destruct the instantiated this pointer SmartPtr object (lol).
	void assign(T* pNewData) { this->release(); t = pNewData; };
	T* operator*() { return t; };
	T* operator->() { return t; };
	T* ptr(){return operator*();};
	void operator=(SmartPtr&& other) { this->assign(other.t); other.t = nullptr; this->len = other.len; other.len = NULL; };
	void operator=(T* other) { this->assign(other); };
	T& operator[](size_t index) { return t[index]; }; //ASSERT(index < datalen)
private:
	size_t len;
	T* t;
};