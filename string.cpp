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
#else
#include <iostream>
#include <stdio.h>
#include <memory>
#include <string.h>
//#include <wchar.h>
#endif
#include "string.h"

AsciiString::AsciiString(const char* string)
{
	bExternalBuffer = false;
#ifdef NO_CRT
	len = strlen_s(string);
#else
	len = strlen(string);
#endif
	buffer = new char[len + 1];
	strcpy_s(buffer, len + 1,string);
}

AsciiString::AsciiString(const char* string, size_t len)
{
	bExternalBuffer = false;
	this->len = len;
	buffer = new char[len + 1];
	if (buffer) {
		buffer[len] = NULL;
	}
	memcpy_s(buffer, this->len, string, len);
}

AsciiString::AsciiString(const AsciiString& string)
{
	bExternalBuffer = false;
	len = string.len;
	buffer = new char[len + 1];
	if (buffer) buffer[len] = NULL;
	memcpy_s(buffer, len, string.buffer, string.len); //strcpy_s(buffer, len + 1, string.buffer);
}

AsciiString::AsciiString(AsciiString&& string)
{
	buffer = string.buffer;
	len = string.len;
	bExternalBuffer = string.bExternalBuffer;
	string.buffer = nullptr;
	string.bExternalBuffer = false;
	string.len = NULL;
}

AsciiString::~AsciiString()
{
	this->clear();
}

void AsciiString::operator=(const AsciiString& string)
{
	this->clear();
	len = string.len;
	buffer = new char[len + 1];
	//strcpy_s(buffer, len + 1, string.buffer);
	if (buffer) buffer[len] = NULL;
	memcpy_s(buffer, len + 1, string.buffer, string.len);
}

void AsciiString::operator=(const char* string)
{
	this->clear();
	len = strlen(string);
	buffer = new char[len + 1];
	strcpy_s(buffer, len + 1, string);
}

char& AsciiString::operator[](size_t index)
{
	return buffer[index];
}

AsciiString AsciiString::operator+(const AsciiString& str) const
{
	size_t lentmp = this->len + str.len;
	AsciiString string;
	string.reserve(lentmp);
	//strcpy(string.buffer, this->buffer);
	//strcpy(&string.buffer[this->len], str.buffer);
	if (string.buffer) {
		memcpy(string.buffer, this->buffer, this->len);
		memcpy(&string.buffer[this->len], str.buffer, str.len);
	}
	return string;
}

AsciiString AsciiString::operator+(const char* str) const
{
	size_t lentmp = this->len + strlen(str);
	AsciiString tmp;
	tmp.reserve(lentmp);
	strcpy(tmp.buffer, this->buffer);
	strcat(tmp.buffer, str);//strcpy(&tmp.buffer[this->len], str);
	return tmp;
}

AsciiString& AsciiString::operator+=(const AsciiString& str)
{
	AsciiString tmp;
	tmp.reserve(this->len + str.len);
	//strcpy(string.buffer, this->buffer);
	//strcpy(&string.buffer[this->len], str.buffer);
	memcpy(tmp.buffer, this->buffer, this->len);
	memcpy(&tmp.buffer[this->len], str.buffer, str.len);
	this->clear();
	*this = std::move(tmp);
	return *this;
}

AsciiString& AsciiString::operator+=(const char* str)
{
	size_t lentmp = this->len + strlen(str);
	AsciiString string;
	string.reserve(lentmp);
	strcpy(string.buffer, this->buffer);
	strcat(string.buffer, str);
	*this = std::move(string);
	return *this;
}

AsciiString & AsciiString::operator+=(const char c)
{
	char str[2] = { c, 0 };
	return this->operator+=(str);
}

bool AsciiString::operator==(const AsciiString& other) const
{
	if (other.buffer == nullptr || this->buffer == nullptr)
		return false;
	if (other.len != this->len)
		return false;
	return 0 == memcmp(other.buffer, this->buffer, len); //strcmp(other.buffer, this->buffer);
}

bool AsciiString::operator==(const char* other) const
{
	if (other == nullptr || this->buffer == nullptr)
		return false;
	if (strlen(other) != this->len)
		return false;
	return 0 == memcmp(other, this->buffer, len); //strcmp(other.buffer, this->buffer);
	//return 0 == strcmp(this->buffer, other);
}
size_t AsciiString::indexOf(char c, size_t offset) const
{
	char str[2] = { c, NULL };
	return this->indexOf(str, offset);
}
/*
size_t AsciiString::indexOf(PCHAR string)
{
	if (PCHAR s = _strstr(this->buffer, string))
		return size_t(s - this->buffer);
	else
		return npos;
}
*/
size_t AsciiString::indexOf(const PCHAR string, size_t offset) const
{
	if (offset >= len)
		return npos;
#ifdef NO_CRT
	if (PCHAR s = strstr_s(&this->buffer[offset], this->len - offset, string)) {
#else
	//to-do: probably should use std::search instead
	if (PCHAR s = strstr(&this->buffer[offset], string)) { //warning buffer must not contain \0, otherwise it might not find it.
#endif
		return size_t(s - this->buffer);
	}
	else
		return npos;
}

void AsciiString::fill(char c)
{
	for (size_t i = 0; i < len; i++)
		buffer[i] = c;
}

AsciiString AsciiString::substr(size_t offset, size_t size) const
{
	if (offset >= len || (size != npos && offset + size > len)) //simple boundary check
		return "";
	/*
	ABC
	len = 3
	pos(position/offset) = 1
	3 - 1 = 2
	will get B, C
	*/
	if (size == npos)
		return AsciiString(&buffer[offset], len - offset);
	return AsciiString(&buffer[offset], size);
}

AsciiString AsciiString::FromUnicodeString(const wchar_t * str)
{
	size_t len = wcslen(str);
#ifdef NO_CRT
	SmartPtr<char> tmp(new char[len + 1]);
	for (size_t i = 0; i <= len; i++)
		tmp[i] = static_cast<char>(str[i]);
	return AsciiString(&tmp[0]);
#else
	std::unique_ptr<char> tmp(new char[len + 1]);
	for (size_t i = 0; i <= len; i++)
		tmp.get()[i] = static_cast<char>(str[i]);
	return AsciiString(&tmp.get()[0]);
#endif
}

AsciiString AsciiString::From(const char* str, size_t len)
{
#ifdef NO_CRT
	SmartPtr<char> tmp(new char[len + 1]);
	tmp[len] = NULL;
	for (size_t i = 0; i < len; i++)
		tmp[i] = static_cast<char>(str[i]);
	return AsciiString(&tmp[0]);
#else
	std::unique_ptr<char> tmp(new char[len + 1]);
	tmp.get()[len] = NULL;
	for (size_t i = 0; i < len; i++)
		tmp.get()[i] = static_cast<char>(str[i]);
	return AsciiString(&tmp.get()[0]);
#endif
}

void AsciiString::expand()
{
	//To specify the environment block for a particular user or the system, use the ExpandEnvironmentStringsForUser function.
	DWORD dwSize = 32208;
#ifdef NO_CRT
	SmartPtr<char> str(new char[dwSize]);
	ExpandEnvironmentStringsA(this->c_str(), &str[0], dwSize);
	(*this) = *str;
#else
	std::unique_ptr<char> str(new char[dwSize]);
	ExpandEnvironmentStringsA(this->c_str(), &str.get()[0], dwSize);
	(*this) = str.get();
#endif
}

//-----------------------------------------------------------------------
//unicode version

UnicodeString::UnicodeString(const wchar_t* string)
{
	len = wcslen(string);
	buffer = new wchar_t[len + 1];
	wcscpy_s(buffer, len + 1, string);
}

UnicodeString::UnicodeString(const wchar_t* string, size_t len)
{
	this->len = len;
	buffer = new wchar_t[len + 1];
	if (buffer == nullptr) {
		len = NULL;
#ifndef NO_CRT
		throw std::exception("Out of memory");
#endif
		return;
	}
	buffer[len] = NULL;
	//wcscpy_s(buffer, len + 1, string);
	memcpy_s(buffer, len * sizeof(wchar_t), string, len * sizeof(wchar_t));
}

UnicodeString::UnicodeString(const UnicodeString& string)
{
	len = string.len;
	buffer = new wchar_t[len + 1];
	if (!buffer) {
		len = NULL;
#ifndef NO_CRT
		//note: when ctor throws, dtor will not be called, according to: http://stackoverflow.com/a/32323458
		throw std::exception("Out of memory"); //can't think of any other reason why it would fail.
#endif
		return;
	}
	buffer[len] = NULL;
	memcpy_s(buffer, len * sizeof(wchar_t), string.buffer, string.len * sizeof(wchar_t));
	//wcscpy_s(buffer, len + 1, string.buffer);
}

UnicodeString::UnicodeString(UnicodeString&& string)
{
	buffer = string.buffer;
	len = string.len;
	string.buffer = nullptr;
	string.len = NULL;
}

UnicodeString::~UnicodeString()
{
	this->clear();
}

void UnicodeString::operator=(const UnicodeString& string)
{
	this->clear();
	len = string.len;
	buffer = new wchar_t[len + 1];
	if (!buffer) {
		len = NULL;
#ifndef NO_CRT
		throw std::exception("Out of memory");
#endif
		return;
	}
	buffer[len] = NULL;
	memcpy_s(buffer, len * sizeof(wchar_t), string.buffer, string.len * sizeof(wchar_t));
	//wcscpy_s(buffer, len + 1, string.buffer);
}

void UnicodeString::operator=(const wchar_t* string)
{
	this->clear();
	len = wcslen(string);
	buffer = new wchar_t[len + 1];
	wcscpy_s(buffer, len + 1, string);
}

wchar_t& UnicodeString::operator[](size_t index)
{
	return buffer[index];
}

UnicodeString UnicodeString::operator+(const UnicodeString& str) const
{
	size_t lentmp = this->len + str.len;
	UnicodeString string;
	string.reserve(lentmp);
	wcscpy(string.buffer, this->buffer);
	wcscpy(&string.buffer[this->len], str.buffer);
	return string;
}

UnicodeString UnicodeString::operator+(const wchar_t* str) const
{
	size_t lentmp = this->len + wcslen(str);
	UnicodeString string;
	string.reserve(lentmp);
	wcscpy(string.buffer, this->buffer);
	wcscpy(&string.buffer[this->len], str);
	return string;
}

UnicodeString& UnicodeString::operator+=(const UnicodeString& str)
{
	size_t lentmp = this->len + str.len;
	UnicodeString string;
	string.reserve(lentmp);
	wcscpy(string.buffer, this->buffer);
	wcscpy(&string.buffer[this->len], str.buffer);
	this->clear();
	this->len = string.len;
	this->buffer = string.buffer;
	string.buffer = nullptr; //string.len = NULL doesn't need to be set as it'll be destroyed.
	return *this;
}

UnicodeString& UnicodeString::operator+=(const wchar_t* str)
{
	size_t lentmp = this->len + wcslen(str);
	UnicodeString string;
	string.reserve(lentmp);
	wcscpy(string.buffer, this->buffer);
	wcscpy(&string.buffer[this->len], str);
	this->clear();
	this->len = string.len;
	this->buffer = string.buffer;
	string.buffer = nullptr;
	return *this;
}

bool UnicodeString::operator==(const UnicodeString& other) const
{
	if (other.buffer == nullptr || this->buffer == nullptr)
		return false;
	return 0 == wcscmp(other.buffer, this->buffer);
}

bool UnicodeString::operator==(const wchar_t* other) const
{
	if (other == nullptr || this->buffer == nullptr)
		return false;
	return 0 == wcscmp(other, this->buffer);
}

size_t UnicodeString::indexOf(PCWCHAR string, size_t offset) const
{
	if (offset >= len)
		return npos;
#ifdef NO_CRT
	if (auto s = wcsstr_s(&this->buffer[offset], this->len - offset, string)) {
#else
	//note: probably should use std::search instead
	if (auto s = wcsstr(&this->buffer[offset], string)) {
#endif
		return size_t(s - this->buffer);
	}
	else
		return npos;
}

size_t UnicodeString::indexOf(wchar_t c, size_t offset) const
{
	wchar_t str[2] = { c, NULL };
	return this->indexOf(str, offset);
}


void UnicodeString::fill(wchar_t c)
{
	for (size_t i = 0; i < len; i++)
		buffer[i] = c;
}

UnicodeString UnicodeString::substr(size_t offset, size_t size) const
{
	if (offset >= len || (size != npos && offset + size > len)) //simple boundary check
		return L"";
	if (size == npos)
		return UnicodeString(&buffer[offset], len - offset);
	return UnicodeString(&buffer[offset], size);
}

UnicodeString UnicodeString::FromAsciiString(const char* str)
{
	UnicodeString tmp;
	tmp.reserve(strlen(str));
	MultiByteToWideChar(CP_ACP, MB_COMPOSITE/*MB_ERR_INVALID_CHARS*/, str, -1, &tmp[0], (int)tmp.size() + (1 * sizeof(wchar_t)));
	return tmp;
}

UnicodeString UnicodeString::From(wchar_t* str, size_t len)
{
#ifdef NO_CRT
	SmartPtr<wchar_t> tmp(new wchar_t[len + 1]);
	tmp[len] = NULL;
	for (size_t i = 0; i < len; i++)
		tmp[i] = static_cast<wchar_t>(str[i]);
	return UnicodeString(&tmp[0]);
#else
	std::unique_ptr<wchar_t> tmp(new wchar_t[len + 1]);
	tmp.get()[len] = NULL;
	for (size_t i = 0; i < len; i++)
		tmp.get()[i] = static_cast<wchar_t>(str[i]);
	return UnicodeString(&tmp.get()[0]);
#endif
}

void UnicodeString::expand()
{
	DWORD dwSize = 32208;
#ifdef NO_CRT
	SmartPtr<wchar_t> str(new wchar_t[dwSize]);
	ExpandEnvironmentStringsW(this->c_str(), &str[0], dwSize);
	(*this) = *str;
#else
	std::unique_ptr<wchar_t> str(new wchar_t[dwSize]);
	ExpandEnvironmentStringsW(this->c_str(), &str.get()[0], dwSize);
	(*this) = str.get();
#endif
}