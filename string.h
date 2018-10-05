#pragma once
//to-do: add ability to limit maximim size, default = 65535 characters long.
//to-do: make UnicodeString memory safe.
//note: AsciiString is memory safe(it can operate on buffers that don't have \0 at the end or contain invalid characters).
//however, UnicodeString is only semi-safe(some of its features are safe to use with raw buffers).
class AsciiString {
public:
	AsciiString() :AsciiString("") {};
	AsciiString(const char* string);
	AsciiString(const char* string, size_t len);
	AsciiString(const AsciiString& string);
	AsciiString(AsciiString&& string);
	~AsciiString();
	void operator=(const AsciiString& string);
	void operator=(const char* string);
	char& operator[](size_t index);
	char& operator[](int index) { return this->operator[](static_cast<size_t>(index)); };
	AsciiString operator+(const AsciiString& str) const;
	AsciiString operator+(const char* str) const;
	AsciiString& operator+=(const AsciiString& str);
	AsciiString& operator+=(const char* str);
	AsciiString& operator+=(const char str);
	bool operator==(const AsciiString& other) const;
	bool operator==(const char* other) const;
	bool operator!=(const AsciiString& other) const { return !this->operator==(other); };
	bool operator!=(const char* other) const { return !this->operator==(other); };
	size_t indexOf(const PCHAR string, size_t offset = 0) const;
	size_t indexOf(const AsciiString& string, size_t offset = 0) const { return this->indexOf(string.c_str(), offset); };
	size_t indexOf(char c, size_t offset = 0) const;
	bool isEmpty() const { return len == NULL; };
	void fill(char c);
	AsciiString substr(size_t offset, size_t size = npos) const;
	static AsciiString FromUnicodeString(const wchar_t* str);
	static AsciiString From(const char* str, size_t len);
	void expand(); //Expands environment-variable strings and replaces them with the values defined for the current user.
	const PCHAR c_str() const { return buffer; };
	size_t length() const { return len; }; //size in characters
	size_t size() const { return len * sizeof(char); }; //size in bytes
	void clear() { if (buffer && !bExternalBuffer) delete[] buffer; len = NULL; buffer = nullptr; };
	void setexternalbuffer(PCHAR buf, size_t buflen) { this->clear(); this->buffer = buf; this->len = buflen; this->bExternalBuffer = buf != nullptr; };
	void reserve(size_t len) { this->clear(); this->len = len; this->buffer = new char[len + 1]; this->buffer[len] = NULL; };
	void truncate() { *this = AsciiString(buffer, strlen(buffer)); };
	static const size_t npos = -1;
	operator const char*() const { return buffer; };
	operator char*() { return buffer; };
private:
	bool bExternalBuffer;
	size_t len;
	PCHAR buffer;
};

//--------------------------------------
//unicode version

class UnicodeString {
public:
	UnicodeString() :UnicodeString(L"") {};
	UnicodeString(const wchar_t* string);
	UnicodeString(const wchar_t* string, size_t len);
	UnicodeString(const UnicodeString& string);
	UnicodeString(UnicodeString&& string);
	~UnicodeString();
	void operator=(const UnicodeString& string);
	void operator=(const wchar_t* string);
	wchar_t& operator[](size_t index);
	wchar_t& operator[](int index) { return this->operator[](static_cast<size_t>(index)); };
	UnicodeString operator+(const UnicodeString& str) const;
	UnicodeString operator+(const wchar_t* str) const;
	UnicodeString& operator+=(const UnicodeString& str);
	UnicodeString& operator+=(const wchar_t* str);
	bool operator==(const UnicodeString& other) const;
	bool operator==(const wchar_t* other) const;
	bool operator!=(const UnicodeString& other) const { return !this->operator==(other); };
	bool operator!=(const wchar_t* other) const { return !this->operator==(other); };
	size_t indexOf(PCWCHAR string, size_t offset = 0) const;
	size_t indexOf(const UnicodeString& string, size_t offset = 0) const { return this->indexOf(string.c_str(), offset); };
	size_t indexOf(wchar_t c, size_t offset = 0) const;
	bool isEmpty() const { return len == NULL; };
	void fill(wchar_t c);
	UnicodeString substr(size_t offset, size_t size = npos) const;
	static UnicodeString FromAsciiString(const char* str);
	static UnicodeString From(wchar_t* str, size_t len);
	void expand(); //Expands environment-variable strings and replaces them with the values defined for the current user.
	PCWCHAR c_str() const { return buffer; };
	size_t length() const { return len; }; //size in wchar_tacters
	size_t size() const { return len * sizeof(wchar_t); }; //size in bytes
	void clear() { if (buffer) delete[] buffer; len = NULL; buffer = nullptr; };
	void reserve(size_t len) { this->clear(); this->len = len; this->buffer = new wchar_t[len + 1]; this->buffer[len] = NULL; };
	void truncate() { *this = UnicodeString(buffer, wcslen(buffer)); };
	operator const wchar_t*() const { return buffer; };
	operator wchar_t*() { return buffer; };
	static const size_t npos = -1;
private:
	size_t len;
	PWCHAR buffer;
};