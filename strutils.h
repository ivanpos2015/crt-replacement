#pragma once

List<AsciiString> inline Split(const AsciiString& str, char delimiter)
{
	List<AsciiString> tmp;
	size_t start = 0;
	for (size_t i = 0; i < str.length(); i++)
	{
		if (str[i] == delimiter) {
			tmp.push(AsciiString::From(&str[start], i - start));
			start = i + 1;
		}
		else if (i + 1 == str.length() && start != 0) {
			tmp.push(AsciiString::From(&str[start], (i + 1) - start));
		}
	}
	return tmp;
}

List<AsciiString> inline Split(PCHAR str, char delimiter) {
	AsciiString s;
	s.setexternalbuffer(str, strlen(str));
	return Split(s, delimiter);
};

List<AsciiString> inline Split(const AsciiString& str, const AsciiString& delim)
{
	List<AsciiString> tmp;
	size_t index = 0;
	while (index < str.length()) {
		size_t next = str.indexOf(delim, index);
		if (next == AsciiString::npos) {
			if (index < str.length())
				tmp.push(str.substr(index));
			break;
		}
		tmp.push(str.substr(index, next - index));
		index = next + delim.length();
	}
	return tmp;
}

AsciiString inline extract_between(const AsciiString& s, const AsciiString& start, const AsciiString& end)
{
	auto _start = s.indexOf(start);
	if (_start == AsciiString::npos)
		return "";
	_start += start.length();
	auto _end = s.indexOf(end, _start);
	if (_end == AsciiString::npos)
		return "";
	return s.substr(_start, _end - _start);
}

UnicodeString inline extract_between(const UnicodeString& s, const UnicodeString& start, const UnicodeString& end)
{
	auto _start = s.indexOf(start);
	if (_start == UnicodeString::npos)
		return L"";
	_start += start.length();
	auto _end = s.indexOf(end, _start);
	if (_end == UnicodeString::npos)
		return L"";
	return s.substr(_start, _end - _start);
}

//similar: http://stackoverflow.com/a/39052987
template <typename T>
T HexStringToNumerical(const AsciiString& hex_string, bool* pbSuccess = nullptr)
{
	if (pbSuccess)
		*pbSuccess = true;
	T result = 0;
	const AsciiString& hexmap = "0123456789ABCDEF";
	int offset = hex_string.indexOf("0x") == 0 ? 2 : 0;

	for (int i = (int)hex_string.length(); i > offset; i--) {
		auto j = hexmap.indexOf(toupper(hex_string[i - 1]));
		if (j == AsciiString::npos) { //hex string is invalid.
			if (pbSuccess)
				*pbSuccess = false;
			return NULL;
		}
		//you can use either: |= || +=
		result |= j << ((hex_string.length() - i) << 2);
	}
	return result;
}