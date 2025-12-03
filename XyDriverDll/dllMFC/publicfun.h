#pragma once
#include "stdafx.h"
#include <string>

void Utf8ToWchar(LPCCH inBuff, std::wstring& outWString);
void WcharToUtf8(LPCWCH pwStr, std::string& outString);

std::string wstring2string(const std::wstring& str, const std::string& locale);

///¸ñÊ½»¯×Ö·û´®
std::string FormatString(const char* fmt, ...);

LPWCH GetErrorString(ULONG error);