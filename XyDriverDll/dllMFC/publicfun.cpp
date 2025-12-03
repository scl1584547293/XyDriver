#include "stdafx.h"
#include "publicfun.h"
#include "..\XyDriverDll\hss.h"

void Utf8ToWchar(LPCCH inBuff, std::wstring& outWString)
{
	if (inBuff == NULL || inBuff[0] == '\0')
		return;
	//获取缓冲区大小，并申请空间，缓冲区大小按字符计算  
	int len = MultiByteToWideChar(CP_UTF8, 0, inBuff, (int)strlen(inBuff), NULL, 0);
	LPWCH buffer = new WCHAR[len + 1];
	RtlZeroMemory(buffer, len + 1);
	//多字节编码转换成宽字节编码  
	MultiByteToWideChar(CP_UTF8, 0, inBuff, (int)strlen(inBuff), buffer, len);
	//删除缓冲区并返回值  
	outWString = L"";
	outWString.append(buffer);

	delete[] buffer;
	buffer = NULL;
	return;
}

void WcharToUtf8(LPCWCH pwStr,std::string& outString)
{
	if (pwStr == NULL)
	{
		return;
	}

	int len = WideCharToMultiByte(CP_UTF8, 0, pwStr, -1, NULL, 0, NULL, NULL);
	if (len <= 0)
	{
		return;
	}
	LPCH pStr = new CHAR[len+1];
	RtlZeroMemory(pStr, len + 1);
	WideCharToMultiByte(CP_UTF8, 0, pwStr, -1, pStr, len, NULL, NULL);

	outString = "";
	outString.append(pStr);

	delete[] pStr;
	pStr = NULL;

	return;
}


#include <locale>
#include <codecvt>
std::string wstring2string(const std::wstring& str, const std::string& locale)
{
	if (str.empty())
		return "";
	typedef std::codecvt_byname<wchar_t, char, std::mbstate_t> F;
	static std::wstring_convert<F> strCnv(new F(locale));

	std::string outStr = "";
	try 
	{
		outStr = strCnv.to_bytes(str);
	}
	catch(std::range_error ){
		return "";
	}

	return outStr;
}

//格式化字符串
std::string FormatString(const char* fmt, ...)
{
	std::string res;
	char buf[10240] = { 0 };
	va_list argptr;
	va_start(argptr, fmt);
	int issize = vsnprintf(buf, sizeof(buf), fmt, argptr);
	if (issize >= sizeof(buf))
	{
		va_end(argptr);
		return "lenth is error!";

		res.resize(issize);
		char* tp = (char*)res.data();
		va_start(argptr, fmt);
		vsnprintf(tp, issize + 1, fmt, argptr);
	}
	else
	{
		res = buf;
	}
	va_end(argptr);
	return res;
}

LPWCH GetErrorString(ULONG error)
{
	switch (error)
	{
	case ERROR_DRIVER_FILE_NOT_EXIST:
		return L"驱动文件不存在";
	case ERROR_DRIVER_NOT_LOADED:
		return L"驱动未加载";
	case ERROR_DRIVER_INSTALL:
		return L"驱动未加载";
	case ERROR_DRIVER_UNINSTALL:
		return L"驱动卸载失败";
	case ERROR_DRIVER_START:
		return L"驱动启动失败";
	case ERROR_DRIVER_STOP:
		return L"驱动停止失败";
	case ERROR_DRIVER_OPEN:
		return L"打开驱动设备或驱动文件失败";
	case ERROR_DRIVER_SEND:
		return L"发送通信指令失败";
	case ERROR_DRIVER_READ:
		return L"获取数据失败";
	case ERROR_INVALID_VALUE:
		return L"无效的参数";
	case ERROR_MEMORY:
		return L"内存错误";
	case ERROR_WIN_OPENSCMANAGER:
		return L"打开资源管理器失败";
	case ERROR_WIN_OPENSERVICE:
		return L"打开服务失败";
	case ERROR_WIN_CREATESERVICE:
		return L"创建服务失败";
	case ERROR_WIN_WRITEREGISTRY:
		return L"写入注册表失败";
	case ERROR_WIN_DELETESERVICE:
		return L"删除服务失败";
	default:
		return L"未知的错误";
	}

	return L"";
}

