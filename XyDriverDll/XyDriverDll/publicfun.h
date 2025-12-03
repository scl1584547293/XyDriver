#pragma once
#include <Windows.h>
#include <string>

//#define WINXP

//安装驱动写入注册表（MiniFilter需要）
BOOL InstallRegistry(LPSTR pDriverName);

//转换盘符
//\Device\harddiskvolume\123.txt =>C:\123.txt
BOOL GetNTLinkName(LPWCH wszNtName, LPSTR wszDesName, ULONG dwDataLength);

//根据进程id获取进程路径
BOOL GetProcessPathByPid(DWORD pid, LPSTR pDesPath, ULONG dwDataLength);

//根据进程id获取父进程id
DWORD GetPPidByPid(DWORD pid);

//根据进程id获取进程名
BOOL GetProcessNameByPid(DWORD pid, LPSTR pDesPath, ULONG dwDataLength);

//根据进程id获取进程创建时间
LONGLONG GetProcessCreateTimeByPid(DWORD pid);

//根据文件名获取文件创建时间
LONGLONG GetFileCreateTimeByFileName(LPWCH fileName);

///格式化字符串
std::string FormatString(const char* fmt, ...);

std::string wstring2string(const std::wstring& str, const std::string& locale);
