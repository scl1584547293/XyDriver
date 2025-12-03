#include "publicfun.h"
#include <Shlwapi.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <locale>
#include <codecvt>

//安装驱动写入注册表（MiniFilter需要）
BOOL InstallRegistry(LPSTR pDriverName)
{
	BOOL success = FALSE;
	CHAR subKeyPath[MAX_PATH] = { 0 };
	snprintf(subKeyPath,sizeof(subKeyPath),"SYSTEM\\CurrentControlSet\\Services\\%s\\Instances", pDriverName);
	HKEY instancesKey = NULL;
	HKEY altitudeAndFlagsKey = NULL;
	HKEY configKey = NULL;

	if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subKeyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &instancesKey, NULL) != ERROR_SUCCESS)
	{
		goto FINAL;
	}

	CHAR defaultInstances[MAX_PATH] = { 0 };
	snprintf(defaultInstances,sizeof(defaultInstances), "%s Instance", pDriverName);

	DWORD defaltInstancesSize = ((DWORD)strlen(defaultInstances) + 1) * sizeof(CHAR);
	if (RegSetValueExA(instancesKey, "DefaultInstance", 0, REG_SZ, (const BYTE*)defaultInstances, defaltInstancesSize) != ERROR_SUCCESS)
	{
		goto FINAL;
	}

	CHAR instanceKey[MAX_PATH] = { 0 };
	snprintf(instanceKey,sizeof(instanceKey), "SYSTEM\\CurrentControlSet\\Services\\%s\\Instances\\%s Instance", pDriverName, pDriverName);

	if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, instanceKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &altitudeAndFlagsKey, NULL) != ERROR_SUCCESS)
	{
		goto FINAL;
	}

	CHAR altitudeString[32] = { 0 };
	snprintf(altitudeString, sizeof(altitudeString), "%d", 37001);

	DWORD altitudeStringSize = ((DWORD)strlen(altitudeString) + 1) * sizeof(CHAR);
	if (RegSetValueExA(altitudeAndFlagsKey, "Altitude", 0, REG_SZ, (const BYTE*)altitudeString, altitudeStringSize) != ERROR_SUCCESS)
	{
		goto FINAL;
	}

	DWORD flags = 0;
	if (RegSetValueExA(altitudeAndFlagsKey, "Flags", 0, REG_DWORD, (const BYTE*)&flags, sizeof(flags)) != ERROR_SUCCESS)
	{
		goto FINAL;
	}

	success = TRUE;

FINAL:
	if (altitudeAndFlagsKey)
	{
		RegFlushKey(altitudeAndFlagsKey);
		RegCloseKey(altitudeAndFlagsKey);
		altitudeAndFlagsKey = NULL;
	}

	if (instancesKey)
	{
		RegFlushKey(instancesKey);
		RegCloseKey(instancesKey);
		instancesKey = NULL;
	}

	return success;
}

//转换盘符
//\Device\harddiskvolume\123.txt =>C:\123.txt
BOOL GetNTLinkName(LPWCH wszNtName, LPSTR wszDesName, ULONG dwDataLength)
{
	if (wszNtName == NULL || wszDesName == NULL || wcslen(wszNtName) <= wcslen(L"\\device\\harddiskvolume") ||
		wcsnicmp(wszNtName, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume")) != 0)
		return FALSE;

	WCHAR szDeviceName[3] = { 0,L':',L'\0'};
	WCHAR driveLetter[52] = { 0 };
	BOOL isFind = FALSE;
	for (WCHAR c = L'C'; c <= L'Z'; c++)
	{
		RtlZeroMemory(driveLetter, 52);
		szDeviceName[0] = c;
		if (!QueryDosDeviceW(szDeviceName, driveLetter, 52))
		{
			continue;
		}

		if (wcsnicmp(wszNtName, driveLetter, wcslen(driveLetter)) == 0)
		{
			isFind = TRUE;
			break;
		}
	}

	if (isFind)
	{
		DWORD maxSize = (wcslen(wszNtName) - wcslen(driveLetter)) * 2;
		if (dwDataLength < wcslen(driveLetter) || dwDataLength < maxSize + 4)
			return FALSE;

		RtlZeroMemory(wszDesName, dwDataLength);

		RtlCopyMemory(wszDesName, szDeviceName, 4);
		RtlCopyMemory(wszDesName + 4, wszNtName + wcslen(driveLetter), maxSize);
		return TRUE;
	}


	return FALSE;
}

//根据进程id获取进程路径
BOOL GetProcessPathByPid(DWORD pid, LPSTR pDesPath, ULONG dwDataLength)
{

	if (pid < 4 || pDesPath == NULL || dwDataLength == 0)
		return FALSE;

	BOOL isFind = FALSE;
#ifndef WINXP
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess == NULL)
	{
		return isFind;
	}

	WCHAR buffer[MAX_PATH];
	DWORD bufferSize = MAX_PATH;
	if (QueryFullProcessImageNameW(hProcess, 0, buffer, &bufferSize)) 
	{
		isFind = TRUE;
		RtlZeroMemory(pDesPath, dwDataLength);
		RtlCopyMemory(pDesPath, buffer, dwDataLength);
	}

	CloseHandle(hProcess);
	hProcess = NULL;
#endif

	return isFind;
}

typedef NTSTATUS (*_NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

//根据进程id获取父进程id
DWORD GetPPidByPid(DWORD pid)
{
	//HANDLE hProcess = NULL;
	//HMODULE hModule = NULL;
	//_NtQueryInformationProcess ntQueryInfoMationProcess = 0;
	//PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS status = 0;
	DWORD ppid = 0;

	if (pid < 4)
		return 0;


	// 创建进程快照
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe32 = { sizeof(pe32) };
		if (Process32First(hSnapshot, &pe32))
		{
			do
			{
				if (pe32.th32ProcessID == pid)
				{
					// 找到指定进程后获取父进程ID
					ppid = pe32.th32ParentProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}

	return ppid;



//	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
//	if (hProcess == NULL) 
//	{
//		goto FINAL;
//	}
//
//	
//	hModule = LoadLibrary(L"ntdll.dll");
//	if (hModule == NULL)
//	{
//		goto FINAL;
//	}
//	ntQueryInfoMationProcess = (_NtQueryInformationProcess)GetProcAddress(hModule,"NtQueryInformationProcess");
//	if (ntQueryInfoMationProcess == NULL)
//		goto FINAL;
//
//	// 获取父进程信息
//	status = ntQueryInfoMationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
//	if (status == 0) 
//	{
//		ppid = (DWORD)pbi.PebBaseAddress->Reserved3;
//	}
//
//FINAL:
//	if (hProcess)
//	{
//		CloseHandle(hProcess);
//		hProcess = NULL;
//	}
//
//	if (hModule)
//	{
//		FreeLibrary(hModule);
//		hModule = NULL;
//	}
//
//	return ppid;
}


//根据进程id获取进程名
BOOL GetProcessNameByPid(DWORD pid, LPSTR pDesPath, ULONG dwDataLength)
{
	if (pid < 4 || pDesPath == NULL || dwDataLength == 0)
		return FALSE;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) 
	{
		return FALSE;
	}

	HMODULE hMod;
	DWORD cbNeeded;
	if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) 
	{
		GetModuleBaseNameA(hProcess, hMod, pDesPath, dwDataLength);
	}

	CloseHandle(hProcess);
	hProcess = NULL;
	
	return TRUE;
}

//根据进程id获取进程创建时间
LONGLONG GetProcessCreateTimeByPid(DWORD pid)
{
	LONGLONG retTime = 0;
	if (pid < 4)
		return retTime;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		return retTime;
	}

	FILETIME createTime, exitTime, kernelTime, userTime;
	SYSTEMTIME sysCreateTime;
	if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime))
	{
		RtlCopyMemory(&retTime, &createTime, sizeof(LONGLONG));
		retTime = retTime / 10000000 - 11644473600;
	}

	CloseHandle(hProcess);
	hProcess = NULL;

	return retTime;
}

//根据文件名获取文件创建时间
LONGLONG GetFileCreateTimeByFileName(LPWCH fileName)
{
	LONGLONG retTime = 0;

	if (fileName == NULL)
		return retTime;

	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		return retTime;
	}

	FILETIME creationTime, lastAccessTime, lastWriteTime;
	if (GetFileTime(hFile, &creationTime, &lastAccessTime, &lastWriteTime)) 
	{
		RtlCopyMemory(&retTime, &creationTime, sizeof(LONGLONG));
		retTime = retTime / 10000000 - 11644473600;
	}

	CloseHandle(hFile);
	hFile = NULL;

	return retTime;
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
	catch (std::range_error) {
		return "";
	}

	return outStr;
}