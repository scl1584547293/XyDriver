#include "public.h"

#define NF_TAG_PUB 'PUBL'
FN_ZwQueryInformationProcess g_pfnZwQueryInformationProcess = NULL;

//输入\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Buffer注意要释放
NTSTATUS QuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
)
{
	OBJECT_ATTRIBUTES   oa = { 0 };
	NTSTATUS            status = 0;
	HANDLE              handle = NULL;

	InitializeObjectAttributes(
		&oa,
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE,
		0,
		0);

	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	LinkTarget->MaximumLength = sizeof(WCHARMAX);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, NF_TAG_PUB);
	if (!LinkTarget->Buffer)
	{
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(LinkTarget->Buffer, NF_TAG_PUB);
		LinkTarget->Buffer = NULL;
	}

	return status;
}

//\Device\\harddiskvolume => C:
NTSTATUS MyRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
)
{
	NTSTATUS                status = 0;
	UNICODE_STRING          driveLetterName = { 0 };
	WCHAR                   driveLetterNameBuf[128] = { 0 };
	WCHAR                   c = L'\0';
	WCHAR                   DriLetter[3] = { 0 };
	UNICODE_STRING          linkTarget = { 0 };

	for (c = L'A'; c <= L'Z'; c++)
	{
		RtlInitEmptyUnicodeString(&driveLetterName, driveLetterNameBuf, sizeof(driveLetterNameBuf));
		RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
		DriLetter[0] = c;
		DriLetter[1] = L':';
		DriLetter[2] = 0;
		RtlAppendUnicodeToString(&driveLetterName, DriLetter);

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE))
		{
			ExFreePoolWithTag(linkTarget.Buffer, NF_TAG_PUB);
			break;
		}

		ExFreePoolWithTag(linkTarget.Buffer, NF_TAG_PUB);
	}

	if (c <= L'Z')
	{
		DosName->Buffer = ExAllocatePoolWithTag(PagedPool, 3 * sizeof(WCHAR), NF_TAG_PUB);
		if (!DosName->Buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(DosName->Buffer,3*sizeof(WCHAR));

		DosName->MaximumLength = 6;
		DosName->Length = 4;
		*DosName->Buffer = c;
		*(DosName->Buffer + 1) = ':';
		*(DosName->Buffer + 2) = 0;

		return STATUS_SUCCESS;
	}

	return status;
}

//\Device\harddiskvolume\123.txt =>C:\123.txt
BOOL NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName)
{
	UNICODE_STRING      ustrFileName = { 0 };
	UNICODE_STRING      ustrDosName = { 0 };
	UNICODE_STRING      ustrDeviceName = { 0 };

	WCHAR               *pPath = NULL;
	ULONG               i = 0;
	ULONG               ulSepNum = 0;

	if (wszFileName == NULL || wszNTName == NULL ||
		_wcsnicmp(wszNTName, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume")) != 0)
	{
		return FALSE;
	}

	ustrFileName.Buffer = wszFileName;
	ustrFileName.Length = 0;
	ustrFileName.MaximumLength = sizeof(WCHARMAX);

	while (wszNTName[i] != L'\0')
	{
		if (wszNTName[i] == L'\0')
		{
			break;
		}
		if (wszNTName[i] == L'\\')
		{
			ulSepNum++;
		}
		if (ulSepNum == 3)
		{
			wszNTName[i] = UNICODE_NULL;
			pPath = &wszNTName[i + 1];
			break;
		}
		i++;
	}

	if (pPath == NULL)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&ustrDeviceName, wszNTName);

	if (!NT_SUCCESS(MyRtlVolumeDeviceToDosName(&ustrDeviceName, &ustrDosName)))
	{
		return FALSE;
	}

	RtlCopyUnicodeString(&ustrFileName, &ustrDosName);
	RtlAppendUnicodeToString(&ustrFileName, L"\\");
	RtlAppendUnicodeToString(&ustrFileName, pPath);

	ExFreePoolWithTag(ustrDosName.Buffer, NF_TAG_PUB);
	ustrDosName.Buffer = NULL;

	return TRUE;
}

VOID LargeToTime(_In_ LARGE_INTEGER sysTm,_Out_ PTIME_FIELDS fileTm)
{
	LARGE_INTEGER nowTm;
	ExSystemTimeToLocalTime(&sysTm, &nowTm);

	RtlTimeToTimeFields(&nowTm, fileTm);
}

void utiltools_sleep(const unsigned int ttw)
{
	if (PASSIVE_LEVEL == KeGetCurrentIrql())
	{
		NDIS_EVENT  _SleepEvent;
		NdisInitializeEvent(&_SleepEvent);
		NdisWaitEvent(&_SleepEvent, ttw);
	}
}

NTSTATUS FuncInit()
{
	if (g_pfnZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING UtrZwQueryInformationProcessName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
		g_pfnZwQueryInformationProcess = (FN_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&UtrZwQueryInformationProcessName);
	}

	return STATUS_SUCCESS;
}

//根据pid获取进程名（废弃）
//NTSTATUS GetProcessImagePathByProcessId(IN HANDLE pid, OUT PWSTR pImagePathBuffer, IN SIZE_T bufferSize, OUT PULONG pNeedSize)
//{
//	if (pImagePathBuffer == NULL)
//	{
//		return STATUS_INFO_LENGTH_MISMATCH;
//	}
//	if (pid <= (HANDLE)4)
//	{
//		return STATUS_INVALID_PARAMETER;
//	}
//
//	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
//	{
//		return STATUS_UNSUCCESSFUL;
//	}
//
//	FuncInit();
//
//	NTSTATUS status = STATUS_UNSUCCESSFUL;
//	HANDLE process = NULL;
//	OBJECT_ATTRIBUTES oa = { 0 };
//	CLIENT_ID cid = { 0 };
//	ULONG needSize = 0;
//	PUNICODE_STRING pTmpImagePath = NULL;
//
//	do
//	{
//		oa.Length = sizeof(OBJECT_ATTRIBUTES);
//		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
//
//		cid.UniqueProcess = pid;
//
//#ifndef PROCESS_QUERY_INFORMATION
//#define PROCESS_QUERY_INFORMATION (0x0400)
//#endif
//
//		//打开进程
//		status = ZwOpenProcess(&process, PROCESS_QUERY_INFORMATION, &oa, &cid);
//		if (!NT_SUCCESS(status))
//		{
//			break;
//		}
//
//		//获取进程相关信息大小
//		status = g_pfnZwQueryInformationProcess(process, ProcessImageFileName, NULL, 0, &needSize);
//		if (status != STATUS_INFO_LENGTH_MISMATCH)
//		{
//			break;
//		}
//
//		//缓存区大小太小
//		if (bufferSize < needSize)
//		{
//			if (pNeedSize)
//			{
//				*pNeedSize = needSize;
//			}
//			status = STATUS_INFO_LENGTH_MISMATCH;
//			break;
//		}
//
//		//进程名
//		pTmpImagePath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, needSize, NF_TAG_PUB);
//		if (pTmpImagePath == NULL)
//		{
//			break;
//		}
//
//		RtlZeroMemory(pTmpImagePath, needSize);
//
//		//获取进程相关信息
//		status = g_pfnZwQueryInformationProcess(process, ProcessImageFileName, pTmpImagePath, needSize, &needSize);
//		if (!NT_SUCCESS(status))
//		{
//			break;
//		}
//
//		status = RtlStringCbCopyNW(pImagePathBuffer, bufferSize, pTmpImagePath->Buffer, pTmpImagePath->Length);
//
//	} while (FALSE);
//
//	if (pTmpImagePath)
//	{
//		//释放内存
//		ExFreePoolWithTag(pTmpImagePath, NF_TAG_PUB);
//		pTmpImagePath = NULL;
//	}
//
//	if (process)
//	{
//		//关闭进程
//		ZwClose(process);
//		process = NULL;
//	}
//
//	return status;
//}

//根据pid获取进程名
BOOL QueryProcessNamePath(IN DWORD pid, OUT PWCHAR path, IN DWORD pathLen)
{
	BOOL bRet = FALSE;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES obj;
	HANDLE hProc = NULL;
	NTSTATUS status;
	PUNICODE_STRING pProcessPath = NULL;

	if (NULL == path || pathLen == 0)
	{
		goto FINAL;
	}

	if (pid == 0 || pid == (DWORD)PsGetProcessId(PsInitialSystemProcess))
	{
		goto FINAL;
	}

	if(KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		goto FINAL;
	}

	InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = NULL;

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

	FuncInit();
	if (g_pfnZwQueryInformationProcess == NULL)
	{
		goto FINAL;
	}

	status = ZwOpenProcess(&hProc, GENERIC_ALL, &obj, &cid);
	if (!NT_SUCCESS(status))
		goto FINAL;
	
	ULONG needSize = 0;
	status = g_pfnZwQueryInformationProcess(hProc, ProcessImageFileName, NULL, 0, &needSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		goto FINAL;
	}

	if (pathLen < needSize || needSize == 0)
	{
		goto FINAL;
	}

	pProcessPath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, needSize, NF_TAG_PUB);
	if (pProcessPath == NULL)
	{
		goto FINAL;
	}
	RtlZeroMemory(pProcessPath, needSize);

	status = g_pfnZwQueryInformationProcess(hProc, ProcessImageFileName, pProcessPath, needSize, &needSize);
	if (!NT_SUCCESS(status) || pProcessPath->Length == 0)
	{
		goto FINAL;
	}

	RtlCopyMemory(path, pProcessPath->Buffer, pProcessPath->Length);
	//status = RtlStringCbCopyNW(path, pathLen, pProcessPath->Buffer, pProcessPath->Length);
	
	bRet = TRUE;

FINAL:
	if (pProcessPath)
	{
		ExFreePoolWithTag(pProcessPath, NF_TAG_PUB);
		pProcessPath = NULL;
	}

	if (hProc)
	{
		ZwClose(hProc);
		hProc = NULL;
	}

	return bRet;
}

//无用
BOOL QueryProcessCommandLine(IN DWORD pid, OUT PWCHAR data, IN DWORD dataLen)
{
	BOOL bRet = FALSE;
	CLIENT_ID cid;
	OBJECT_ATTRIBUTES obj;
	HANDLE hProc = NULL;
	NTSTATUS status;
	PUNICODE_STRING pCommandPath = NULL;

	if (NULL == data || dataLen == 0)
	{
		goto FINAL;
	}

	InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = NULL;

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

	status = ZwOpenProcess(&hProc, GENERIC_ALL, &obj, &cid);
	if (!NT_SUCCESS(status))
		goto FINAL;

	FuncInit();
	if (g_pfnZwQueryInformationProcess == NULL)
	{
		goto FINAL;
	}


	ULONG needSize = 0;
	status = g_pfnZwQueryInformationProcess(hProc, ProcessCommandLineInformation, NULL, 0, &needSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		KdPrint(("====ProcessCommandLineInformation err:%p\n", status));
		goto FINAL;
	}

	if (dataLen < needSize)
	{
		goto FINAL;
	}

	pCommandPath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, needSize, NF_TAG_PUB);
	if (pCommandPath == NULL)
	{
		goto FINAL;
	}
	RtlZeroMemory(pCommandPath, needSize);

	status = g_pfnZwQueryInformationProcess(hProc, ProcessCommandLineInformation, pCommandPath, needSize, &needSize);
	if (!NT_SUCCESS(status))
	{
		goto FINAL;
	}

	RtlCopyMemory(data, pCommandPath->Buffer, pCommandPath->Length);
	//status = RtlStringCbCopyNW(data, dataLen, pCommandPath->Buffer, pCommandPath->Length);

	bRet = TRUE;

FINAL:
	if (pCommandPath)
	{
		ExFreePoolWithTag(pCommandPath, NF_TAG_PUB);
		pCommandPath = NULL;
	}

	if (hProc)
	{
		ZwClose(hProc);
		hProc = NULL;
	}

	return bRet;
}

//获取当前时间
BOOL GetCurrentTimeString(PLONGLONG pTime)
{
	//LARGE_INTEGER SystemTime;
	LONGLONG SystemTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS timeFiled;

	KeQuerySystemTime(&SystemTime);

	//转成unix时间戳，11644473600是1601到1901的秒数
	*pTime = SystemTime / 10000000 - 11644473600;

	//转成本地时区时间
	//ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
	//格式化时间
	//RtlTimeToTimeFields(&LocalTime, &timeFiled);

	//*pTime = timeFiled;

	//RtlStringCchPrintfW(data, dataSize, L"%04d-%02d-%02d %02d:%02d:%02d",
	//	timeFiled.Year, timeFiled.Month, timeFiled.Day,
	//	timeFiled.Hour, timeFiled.Minute, timeFiled.Second);

	//swprintf(data, L"%04d-%02d-%02d %02d:%02d:%02d",
	//	timeFiled.Year,timeFiled.Month,timeFiled.Day,
	//	timeFiled.Hour,timeFiled.Minute,timeFiled.Second
	//);

	return TRUE;
}

//unicode转ansi，需要级别 PASSIVE_LEVEL
BOOL UnicodeToAnsi(LPSTR str, PUNICODE_STRING wString, ULONG len)
{
	if (str == NULL || wString == NULL || wString->Length == 0 || wString->Buffer[0] == L'\0' || 
		KeGetCurrentIrql() != PASSIVE_LEVEL)
		return FALSE;

	ANSI_STRING ansiProcessPath = { 0 };
	NTSTATUS status = RtlUnicodeStringToAnsiString(&ansiProcessPath, wString, TRUE);
	if (NT_SUCCESS(status))
	{
		RtlFreeAnsiString(&ansiProcessPath);
		return FALSE;

		if (ansiProcessPath.Length > 0 && ansiProcessPath.Length < len)
		{
			RtlZeroMemory(str, len);
			RtlCopyMemory(str, ansiProcessPath.Buffer, ansiProcessPath.Length);
		}

		RtlFreeAnsiString(&ansiProcessPath);
		return TRUE;
	}

	return FALSE;
}

//比对guid
BOOL GuidCmpare(GUID guid1, GUID guid2)
{
	BOOL ret = FALSE;

	if (guid1.Data1 != guid2.Data1 || guid1.Data2 != guid2.Data2 ||
		guid1.Data3 != guid2.Data3)
	{
		return ret;
	}

	for (DWORD i = 0; i < sizeof(guid1.Data4); i++)
	{
		if (guid1.Data4[i] != guid2.Data4[i])
			break;
	}

	ret = TRUE;

	return ret;
}

//根据进程id获取进程名
NTSTATUS GetProcessNameByPID(DWORD pid, LPSTR data, ULONG dataSize, PDWORD pPid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (KeGetCurrentIrql() > APC_LEVEL ||  pid == 0 || data == NULL)
		return status;

	PEPROCESS eProcess = NULL;
	status = PsLookupProcessByProcessId((HANDLE)pid, &eProcess);
	if (NT_SUCCESS(status))
	{
		UCHAR* ucProcessImageFileName = PsGetProcessImageFileName(eProcess);
		if (ucProcessImageFileName != NULL)
			RtlCopyMemory(data, ucProcessImageFileName, dataSize);

		if(pPid)
			*pPid = (DWORD)PsGetProcessInheritedFromUniqueProcessId(eProcess);
	}

	if(eProcess)
		ObDereferenceObject(eProcess);

	return status;
}

NTSTATUS GetProcessCreateTimeByPID(DWORD pid, PLONGLONG pTime)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (KeGetCurrentIrql() > APC_LEVEL || pid == 0 || pTime == NULL)
		return status;

	PEPROCESS eProcess = NULL;
	status = PsLookupProcessByProcessId((HANDLE)pid, &eProcess);
	if (NT_SUCCESS(status))
	{
		LONGLONG timeQuadPart = PsGetProcessCreateTimeQuadPart(eProcess);

		if (timeQuadPart != 0)
		{
			//LARGE_INTEGER current_local_time;
			////从系统时间转换成当地时区时间
			//ExSystemTimeToLocalTime(&timeQuadPart, &current_local_time);
			//RtlTimeToTimeFields(&current_local_time, pTimes);

			//转成unix时间戳，11644473600是1601到1901的秒数
			*pTime = timeQuadPart / 10000000 - 11644473600;
		}
	}

	if (eProcess)
		ObDereferenceObject(eProcess);

	return status;
}



