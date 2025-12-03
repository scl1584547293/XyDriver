#pragma once
#include <fltKernel.h>
#include <minwindef.h>
#include <ndis.h>

typedef WCHAR WCHARMAX[255];

#define NF_TAG_LIST 'LgTg'

#define sl_init(x) KeInitializeSpinLock(x)
#define sl_lock(x, lh) KeAcquireInStackQueuedSpinLock(x, lh)
#define sl_unlock(lh) KeReleaseInStackQueuedSpinLock(lh)

//获取进程名
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
//获取父进程id
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);

//NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, 
//	PEPROCESS *Process);


typedef struct _DEVBUFFER
{
	LIST_ENTRY			pEntry;
	ULONG				dataLength;
	char*				dataBuffer;
}DEVBUFFER, *PDEVBUFFER;

typedef struct _DEVDATA
{
	KSPIN_LOCK lock;
	LIST_ENTRY pending;
	ULONG dataSize;
}DEVDATA, *PDEVDATA;


NTSTATUS QuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
);

NTSTATUS MyRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
);

typedef NTSTATUS(NTAPI* FN_ZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

//路径转换
BOOL NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName);
//时间转换
VOID LargeToTime(_In_ LARGE_INTEGER sysTm, _Out_ PTIME_FIELDS fileTm);
void utiltools_sleep(const unsigned int ttw);

//函数初始化
NTSTATUS FuncInit();
//根据进程id获取进程名
BOOL QueryProcessNamePath(IN DWORD pid, OUT PWCHAR path, IN DWORD pathLen);

//根据进程id获取进程命令行
BOOL QueryProcessCommandLine(IN DWORD pid, OUT PWCHAR data, IN DWORD dataLen);

//获取当前时间
BOOL GetCurrentTimeString(PLONGLONG pTime);

//unicode转ansi
BOOL UnicodeToAnsi(LPSTR str, PUNICODE_STRING wString,ULONG len);

//比对guid
BOOL GuidCmpare(GUID guid1,GUID guid2);

//根据进程id获取进程名
NTSTATUS GetProcessNameByPID(DWORD pid,LPSTR data,ULONG dataSize, PDWORD pPid);

//根据进程id获取进程创建时间
NTSTATUS GetProcessCreateTimeByPID(DWORD pid, PLONGLONG pTime);
