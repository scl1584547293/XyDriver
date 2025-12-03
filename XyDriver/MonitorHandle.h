#pragma once
#include <fltKernel.h>

//x86
//typedef struct _KLDR_DATA_TABLE_ENTRY
//{
//	LIST_ENTRY InLoadOrderModuleList;
//	LIST_ENTRY InMemoryOrderModuleList;
//	LIST_ENTRY InInitializationOrderModuleList;
//	PVOID DllBase;
//	PVOID EntryPoint;
//	UINT32 SizeOfImage;
//	UNICODE_STRING FullDllName;
//	UNICODE_STRING BaseDllName;
//	UINT32 Flags;
//	USHORT LoadCount;
//	USHORT TlsIndex;
//	LIST_ENTRY HashLinks;
//	PVOID SectionPointer;
//	UINT32 CheckSum;
//	UINT32 TimeDateStamp;
//	PVOID LoadedImports;
//	PVOID EntryPointActivationContext;
//	PVOID PatchInformation;
//} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

#ifndef _WIN64
#pragma pack(1)                               
#endif
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#ifndef _WIN64
#pragma pack()
#endif


//³õÊ¼»¯¼à¿Ø¾ä±ú»Øµ÷
NTSTATUS InitObRegistration(PDRIVER_OBJECT pDriverObject);
NTSTATUS InitProcessObRegistration(PDRIVER_OBJECT pDriverObject);
NTSTATUS InitThreadObRegistration(PDRIVER_OBJECT pDriverObject);
//Ð¶ÔØ¼à¿Ø¾ä±ú
VOID UninstallHandle();
