#include "MonitorHandle.h"
#include "minifilter.h"
#include "process.h"
#include "thread.h"
#include "policy.h"

static PVOID g_RegistrationHandle = NULL;
//static PVOID g_ThreadRegistrationHandle = NULL;
static OB_OPERATION_REGISTRATION obOperationRegistrations[2];

NTSTATUS InitObRegistration(PDRIVER_OBJECT pDriverObject)
{
	//绕过签名检测（ObRegisterCallbacks 必需的）
	//PLDR_DATA_TABLE_ENTRY pLDR = NULL;
	//pLDR = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	//pLDR->Flags |= 0x20;

	//OB_OPERATION_REGISTRATION obOperationRegistrations[2];
	//进程句柄
	obOperationRegistrations[0].ObjectType = PsProcessType;
	//打开句柄 | 复制句柄
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[0].PreOperation = PreProcessCallback;

	//线程句柄
	obOperationRegistrations[1].ObjectType = PsThreadType;
	//打开句柄 | 复制句柄
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[1].PreOperation = PreThreadCallback;


	//LARGE_INTEGER		lTickCount = { 0, };
	WCHAR				szAltitude[40] = L"370130";
	UNICODE_STRING altitude = { 0 };

	//KeQueryTickCount(&lTickCount);
	//RtlStringCbPrintfW(szAltitude, sizeof(szAltitude), L"%ws.%d", L"370130", lTickCount.LowPart);
	RtlInitUnicodeString(&altitude, szAltitude);

	OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };

	obCallbackRegistration.Version = ObGetFilterVersion();
	obCallbackRegistration.OperationRegistrationCount = 2;
	obCallbackRegistration.RegistrationContext = NULL;
	obCallbackRegistration.Altitude = altitude;
	obCallbackRegistration.OperationRegistration = obOperationRegistrations;

	return ObRegisterCallbacks(&obCallbackRegistration, &g_RegistrationHandle);





	//NTSTATUS status = STATUS_SUCCESS;

	//status = InitProcessObRegistration(pDriverObject);
	//if (!NT_SUCCESS(status))
	//{
	//	KdPrint(("InitProcessObRegistration err:%p\n", status));
	//	return status;
	//}
	//
	//status = InitThreadObRegistration(pDriverObject);
	//if (!NT_SUCCESS(status))
	//{
	//	KdPrint(("InitThreadObRegistration err:%p\n", status));
	//	return status;
	//}

	//return status;
}

NTSTATUS InitProcessObRegistration(PDRIVER_OBJECT pDriverObject)
{
	OB_OPERATION_REGISTRATION obOperationRegistrations;
	//进程句柄
	obOperationRegistrations.ObjectType = PsProcessType;
	//打开句柄 | 复制句柄
	obOperationRegistrations.Operations |= OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations.PreOperation = PreProcessCallback;


	LARGE_INTEGER		lTickCount = { 0, };
	WCHAR				szAltitude[40] = L"3210000";
	UNICODE_STRING altitude = { 0 };

	//KeQueryTickCount(&lTickCount);
	//RtlStringCbPrintfW(szAltitude, sizeof(szAltitude), L"%ws.%d", L"370130", lTickCount.LowPart);
	RtlInitUnicodeString(&altitude, szAltitude);

	OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };

	obCallbackRegistration.Version = ObGetFilterVersion();
	obCallbackRegistration.OperationRegistrationCount = 1;
	obCallbackRegistration.RegistrationContext = NULL;
	obCallbackRegistration.Altitude = altitude;
	obCallbackRegistration.OperationRegistration = &obOperationRegistrations;

	return ObRegisterCallbacks(&obCallbackRegistration, &g_RegistrationHandle);
}

NTSTATUS InitThreadObRegistration(PDRIVER_OBJECT pDriverObject)
{
	OB_OPERATION_REGISTRATION obOperationRegistrations;
	//线程句柄
	obOperationRegistrations.ObjectType = PsThreadType;
	//打开句柄 | 复制句柄
	obOperationRegistrations.Operations |= OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations.PreOperation = PreThreadCallback;


	LARGE_INTEGER		lTickCount = { 0, };
	WCHAR				szAltitude[40] = L"3212000";
	UNICODE_STRING altitude = { 0 };

	//KeQueryTickCount(&lTickCount);
	//RtlStringCbPrintfW(szAltitude, sizeof(szAltitude), L"%ws.%d", L"370130", lTickCount.LowPart);
	RtlInitUnicodeString(&altitude, szAltitude);

	OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };

	obCallbackRegistration.Version = ObGetFilterVersion();
	obCallbackRegistration.OperationRegistrationCount = 1;
	obCallbackRegistration.RegistrationContext = NULL;
	obCallbackRegistration.Altitude = altitude;
	obCallbackRegistration.OperationRegistration = &obOperationRegistrations;

	return ObRegisterCallbacks(&obCallbackRegistration, &g_RegistrationHandle);
}

VOID UninstallHandle()
{
	if (g_RegistrationHandle)
	{
		KdPrint(("UninstallHandle ProcessRegistrationHandle\n"));
		ObUnRegisterCallbacks(g_RegistrationHandle);
		g_RegistrationHandle = NULL;
	}
	//if (g_ThreadRegistrationHandle)
	//{
	//	KdPrint(("UninstallHandle ThreadRegistrationHandle\n"));
	//	ObUnRegisterCallbacks(g_ThreadRegistrationHandle);
	//	g_ThreadRegistrationHandle = NULL;
	//}
}
