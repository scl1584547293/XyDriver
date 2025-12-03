#include "hotplug.h"
#include "devctrl.h"
#include "policy.h"

DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE,
	0xA5DCBF10, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);

#define NF_TAG_HOT 'HgTg'
#define NF_TAG_HOT_BUF 'HbTg'

//一条数据申请内存大小
#define HOTPLUG_ALLOCATESIZE sizeof(MonitorMsg) + sizeof(HOTPLUGINFO)
#define HOTPLUG_DATAMAXNUM LIST_MAX_SIZE/HOTPLUG_ALLOCATESIZE

//申请内存的List
static NPAGED_LOOKASIDE_LIST g_hotPlugList;
//热插拔数据
static DEVDATA g_hotPlugData;

static BOOL g_IsClean = FALSE;

PVOID g_notificationEntry = NULL;

//初始化热插拔模块
NTSTATUS HotPlugInit(_In_ PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;

	sl_init(&g_hotPlugData.lock);
	InitializeListHead(&g_hotPlugData.pending);

	ExInitializeNPagedLookasideList(
		&g_hotPlugList,
		NULL,
		NULL,
		0,
		sizeof(DEVBUFFER),
		NF_TAG_LIST,
		0
	);

	g_IsClean = TRUE;

	status = IoRegisterPlugPlayNotification(
		EventCategoryDeviceInterfaceChange,
		PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
		&GUID_DEVINTERFACE_USB_DEVICE,
		DriverObject,
		NotificationCallback,
		NULL, &g_notificationEntry
	);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("%s:%d(%s) [HotPlug]IoRegisterPlugPlayNotification err:%p\n", __FILE__, __LINE__, __FUNCTION__, status));

		return status;
	}

	return status;
}

//清理线程模块
VOID CleanHotPlug()
{
	if (!g_IsClean)
		return;

	KLOCK_QUEUE_HANDLE lh;
	PDEVBUFFER pData = NULL;
	int lock_status = 0;

	try {
		sl_lock(&g_hotPlugData.lock, &lh);
		lock_status = 1;
		while (!IsListEmpty(&g_hotPlugData.pending))
		{
			pData = (PDEVBUFFER)RemoveHeadList(&g_hotPlugData.pending);
			if (!pData)
				break;
			g_hotPlugData.dataSize--;
			sl_unlock(&lh);
			lock_status = 0;
			HotPlugPacketFree(pData);
			pData = NULL;
			sl_lock(&g_hotPlugData.lock, &lh);
			lock_status = 1;
		}

		sl_unlock(&lh);
		lock_status = 0;
	}
	finally {
		if (1 == lock_status)
			sl_unlock(&lh);
	}
}

//释放线程模块
VOID FreeHotPlug()
{
	if (!g_IsClean)
		return;

	CleanHotPlug();
	ExDeleteNPagedLookasideList(&g_hotPlugList);

	if (g_notificationEntry)
	{
		IoUnregisterPlugPlayNotification(g_notificationEntry);
		g_notificationEntry = NULL;
	}

	return;
}

//热插拔回调函数
NTSTATUS NotificationCallback(
	IN PVOID NotificationStructure,
	IN PVOID Context
)
{
	PMonitorMsg pHotPlugMsg = NULL;
	if (!GetTypeConfig(Monitor_USB) || NULL == NotificationStructure || KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		goto FINAL;
	}

	//SIZE_T allocateSize = sizeof(MonitorMsg) + sizeof(HOTPLUGINFO);

	pHotPlugMsg = (PMonitorMsg)ExAllocatePoolWithTag(NonPagedPool, HOTPLUG_ALLOCATESIZE, NF_TAG_HOT);
	if (pHotPlugMsg == NULL)
	{
		goto FINAL;
	}
	RtlZeroMemory(pHotPlugMsg, HOTPLUG_ALLOCATESIZE);

	PHOTPLUGINFO pHotPlugInfo = (PHOTPLUGINFO)pHotPlugMsg->data;
	if (!pHotPlugInfo)
		goto FINAL;

	PDEVICE_INTERFACE_CHANGE_NOTIFICATION notification = (PDEVICE_INTERFACE_CHANGE_NOTIFICATION)NotificationStructure;
	//GUID_DEVICE_INTERFACE_ARRIVAL;
	//GUID_DEVICE_INTERFACE_REMOVAL;
	//guid对比
	if (GuidCmpare(notification->Event, GUID_DEVICE_INTERFACE_REMOVAL))
	{
		pHotPlugInfo->type = MT_USBRemoval;
		if (!GetTypeConfig(MT_USBRemoval))
			goto FINAL;
	}
	else
	{
		pHotPlugInfo->type = MT_USBArrival;
		if (!GetTypeConfig(MT_USBArrival))
			goto FINAL;
	}
	
	pHotPlugMsg->common.type = Monitor_USB;
	pHotPlugMsg->common.pid = (DWORD)PsGetCurrentProcessId();
	pHotPlugInfo->threadId = (DWORD)PsGetCurrentThreadId();

	GetCurrentTimeString(&pHotPlugMsg->common.time);

	//根据进程id获取进程名
	GetProcessNameByPID(pHotPlugMsg->common.pid, pHotPlugMsg->common.comm,sizeof(pHotPlugMsg->common.comm), &pHotPlugMsg->common.ppid);
	//根据进程id获取进程创建时间
	GetProcessCreateTimeByPID((DWORD)pHotPlugMsg->common.pid, &pHotPlugInfo->createTime);

	WCHARMAX processPath = { 0 };
	if (QueryProcessNamePath((DWORD)pHotPlugMsg->common.pid, processPath, sizeof(processPath)))
	{
		RtlCopyMemory(pHotPlugMsg->common.exe, processPath, sizeof(WCHARMAX));

		//if (!IsAllowData(POLICY_EXE_LIST, pHotPlugMsg->common.exe, TRUE))
		//{
		//	goto FINAL;
		//}
	}
	//else
	//{
	//	if (!IsAllowData(POLICY_EXE_LIST, pHotPlugMsg->common.comm, FALSE))
	//	{
	//		goto FINAL;
	//	}
	//}

	//RtlStringCbCopyNW(pHotPlugInfo->symbolicLinkName, sizeof(WCHAR) * 260, notification->SymbolicLinkName->Buffer, sizeof(WCHAR) * 260);
	//RtlCopyMemory(&pHotPlugInfo->interfaceClassGuid, &notification->InterfaceClassGuid, sizeof(GUID));

	if(notification->SymbolicLinkName->Length < sizeof(WCHARMAX))
		RtlCopyMemory(pHotPlugInfo->symbolicLinkName,notification->SymbolicLinkName->Buffer, notification->SymbolicLinkName->Length);
	
	RtlCopyMemory(&pHotPlugInfo->interfaceClassGuid, &notification->InterfaceClassGuid, sizeof(GUID));

	//UNICODE_STRING          driveLetterName = { 0 };
	//UNICODE_STRING          linkTarget = { 0 };

	//RtlInitUnicodeString(&driveLetterName, pHotPlugInfo->symbolicLinkName);

	PDEVBUFFER pInfo = (PDEVBUFFER)HotPlugPacketAllocate(HOTPLUG_ALLOCATESIZE);
	if (!pInfo)
	{
		//ExFreePoolWithTag(pHotPlugInfo, 'REMM');
		KdPrint(("%s:%d(%s) [HotPlug]HotPlugPacketAllocate err\n", __FILE__, __LINE__, __FUNCTION__));
		return STATUS_SUCCESS;
	}

	RtlCopyMemory(pInfo->dataBuffer, pHotPlugMsg, HOTPLUG_ALLOCATESIZE);

	//检测数据量
	CheckHotPlugDataNum();

	KLOCK_QUEUE_HANDLE lh;
	sl_lock(&g_hotPlugData.lock, &lh);
	InsertHeadList(&g_hotPlugData.pending, &pInfo->pEntry);

	g_hotPlugData.dataSize++;
	sl_unlock(&lh);

	KdPrint(("%s:%d(%s) [HotPlug]name:%S,guid:0x%p-%p-%p-%p,processid:%d,threadid:%d\n", __FILE__, __LINE__, __FUNCTION__,
		pHotPlugInfo->symbolicLinkName, 
		pHotPlugInfo->interfaceClassGuid.Data1, pHotPlugInfo->interfaceClassGuid.Data2,
		pHotPlugInfo->interfaceClassGuid.Data3, pHotPlugInfo->interfaceClassGuid.Data4,
		pHotPlugMsg->common.pid, pHotPlugInfo->threadId));

	//添加数据
	PushInfo(Monitor_USB);

	//无效参数
	//STATUS_INVALID_PARAMETER;
	//拒绝访问
	//STATUS_ACCESS_DENIED

FINAL:
	if (pHotPlugMsg)
	{
		ExFreePoolWithTag(pHotPlugMsg,NF_TAG_HOT);
		pHotPlugMsg = NULL;
	}

	return STATUS_SUCCESS;
}

//从List中申请内存
PDEVBUFFER HotPlugPacketAllocate(int lens)
{
	PDEVBUFFER pHotPlugbuf = NULL;
	if (lens <= 0)
		return pHotPlugbuf;
	
	pHotPlugbuf = (PDEVBUFFER)ExAllocateFromNPagedLookasideList(&g_hotPlugList);
	if (!pHotPlugbuf)
		return pHotPlugbuf;

	RtlZeroMemory(pHotPlugbuf,sizeof(DEVBUFFER));

	pHotPlugbuf->dataBuffer = (char*)ExAllocatePoolWithTag(NonPagedPool, lens, NF_TAG_HOT_BUF);
	if (!pHotPlugbuf->dataBuffer)
	{
		KdPrint(("%s:%d(%s) [HotPlug]ExAllocatePoolWithTag err\n", __FILE__, __LINE__, __FUNCTION__));
		ExFreeToNPagedLookasideList(&g_hotPlugList, pHotPlugbuf);
		pHotPlugbuf = NULL;
		return pHotPlugbuf;
	}
	pHotPlugbuf->dataLength = lens;
	RtlZeroMemory(pHotPlugbuf->dataBuffer,lens);
	
	return pHotPlugbuf;
}

//释放内存
void HotPlugPacketFree(PDEVBUFFER packet)
{
	if (!packet)
		return;
	if (packet->dataBuffer)
	{
		ExFreePoolWithTag(packet->dataBuffer, NF_TAG_HOT_BUF);
		packet->dataBuffer = NULL;
	}
	ExFreeToNPagedLookasideList(&g_hotPlugList, packet);
}

//获取存储数据信息
PDEVDATA GetHotPlugCtx()
{
	return &g_hotPlugData;
}

//检测数据量
VOID CheckHotPlugDataNum()
{
	if (g_hotPlugData.dataSize > HOTPLUG_DATAMAXNUM)
	{
		CleanHotPlug();

		//KLOCK_QUEUE_HANDLE lh;
		//sl_lock(&g_hotPlugData.lock, &lh);
		//g_hotPlugData.dataSize = 0;
		//sl_unlock(&lh);
	}
}