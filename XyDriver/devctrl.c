#include "devctrl.h"
#include "public.h"
#include "register.h"
#include "process.h"
#include "thread.h"
#include "minifilter.h"
#include "network.h"
#include "hotplug.h"
#include "MonitorHandle.h"
#include "policy.h"
#include "loadimage.h"

#include "tdi.h"

BOOL g_isInit = FALSE;

//输入内存
static SHARED_MEMORY g_inBuf;
static SHARED_MEMORY g_outBuf;

//申请内存使用的list
static NPAGED_LOOKASIDE_LIST    g_IoQueryList;
//锁
static KSPIN_LOCK               g_IoQueryLock;
//存放数据list
static LIST_ENTRY               g_IoQueryHead;

//消息
static KEVENT					g_ioThreadEvent;
//线程句柄
static PVOID			        g_ioThreadObject = NULL;
//存放数据量list
static LIST_ENTRY				g_pendedIoRequests;

//是否结束
static BOOL					g_shutdown = FALSE;

static BOOL g_IsClean = FALSE;

//static KSPIN_LOCK g_DriverStatusLock;
//static ULONG g_IsStart = 0;

//初始化进程信息
NTSTATUS DevThreadInit()
{
	NTSTATUS status = STATUS_SUCCESS;
	if (g_ioThreadObject)
		return status;

	HANDLE threadHandle;
	//创建线程
	status = PsCreateSystemThread(
		&threadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		IoThread,
		NULL
	);

	//线程句柄映射到应用层
	if (NT_SUCCESS(status))
	{
		KPRIORITY priority = HIGH_PRIORITY;

		ZwSetInformationThread(threadHandle, ThreadPriority, &priority, sizeof(priority));

		status = ObReferenceObjectByHandle(
			threadHandle,
			0,
			NULL,
			KernelMode,
			&g_ioThreadObject,
			NULL
		);
		//ASSERT(NT_SUCCESS(status));
	}

	return status;
}

//初始化
NTSTATUS DevInit(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	KdPrint(("%s:%d(%s) DevInit\n",__FILE__,__LINE__,__FUNCTION__));
	//初始化list
	InitializeListHead(&g_IoQueryHead);
	InitializeListHead(&g_pendedIoRequests);
	//初始化锁
	sl_init(&g_IoQueryLock);
	//KeInitializeSpinLock(&g_DriverStatusLock);

	//
	ExInitializeNPagedLookasideList(
		&g_IoQueryList,
		NULL,
		NULL,
		0,
		sizeof(NF_QUEUE_ENTRY),
		NF_TAG_LIST,
		0
	);

	//初始化消息
	KeInitializeEvent(
		&g_ioThreadEvent,
		SynchronizationEvent,
		FALSE
	);

	g_IsClean = TRUE;

	//初始化线程
	status = DevThreadInit();
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	InitPolicy();

	//初始化注册表模块
	status = RegisterInit();
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	KdPrint(("RegisterInit success\n"));

	//初始化进程模块
	status = ProcessInit();
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	KdPrint(("ProcessInit success\n"));

#ifndef WINXP
	status = InitObRegistration(DriverObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("InitObRegistration error:%p\n", status));
		return status;
	}
	KdPrint(("InitObRegistration success\n"));
#endif

	//初始化线程模块
	status = ThreadInit();
	if (!NT_SUCCESS(status))
		return status;
	KdPrint(("ThreadInit success\n"));

	//初始化热插拔模块
	status = HotPlugInit(DriverObject);
	if (!NT_SUCCESS(status))
		return status;
	KdPrint(("HotPlugInit success\n"));

#ifndef WINXP
	//初始化网络模块
	status = WallRegisterCallouts(DriverObject);
	if (!NT_SUCCESS(status))
		return status;
	KdPrint(("WallRegisterCallouts success\n"));
#else
	status = TdiInit(DriverObject);
	if (!NT_SUCCESS(status))
		return status;
	KdPrint(("TdiInit success\n"));
#endif

	status = LoadImageInit();
	if (!NT_SUCCESS(status))
		return status;
	KdPrint(("LoadImageInit success\n"));

	g_isInit = TRUE;
	return status;
}

//关闭
NTSTATUS DevClose(PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;

//	//清理配置
//	CleanAllPolicy();
//
//	//清理MiniFilter
//	CleanMiniFilter();
//
//	//清理注册表模块
//	CleanRegister();
//	//清理进程模块
//	CleanProcess();
//	//清理线程模块
//	CleanThread();
//	//清理热插拔模块
//	CleanHotPlug();
//#ifndef WINXP
//	//清理网络模块
//	CleanNetWork();
//#endif
//
//	//清理
//	DevClean();

	//释放共享内存
	FreeSharedMemory(&g_inBuf);
	FreeSharedMemory(&g_outBuf);

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

//释放资源
VOID DevFree(PDRIVER_OBJECT pDriverObject)
{
	//结束采集
	SetShutdown();

	//清理配置
	FreePolicy();

	//注册表监控
	FreeRegister();
	//进程监控
	FreeProcess();
	//线程监控
	FreeThread();
	//热插拔
	FreeHotPlug();
#ifndef WINXP
	//网络
	WallUnRegisterCallouts();

	//卸载监控句柄模块
	UninstallHandle();
#else
	FreeTdi(pDriverObject);
#endif
	FreeLoadImage();

	//NO NO NO NO NO!!!!minifilter(不要在这里卸载！)
	//UnloadMiniFilter();

	if (!g_IsClean)
		return;

	//清理
	DevClean();

	//释放共享内存
	FreeSharedMemory(&g_inBuf);
	FreeSharedMemory(&g_outBuf);

	//释放List
	ExDeleteNPagedLookasideList(&g_IoQueryList);


	if (g_ioThreadObject) {
		// 标记卸载驱动-跳出循环
		KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);

		KeWaitForSingleObject(
			g_ioThreadObject,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		ObDereferenceObject(g_ioThreadObject);
		g_ioThreadObject = NULL;
	}
}

//清理
VOID DevClean()
{
	if (!g_IsClean)
		return;
	PNF_QUEUE_ENTRY pQuery = NULL;
	KLOCK_QUEUE_HANDLE lh;
	int lock_status = 0;

	try {
		sl_lock(&g_IoQueryLock, &lh);
		lock_status = 1;
		//清理List
		while (!IsListEmpty(&g_IoQueryHead))
		{
			pQuery = (PNF_QUEUE_ENTRY)RemoveHeadList(&g_IoQueryHead);
			if (!pQuery)
			{
				break;
			}

			sl_unlock(&lh);
			lock_status = 0;

			ExFreeToNPagedLookasideList(&g_IoQueryList, pQuery);
			pQuery = NULL;
			sl_lock(&g_IoQueryLock, &lh);
			lock_status = 1;
		}
	}
	finally {
		if (1 == lock_status)
			sl_unlock(&lh);
	}

	//结束
	CancelPendingReads();
}


//读取采集数据
NTSTATUS DriverRead(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	KdPrint(("%s:%d(%s) DriverRead\n", __FILE__, __LINE__, __FUNCTION__));
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;

	if (irp->MdlAddress == NULL)
	{
		KdPrint(("%s:%d(%s) irp->MdlAddress error\n", __FILE__, __LINE__, __FUNCTION__));
		status = STATUS_INVALID_PARAMETER;
		goto FINAL;
	}

	//物理内存映射的缓存区为空或结构大小错误则返回
	if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL ||
		irpSp->Parameters.Read.Length < sizeof(NF_READ_RESULT))
	{
		KdPrint(("%s:%d(%s) MmGetSystemAddressForMdlSafe error\n", __FILE__, __LINE__, __FUNCTION__));
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto FINAL;
	}

	sl_lock(&g_IoQueryLock, &lh);

	IoSetCancelRoutine(irp, DriverCancelRead);

	if (irp->Cancel &&IoSetCancelRoutine(irp, NULL))
	{
		KdPrint(("%s:%d(%s) STATUS_CANCELLED\n", __FILE__, __LINE__, __FUNCTION__));
		status = STATUS_CANCELLED;
	}
	else
	{
		KdPrint(("%s:%d(%s) STATUS_PENDING\n", __FILE__, __LINE__, __FUNCTION__));

		// pending请求
		InsertTailList(&g_pendedIoRequests, &irp->Tail.Overlay.ListEntry);
		IoMarkIrpPending(irp);
		status = STATUS_PENDING;
	}

	sl_unlock(&lh);

	// 激活处理事件
	KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);

FINAL:
	if (status != STATUS_PENDING)
	{
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;
}

//处理线程
void  IoThread(void* StartContext)
{
	KLOCK_QUEUE_HANDLE lh;
	PLIST_ENTRY	pEntry;

	for (;;)
	{
		// handler io packter
		KeWaitForSingleObject(
			&g_ioThreadEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);
	
		//结束
		if (IsShutdown())
		{
			KdPrint(("%s:%d(%s) IsShutdown\n", __FILE__, __LINE__, __FUNCTION__));
			break;
		}

		//读取数据
		ServiceReads();

	}
	//结束进程
	PsTerminateSystemThread(STATUS_SUCCESS);
}

//驱动结束
VOID SetShutdown()
{
	if (!g_IsClean)
		return;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);
	g_shutdown = TRUE;
	sl_unlock(&lh);
}

//是否结束
BOOL	IsShutdown()
{
	BOOL		res;
	KLOCK_QUEUE_HANDLE lh;

	res = g_shutdown;

	return g_shutdown;
} 

//结束读取
void CancelPendingReads()
{
	PIRP                irp;
	PLIST_ENTRY         pIrpEntry;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);

	//清理List
	while (!IsListEmpty(&g_pendedIoRequests))
	{
		pIrpEntry = g_pendedIoRequests.Flink;
		irp = CONTAINING_RECORD(pIrpEntry, IRP, Tail.Overlay.ListEntry);

		if (IoSetCancelRoutine(irp, NULL))
		{
			RemoveEntryList(pIrpEntry);

			sl_unlock(&lh);

			irp->IoStatus.Status = STATUS_CANCELLED;
			irp->IoStatus.Information = 0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			sl_lock(&g_IoQueryLock, &lh);
		}
		else
		{
			sl_unlock(&lh);

			utiltools_sleep(1000);

			sl_lock(&g_IoQueryLock, &lh);
		}
	}

	sl_unlock(&lh);
}

//读取数据
void ServiceReads()
{
	PIRP                irp = NULL;
	PLIST_ENTRY         pIrpEntry;
	BOOL             foundPendingIrp = FALSE;
	PNF_READ_RESULT		pResult;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);

	if (IsListEmpty(&g_pendedIoRequests))
	{
		sl_unlock(&lh);
		return;
	}

	//if (IsListEmpty(&g_IoQueryHead))
	//{
	//	sl_unlock(&lh);
	//	return;
	//}

	pIrpEntry = g_pendedIoRequests.Flink;
	while (pIrpEntry != &g_pendedIoRequests)
	{
		irp = CONTAINING_RECORD(pIrpEntry, IRP, Tail.Overlay.ListEntry);

		if (IoSetCancelRoutine(irp, NULL))
		{
			// 移除
			RemoveEntryList(pIrpEntry);
			foundPendingIrp = TRUE;
			break;
		}
		else
		{
			pIrpEntry = pIrpEntry->Flink;
		}
	}

	sl_unlock(&lh);

	if (!foundPendingIrp)
	{
		return;
	}

	//UINT64 bufferLen = FillBuffer();
	//if (bufferLen != 0)
	{
		//从物理内存地址的缓存区中读取数据
		pResult = (PNF_READ_RESULT)MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
		if (!pResult)
		{
			KdPrint(("%s:%d(%s) MmGetSystemAddressForMdlSafe error\n", __FILE__, __LINE__, __FUNCTION__));
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return;
		}

		//读取数据
		pResult->length = FillBuffer();
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(NF_READ_RESULT);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

//结束读取IRP
VOID DriverCancelRead(IN PDEVICE_OBJECT deviceObject, IN PIRP irp)
{
	KLOCK_QUEUE_HANDLE lh;

	//UNREFERENCED_PARAMETER(deviceObject);

	IoReleaseCancelSpinLock(irp->CancelIrql);

	sl_lock(&g_IoQueryLock, &lh);
	RemoveEntryList(&irp->Tail.Overlay.ListEntry);
	sl_unlock(&lh);

	irp->IoStatus.Status = STATUS_CANCELLED;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

//获取所有数据
UINT64 FillBuffer()
{
	PNF_QUEUE_ENTRY	pEntry;
	UINT64		offset = 0;
	NTSTATUS	status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lh;

	sl_lock(&g_IoQueryLock, &lh);

	while (!IsListEmpty(&g_IoQueryHead))
	{
		pEntry = (PNF_QUEUE_ENTRY)RemoveHeadList(&g_IoQueryHead);

		sl_unlock(&lh);

		//抛出数据
		status = PopInfo(&offset, pEntry->code);

		sl_lock(&g_IoQueryLock, &lh);

		if (!NT_SUCCESS(status))
		{
			InsertHeadList(&g_IoQueryHead, &pEntry->entry);
			break;
		}

		ExFreeToNPagedLookasideList(&g_IoQueryList, pEntry);
	}

	sl_unlock(&lh);
	return offset;
}


//打开共享内存
NTSTATUS OpenShareMem(PDEVICE_OBJECT DeviceObject, PIRP irp, PIO_STACK_LOCATION irpSp)
{
	PVOID ioBuffer = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	ioBuffer = irp->AssociatedIrp.SystemBuffer;
	if (!ioBuffer)
	{
		ioBuffer = irp->UserBuffer;
	}
	ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (ioBuffer && (outputBufferLength >= sizeof(NF_BUFFERS)))
	{
		if (!g_inBuf.mdl)
		{
			//创建共享内存
			status = CreateSharedMemory(&g_inBuf, NF_PACKET_BUF_SIZE * 20);
		}

		if (!NT_SUCCESS(status))
		{
			goto FINAL;
		}

		if (!g_outBuf.mdl)
		{
			//创建共享内存
			status = CreateSharedMemory(&g_outBuf, NF_PACKET_BUF_SIZE * 1);
		}

		if (!NT_SUCCESS(status))
		{
			goto FINAL;
		}

		PNF_BUFFERS pBuffers = (PNF_BUFFERS)ioBuffer;

		pBuffers->inBuf = (UINT64)g_inBuf.userVa;
		pBuffers->inBufLen = g_inBuf.bufferLength;
		pBuffers->outBuf = (UINT64)g_outBuf.userVa;
		pBuffers->outBufLen = g_outBuf.bufferLength;

		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = sizeof(NF_BUFFERS);
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		KdPrint(("创建/打开共享内存成功！\n"));
		return STATUS_SUCCESS;
	}

FINAL:
	KdPrint(("%s:%d(%s) OpenShareMem error:%p",__FILE__,__LINE__, __FUNCTION__,status));
	FreeSharedMemory(&g_inBuf);
	FreeSharedMemory(&g_outBuf);

	irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_UNSUCCESSFUL;
}

//创建共享内存
NTSTATUS CreateSharedMemory(PSHARED_MEMORY pSharedMemory, ULONG len)
{
	PMDL  mdl;
	PVOID userVa = NULL;
	PVOID kernelVa = NULL;
	PHYSICAL_ADDRESS lowAddress;
	PHYSICAL_ADDRESS highAddress;

	memset(pSharedMemory, 0, sizeof(SHARED_MEMORY));

	lowAddress.QuadPart = 0;
	highAddress.QuadPart = 0xFFFFFFFFFFFFFFFF;

	mdl = MmAllocatePagesForMdl(lowAddress, highAddress, lowAddress, (SIZE_T)len);
	if (!mdl)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		kernelVa = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
		if (!kernelVa)
		{
			MmFreePagesFromMdl(mdl);
			IoFreeMdl(mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		userVa = MmMapLockedPagesSpecifyCache(mdl,UserMode,MmCached,NULL,FALSE,HighPagePriority);
		if (!userVa)
		{
			MmUnmapLockedPages(kernelVa, mdl);
			MmFreePagesFromMdl(mdl);
			IoFreeMdl(mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (!userVa || !kernelVa)
	{
		if (userVa)
		{
			MmUnmapLockedPages(userVa, mdl);
		}
		if (kernelVa)
		{
			MmUnmapLockedPages(kernelVa, mdl);
		}
		MmFreePagesFromMdl(mdl);
		IoFreeMdl(mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pSharedMemory->mdl = mdl;
	pSharedMemory->userVa = userVa;
	pSharedMemory->kernelVa = kernelVa;
	pSharedMemory->bufferLength = MmGetMdlByteCount(mdl);

	return STATUS_SUCCESS;
}

//释放共享内存
VOID FreeSharedMemory(PSHARED_MEMORY pSharedMemory)
{
	if (pSharedMemory->mdl)
	{
		__try
		{
			if (pSharedMemory->userVa)
			{
				RtlZeroMemory(pSharedMemory->userVa, MmGetMdlByteCount(pSharedMemory->mdl));
				MmUnmapLockedPages(pSharedMemory->userVa, pSharedMemory->mdl);
				pSharedMemory->userVa = NULL;
			}
			if (pSharedMemory->kernelVa)
			{
				RtlZeroMemory(pSharedMemory->kernelVa, MmGetMdlByteCount(pSharedMemory->mdl));
				MmUnmapLockedPages(pSharedMemory->kernelVa, pSharedMemory->mdl);
				pSharedMemory->kernelVa = NULL;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}

		MmFreePagesFromMdl(pSharedMemory->mdl);
		IoFreeMdl(pSharedMemory->mdl);
		pSharedMemory->mdl = NULL;

		memset(pSharedMemory, 0, sizeof(SHARED_MEMORY));
	}
}

//存放数据
void PushInfo(int code)
{
	if (!g_isInit)
		return;

	NTSTATUS status = STATUS_SUCCESS;
	PNF_QUEUE_ENTRY pQuery = NULL;
	KLOCK_QUEUE_HANDLE lh;

	switch (code)
	{
	case Monitor_Process:
	case Monitor_Thread:
	case Monitor_File:
	case Monitor_Registry:
	case Monitor_Socket:
	case Monitor_USB:
	case Monitor_Image:
	{
		pQuery = (PNF_QUEUE_ENTRY)ExAllocateFromNPagedLookasideList(&g_IoQueryList);
		if (!pQuery)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		pQuery->code = code;
		sl_lock(&g_IoQueryLock, &lh);
		InsertHeadList(&g_IoQueryHead, &pQuery->entry);
		sl_unlock(&lh);
	}
	break;
	default:
		return;
	}

	KeSetEvent(&g_ioThreadEvent, IO_NO_INCREMENT, FALSE);
}

//设置开始工作的状态
//VOID SetWorkStatus(BOOLEAN status)
//{
//	if (status)
//		InterlockedIncrement(&g_IsStart);
//	else
//	{
//		if (g_IsStart > 0)
//			InterlockedDecrement(&g_IsStart);
//	}
//
//	//KLOCK_QUEUE_HANDLE lh;
//
//	//sl_lock(&g_DriverStatusLock, &lh);
//	//g_IsStart = status;
//	//sl_unlock(&lh);	
//}

//获取工作状态
//BOOLEAN GetWorkStatus()
//{
//	if (!g_IsClean)
//		return FALSE;
//	BOOLEAN ret = FALSE;
//	KLOCK_QUEUE_HANDLE lh;
//
//	sl_lock(&g_DriverStatusLock, &lh);
//	ret = g_IsStart == 0 ? FALSE : TRUE;
//	sl_unlock(&lh);
//	return ret;
//}


/////////////////////////////////////////////////////////////////////////////
//抛出数据
NTSTATUS PopInfo(UINT64* pOffset,int typeCode)
{
	NTSTATUS			status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE	lh;
	PDEVBUFFER		devBufEntry = NULL;
	PDEVDATA		devData = NULL;
	PNF_DATA			pData;
	UINT64				dataSize = 0;
	ULONG				pPacketlens = 0;

	if (!g_inBuf.mdl)
	{
		return status;
	}

	switch (typeCode)
	{
		//注册表数据
	case Monitor_Registry:
		devData = GetRegisterCtx();
		break;
		//进程数据
	case Monitor_Process:
		devData = GetProcessCtx();
		break;
		//线程数据
	case Monitor_Thread:
		devData = GetThreadCtx();
		break;
		//文件数据
	case Monitor_File:
		devData = GetMiniFilterCtx();
		break;
		//网络数据
	case Monitor_Socket:
#ifndef WINXP
		devData = GetNetWorkCtx();
#else
		devData = GetTdiCtx();
#endif
		break;
		//设备热插拔数据
	case Monitor_USB:
		devData = GetHotPlugCtx();
		break;
	case Monitor_Image:
		devData = GetImageCtx();
		break;
	}

	if (!devData)
		return STATUS_UNSUCCESSFUL;

	sl_lock(&devData->lock, &lh);

	do
	{
		if (devData->dataSize == 0)
			break;
		devBufEntry = (PDEVBUFFER)RemoveHeadList(&devData->pending);
		if (!devBufEntry)
			break;

		devData->dataSize--;
		//数据长度
		pPacketlens = devBufEntry->dataLength;
		if (pPacketlens == 0)
		{
			break;
		}

		dataSize = sizeof(NF_DATA) - 1 + pPacketlens;

		if ((g_inBuf.bufferLength - *pOffset - 1) < dataSize)
		{
			status = STATUS_NO_MEMORY;
			break;
		}

		//数据
		pData = (PNF_DATA)((char*)g_inBuf.kernelVa + *pOffset);
		if (!pData)
		{
			//status = STATUS_UNSUCCESSFUL;
			break;
		}

		//数据类型
		//pData->code = typeCode;
		//pData->id = 0;
		pData->bufferSize = devBufEntry->dataLength;

		RtlCopyMemory(pData->buffer, devBufEntry->dataBuffer, devBufEntry->dataLength);

		KdPrint(("%s:%d【Data】l:%d,N:%S\n",__FILE__,__LINE__,pData->bufferSize,((PNETWORKINFO)((PMonitorMsg)pData->buffer)->data)->protocolName));

		//偏移
		*pOffset += dataSize;

	} while (FALSE);

	sl_unlock(&lh);

	if (devBufEntry)
	{
		sl_lock(&devData->lock, &lh);
		if (NT_SUCCESS(status))
		{	
			switch (typeCode)
			{
			case Monitor_Registry:
				RegisterPacketFree(devBufEntry);
				break;
			case Monitor_Process:
				ProcessPacketFree(devBufEntry);
				break;
			case Monitor_Thread:
				ThreadPacketFree(devBufEntry);
				break;
			case Monitor_File:
				MiniFilterPacketFree(devBufEntry);
				break;
			case Monitor_Socket:
#ifndef WINXP
				NetWorkPacketFree(devBufEntry);
#else
				TdiPacketFree(devBufEntry);
#endif
				break;
			case Monitor_USB:
				HotPlugPacketFree(devBufEntry);
				break;
			case Monitor_Image:
				ImagePacketFree(devBufEntry);
				break;
			}

			devBufEntry = NULL;
		}
		else
		{
			InsertHeadList(&devData->pending, &devBufEntry->pEntry);
			devData->dataSize++;
		}

		sl_unlock(&lh);
	}

	return status;
}

